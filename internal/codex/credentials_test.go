package codex

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestImportCredentialEncryptsWithoutChangingSource(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	source := map[string]any{
		"tokens": map[string]any{
			"access_token":  "source-access",
			"refresh_token": "source-refresh",
			"id_token":      testJWT(t, map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "source-account"}}),
			"account_id":    "source-account",
			"expires_at":    expires,
		},
		"last_refresh": "2026-08-02T00:00:00Z",
	}
	sourceBytes, err := json.MarshalIndent(source, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(t.TempDir(), "credential.enc")
	credential, err := ImportCredential(context.Background(), sourcePath, destinationPath, []byte("encryption-key"))
	if err != nil {
		t.Fatalf("import credential: %v", err)
	}
	if credential.AccessToken != "source-access" || credential.RefreshToken != "source-refresh" || credential.AccountID != "source-account" {
		t.Fatalf("credential = %#v", credential)
	}
	got, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(sourceBytes) {
		t.Fatal("source credential changed")
	}
	if got, err := LoadCredential(destinationPath, []byte("encryption-key")); err != nil || got.AccessToken != credential.AccessToken {
		t.Fatalf("load imported credential = %#v, %v", got, err)
	}
	if mode := encryptedMode(t, destinationPath); mode != 0o600 {
		t.Fatalf("destination mode = %o, want 600", mode)
	}
}

func TestImportCredentialRejectsSourceAndDestinationSame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"tokens":{"access_token":"access","refresh_token":"refresh"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ImportCredential(context.Background(), path, path, []byte("key"))
	if err == nil {
		t.Fatal("same source and destination were accepted")
	}
	if !strings.Contains(err.Error(), "same") {
		t.Fatalf("error = %v", err)
	}
}

func TestImportCredentialRejectsNonRegularSourceWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ImportCredential(context.Background(), path, filepath.Join(t.TempDir(), "destination.enc"), []byte("key"))
	if err == nil {
		t.Fatal("FIFO source was accepted")
	}
	if strings.Contains(err.Error(), "access") {
		t.Fatal("source data reached error")
	}
}

func TestCredentialAvailableRequiresUsableEncryptedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	if CredentialAvailable(path, []byte("key")) {
		t.Fatal("missing credential reported as available")
	}
	if err := os.WriteFile(path, []byte("plain credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if CredentialAvailable(path, []byte("key")) {
		t.Fatal("plain credential reported as available")
	}
	credential := Credential{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour), AccountID: "account"}
	if err := SaveCredential(path, credential, []byte("key")); err != nil {
		t.Fatal(err)
	}
	if !CredentialAvailable(path, []byte("key")) {
		t.Fatal("usable encrypted credential reported as unavailable")
	}
	credential.ExpiresAt = time.Now().Add(-time.Second)
	if err := SaveCredential(path, credential, []byte("key")); err != nil {
		t.Fatal(err)
	}
	if CredentialAvailable(path, []byte("key")) {
		t.Fatal("expired credential reported as available")
	}
	credential.ExpiresAt = time.Now().Add(time.Hour)
	credential.AccountID = ""
	if err := SaveCredential(path, credential, []byte("key")); err != nil {
		t.Fatal(err)
	}
	if CredentialAvailable(path, []byte("key")) {
		t.Fatal("credential without account identity reported as available")
	}
	if CredentialAvailable(path, []byte("wrong")) {
		t.Fatal("credential with wrong key reported as available")
	}
}

func TestImportCredentialReadsOMPDatabase(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "omp ?& # %.db")
	databaseURL := url.URL{Scheme: "file", Path: filepath.ToSlash(databasePath)}
	db, err := gorm.Open(sqlite.Open(databaseURL.String()), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.Exec(`CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT, credential_type TEXT, data TEXT, disabled_cause TEXT)`).Error; err != nil {
		t.Fatalf("create credential table: %v", err)
	}
	data := `{"access":"omp-access","refresh":"omp-refresh","expires":4102444800000,"accountId":"omp-account","email":"omp@example.com","orgId":"omp-workspace","orgName":"pro"}`
	if err := db.Exec("INSERT INTO auth_credentials(provider, credential_type, data) VALUES (?, ?, ?)", "openai-codex", "oauth", data).Error; err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o400); err != nil {
		t.Fatalf("make database read-only: %v", err)
	}
	destinationPath := filepath.Join(t.TempDir(), "credential.enc")
	credential, err := ImportCredential(context.Background(), databasePath, destinationPath, []byte("key"))
	if err != nil {
		t.Fatalf("import OMP credential: %v", err)
	}
	if credential.AccessToken != "omp-access" || credential.RefreshToken != "omp-refresh" || credential.AccountID != "omp-account" || credential.WorkspaceID != "omp-workspace" || credential.PlanType != "pro" {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestImportCredentialRejectsCodexHomeAuthDestination(t *testing.T) {
	codexHome := t.TempDir()
	destination := filepath.Join(codexHome, "auth.json")
	_, err := ImportCredential(context.Background(), codexHome, destination, []byte("key"))
	if err == nil {
		t.Fatal("Codex home auth.json destination was accepted")
	}
	if _, statErr := os.Lstat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("destination exists after rejected import: %v", statErr)
	}
}

func TestImportCredentialRejectsCodexHomeAuthDestinationCaseInsensitive(t *testing.T) {
	codexHome := t.TempDir()
	destination := filepath.Join(codexHome, "AUTH.JSON")
	_, err := ImportCredential(context.Background(), codexHome, destination, []byte("key"))
	if err == nil {
		t.Fatal("case-variant Codex home auth.json destination was accepted")
	}
	if _, statErr := os.Lstat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("destination exists after rejected import: %v", statErr)
	}
}

func TestImportCredentialRejectsOMPSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "agent.db")
	if err := os.WriteFile(target, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "agent.db")
	if err := os.Symlink(target, source); err != nil {
		t.Fatal(err)
	}
	_, err := ImportCredential(context.Background(), source, filepath.Join(t.TempDir(), "credential.enc"), []byte("key"))
	if err == nil {
		t.Fatal("OMP database symlink was accepted")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v, want symbolic-link rejection", err)
	}
}

func TestReadCodexKeyringHashesAbsoluteCanonicalHome(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Codex keyring import is only available on macOS")
	}
	workingDir := t.TempDir()
	realHome := filepath.Join(workingDir, "real-codex")
	if err := os.Mkdir(realHome, 0o700); err != nil {
		t.Fatal(err)
	}
	relativeHome := filepath.Join(workingDir, "relative-codex")
	if err := os.Symlink("real-codex", relativeHome); err != nil {
		t.Fatal(err)
	}
	capturePath := filepath.Join(workingDir, "account")
	securityPath := filepath.Join(workingDir, "security")
	script := "#!/bin/sh\nprintf '%s' \"$5\" > \"$CAPTURE\"\nprintf '%s' '{\"tokens\":{\"access_token\":\"access\",\"refresh_token\":\"refresh\"}}'\n"
	if err := os.WriteFile(securityPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", workingDir)
	t.Setenv("CAPTURE", capturePath)
	t.Chdir(workingDir)
	if _, err := readCodexKeyring(context.Background(), "relative-codex"); err != nil {
		t.Fatalf("read Codex keyring: %v", err)
	}
	canonical, err := filepath.EvalSymlinks(realHome)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(canonical))
	want := "cli|" + hex.EncodeToString(digest[:])[:16]
	got, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("keyring account = %q, want %q", got, want)
	}
}

func TestImportedCredentialUsesAccessTokenExpiryBeforeIDToken(t *testing.T) {
	accessExpiry := time.Unix(1_800_000_000, 0)
	idExpiry := time.Unix(1_700_000_000, 0)
	data, err := json.Marshal(map[string]any{
		"tokens": map[string]string{
			"access_token":  testJWT(t, map[string]any{"exp": accessExpiry.Unix()}),
			"refresh_token": "refresh",
			"id_token":      testJWT(t, map[string]any{"exp": idExpiry.Unix()}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := parseCredentialJSON(data)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if !credential.ExpiresAt.Equal(accessExpiry) {
		t.Fatalf("credential expiry = %s, want %s", credential.ExpiresAt, accessExpiry)
	}
}

func TestBuildCredentialMergesAccessAndIDTokenIdentity(t *testing.T) {
	accessToken := testJWT(t, map[string]any{
		"account_id":   "access-account",
		"workspace_id": "access-workspace",
	})
	idToken := testJWT(t, map[string]any{
		"user_id": "id-user",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "id-account",
			"workspace_id":       "id-workspace",
			"chatgpt_plan_type":  "pro",
		},
		"https://api.openai.com/profile": map[string]string{"email": "id@example.com"},
	})
	credential, err := buildCredential(accessToken, "refresh", idToken, time.Time{}, "", "", "", "", false, "", false)
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	if credential.AccountID != "access-account" || credential.WorkspaceID != "access-workspace" {
		t.Fatalf("access-token identity = %#v", credential)
	}
	if credential.UserID != "id-user" || credential.PlanType != "pro" || credential.Email != "id@example.com" {
		t.Fatalf("fallback identity = %#v", credential)
	}
}

func encryptedMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
