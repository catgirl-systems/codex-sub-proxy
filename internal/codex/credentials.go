package codex

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	maxCredentialFileBytes = 1 << 20
	maxTokenBytes          = 64 << 10
	credentialFormat       = "csp-credential"
	credentialVersion      = 1
)

// Credential contains Codex OAuth material and its non-secret identity.
// SaveCredential encrypts the credential before it writes it to disk.
type Credential struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	ExpiresAt        time.Time `json:"expires_at"`
	AccountID        string    `json:"account_id"`
	UserID           string    `json:"user_id"`
	WorkspaceID      string    `json:"workspace_id"`
	PlanType         string    `json:"plan_type"`
	AccountIsFedRAMP bool      `json:"account_is_fedramp"`
	Email            string    `json:"email,omitempty"`
}

type encryptedCredential struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type codexAuthFile struct {
	Tokens       *codexTokenData `json:"tokens"`
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	AccountID    string          `json:"account_id"`
	UserID       string          `json:"user_id"`
	WorkspaceID  string          `json:"workspace_id"`
	PlanType     string          `json:"plan_type"`
	FedRAMP      bool            `json:"account_is_fedramp"`
	Email        string          `json:"email"`
}

type codexTokenData struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
}

type ompCredentialData struct {
	AccessToken string `json:"access"`
	Refresh     string `json:"refresh"`
	Expires     int64  `json:"expires"`
	AccountID   string `json:"accountId"`
	Email       string `json:"email"`
	Workspace   string `json:"orgId"`
	PlanType    string `json:"orgName"`
}

type identityClaims struct {
	Email       string         `json:"email"`
	Subject     string         `json:"sub"`
	AccountID   string         `json:"account_id"`
	AccountID2  string         `json:"accountId"`
	WorkspaceID string         `json:"workspace_id"`
	UserID      string         `json:"user_id"`
	Profile     *profileClaims `json:"https://api.openai.com/profile"`
	Auth        *authClaims    `json:"https://api.openai.com/auth"`
}

type profileClaims struct {
	Email string `json:"email"`
}

type authClaims struct {
	AccountID        string `json:"chatgpt_account_id"`
	UserID           string `json:"chatgpt_user_id"`
	UserID2          string `json:"user_id"`
	WorkspaceID      string `json:"workspace_id"`
	PlanType         string `json:"chatgpt_plan_type"`
	AccountIsFedRAMP bool   `json:"chatgpt_account_is_fedramp"`
}

type standardClaims struct {
	ExpiresAt int64 `json:"exp"`
}

// EncryptCredential returns a versioned AES-GCM envelope.
func EncryptCredential(credential Credential, key []byte) ([]byte, error) {
	if err := validateCredential(credential, false); err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errors.New("credential encryption key is empty")
	}
	plain, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("encode credential: %w", err)
	}
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, block.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := block.Seal(nil, nonce, plain, nil)
	envelope := encryptedCredential{
		Format:     credentialFormat,
		Version:    credentialVersion,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted credential: %w", err)
	}
	return encoded, nil
}

// DecryptCredential opens a credential envelope written by SaveCredential.
func DecryptCredential(data, key []byte) (Credential, error) {
	if len(data) == 0 {
		return Credential{}, errors.New("encrypted credential is empty")
	}
	if len(data) > maxCredentialFileBytes {
		return Credential{}, errors.New("encrypted credential is too large")
	}
	if len(key) == 0 {
		return Credential{}, errors.New("credential encryption key is empty")
	}
	var envelope encryptedCredential
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Credential{}, errors.New("decode encrypted credential")
	}
	if envelope.Format != credentialFormat || envelope.Version != credentialVersion {
		return Credential{}, errors.New("unsupported encrypted credential format")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return Credential{}, errors.New("decode encrypted credential nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return Credential{}, errors.New("decode encrypted credential payload")
	}
	block, err := newCipher(key)
	if err != nil {
		return Credential{}, err
	}
	if len(nonce) != block.NonceSize() {
		return Credential{}, errors.New("invalid encrypted credential nonce")
	}
	plain, err := block.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Credential{}, errors.New("decrypt credential")
	}
	if len(plain) > maxCredentialFileBytes {
		return Credential{}, errors.New("decrypted credential is too large")
	}
	var credential Credential
	if err := json.Unmarshal(plain, &credential); err != nil {
		return Credential{}, errors.New("decode credential")
	}
	if err := validateCredential(credential, false); err != nil {
		return Credential{}, errors.New("invalid credential")
	}
	return credential, nil
}

// SaveCredential writes an encrypted credential with private-file permissions.
func SaveCredential(path string, credential Credential, key []byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("credential path is empty")
	}
	if err := validateCredential(credential, false); err != nil {
		return err
	}
	encoded, err := EncryptCredential(credential, key)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential path is a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect credential path: %w", err)
	}
	file, err := os.CreateTemp(directory, ".credential-*.tmp")
	if err != nil {
		return fmt.Errorf("create credential file: %w", err)
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set credential permissions: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return fmt.Errorf("write credential: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync credential: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close credential: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace credential: %w", err)
	}
	removeTemporary = false
	return nil
}

// LoadCredential reads and decrypts a credential without exposing token bytes.
func LoadCredential(path string, key []byte) (Credential, error) {
	data, err := readRegularFile(path, maxCredentialFileBytes)
	if err != nil {
		return Credential{}, err
	}
	return DecryptCredential(data, key)
}

// CredentialAvailable reports whether path contains a usable encrypted credential.
func CredentialAvailable(path string, key []byte) bool {
	credential, err := LoadCredential(path, key)
	return err == nil && credential.AccessToken != "" && credential.RefreshToken != ""
}

// ImportCredential reads a Codex auth.json, a Codex keyring home, or an OMP
// agent database and writes a new encrypted credential. The source is read only.
func ImportCredential(ctx context.Context, sourcePath, destinationPath string, key []byte) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("credential import context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	sourcePath = strings.TrimSpace(sourcePath)
	destinationPath = strings.TrimSpace(destinationPath)
	if sourcePath == "" {
		return Credential{}, errors.New("credential source path is empty")
	}
	if destinationPath == "" {
		return Credential{}, errors.New("credential destination path is empty")
	}
	credential, sourceFile, err := readImportedCredential(ctx, sourcePath)
	if err != nil {
		return Credential{}, err
	}
	if sourceFile != nil {
		if destinationInfo, statErr := os.Stat(destinationPath); statErr == nil {
			if os.SameFile(sourceFile, destinationInfo) {
				return Credential{}, errors.New("credential source and destination are the same file")
			}
		} else if !os.IsNotExist(statErr) {
			return Credential{}, fmt.Errorf("inspect credential destination: %w", statErr)
		}
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if err := SaveCredential(destinationPath, credential, key); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

func readImportedCredential(ctx context.Context, sourcePath string) (Credential, os.FileInfo, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return Credential{}, nil, fmt.Errorf("inspect credential source: %w", err)
	}
	if info.IsDir() {
		authPath := filepath.Join(sourcePath, "auth.json")
		authInfo, authErr := os.Stat(authPath)
		switch {
		case authErr == nil && !authInfo.Mode().IsRegular():
			return Credential{}, nil, errors.New("Codex auth file is not a regular file")
		case authErr == nil:
			credential, err := readCredentialJSON(authPath)
			if err != nil {
				return Credential{}, nil, err
			}
			return credential, authInfo, nil
		case !os.IsNotExist(authErr):
			return Credential{}, nil, fmt.Errorf("inspect Codex auth file: %w", authErr)
		}
		data, keyringErr := readCodexKeyring(ctx, sourcePath)
		if keyringErr != nil {
			return Credential{}, nil, keyringErr
		}
		credential, err := parseCredentialJSON(data)
		return credential, nil, err
	}
	if !info.Mode().IsRegular() {
		return Credential{}, nil, errors.New("credential source is not a regular file")
	}
	if strings.EqualFold(filepath.Ext(sourcePath), ".db") || filepath.Base(sourcePath) == "agent.db" {
		if credential, err := readOMPCredential(ctx, sourcePath); err == nil {
			return credential, info, nil
		}
	}
	credential, err := readCredentialJSON(sourcePath)
	return credential, info, err
}

func readCredentialJSON(path string) (Credential, error) {
	data, err := readRegularFile(path, maxCredentialFileBytes)
	if err != nil {
		return Credential{}, fmt.Errorf("read credential source: %w", err)
	}
	credential, err := parseCredentialJSON(data)
	if err != nil {
		return Credential{}, fmt.Errorf("parse credential source: %w", err)
	}
	return credential, nil
}

func parseCredentialJSON(data []byte) (Credential, error) {
	if len(data) > maxCredentialFileBytes {
		return Credential{}, errors.New("credential JSON is too large")
	}
	var auth codexAuthFile
	if err := json.Unmarshal(data, &auth); err != nil {
		return Credential{}, errors.New("invalid credential JSON")
	}
	accessToken := auth.AccessToken
	refreshToken := auth.RefreshToken
	idToken := auth.IDToken
	accountID := auth.AccountID
	userID := auth.UserID
	workspaceID := auth.WorkspaceID
	planType := auth.PlanType
	fedramp := auth.FedRAMP
	email := auth.Email
	if auth.Tokens != nil {
		accessToken = auth.Tokens.AccessToken
		refreshToken = auth.Tokens.RefreshToken
		idToken = auth.Tokens.IDToken
		if accountID == "" {
			accountID = auth.Tokens.AccountID
		}
	}
	if accessToken == "" || refreshToken == "" {
		var omp ompCredentialData
		if err := json.Unmarshal(data, &omp); err == nil && omp.AccessToken != "" && omp.Refresh != "" {
			var expiresAt time.Time
			if omp.Expires > 0 {
				expiresAt = time.UnixMilli(omp.Expires)
			}
			return buildCredential(omp.AccessToken, omp.Refresh, idToken, expiresAt, omp.AccountID, userID, omp.Workspace, omp.PlanType, fedramp, omp.Email, false)
		}
	}
	return buildCredential(accessToken, refreshToken, idToken, time.Time{}, accountID, userID, workspaceID, planType, fedramp, email, false)
}

func readOMPCredential(ctx context.Context, path string) (Credential, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return Credential{}, errors.New("resolve OMP credential database")
	}
	dsn := "file:" + filepath.ToSlash(absolutePath) + "?mode=ro"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return Credential{}, errors.New("open OMP credential database")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return Credential{}, errors.New("open OMP credential database")
	}
	defer func() { _ = sqlDB.Close() }()
	var row struct {
		Data string
	}
	if err := db.WithContext(ctx).Raw("SELECT substr(data, 1, ?) AS data FROM auth_credentials WHERE provider = ? AND credential_type = ? AND disabled_cause IS NULL ORDER BY id ASC LIMIT 1", maxCredentialFileBytes+1, "openai-codex", "oauth").Scan(&row).Error; err != nil {
		return Credential{}, errors.New("read OMP credential database")
	}
	if strings.TrimSpace(row.Data) == "" {
		return Credential{}, errors.New("OMP Codex credential is missing")
	}
	return parseCredentialJSON([]byte(row.Data))
}

func readCodexKeyring(ctx context.Context, codexHome string) ([]byte, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("Codex keyring import is not supported on this platform")
	}
	absolute, err := filepath.Abs(codexHome)
	if err != nil {
		return nil, errors.New("resolve Codex home")
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		canonical = absolute
	}
	if canonical == "" {
		return nil, errors.New("resolve Codex home")
	}
	digest := sha256.Sum256([]byte(canonical))
	account := "cli|" + hex.EncodeToString(digest[:])[:16]
	keyringContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(keyringContext, "security", "find-generic-password", "-s", "Codex Auth", "-a", account, "-w")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("read Codex keyring")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, errors.New("read Codex keyring")
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxCredentialFileBytes+1))
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil {
		return nil, errors.New("Codex keyring credential is unavailable")
	}
	if len(data) > maxCredentialFileBytes {
		return nil, errors.New("Codex keyring credential is too large")
	}
	return data, nil
}

func buildCredential(accessToken, refreshToken, idToken string, expiresAt time.Time, accountID, userID, workspaceID, planType string, fedramp bool, email string, requireIdentity bool) (Credential, error) {
	credential := Credential{
		AccessToken:      strings.TrimSpace(accessToken),
		RefreshToken:     strings.TrimSpace(refreshToken),
		ExpiresAt:        expiresAt,
		AccountID:        strings.TrimSpace(accountID),
		UserID:           strings.TrimSpace(userID),
		WorkspaceID:      strings.TrimSpace(workspaceID),
		PlanType:         strings.TrimSpace(planType),
		AccountIsFedRAMP: fedramp,
		Email:            strings.TrimSpace(email),
	}
	if credential.ExpiresAt.IsZero() {
		if tokenExpiry, ok := jwtExpiry(credential.AccessToken); ok {
			credential.ExpiresAt = tokenExpiry
		} else if tokenExpiry, ok := jwtExpiry(idToken); ok {
			credential.ExpiresAt = tokenExpiry
		}
	}
	claims := jwtIdentity(idToken)
	if claims == (identityClaims{}) {
		claims = jwtIdentity(credential.AccessToken)
	}
	if credential.AccountID == "" {
		credential.AccountID = firstNonEmpty(claims.AccountID, claims.AccountID2, claims.AuthAccountID())
	}
	if credential.UserID == "" {
		credential.UserID = firstNonEmpty(claims.UserID, claims.AuthUserID(), claims.Subject)
	}
	if credential.WorkspaceID == "" {
		credential.WorkspaceID = firstNonEmpty(claims.WorkspaceID, claims.AuthWorkspaceID(), credential.AccountID)
	}
	if credential.PlanType == "" {
		credential.PlanType = claims.AuthPlanType()
	}
	if !credential.AccountIsFedRAMP {
		credential.AccountIsFedRAMP = claims.AuthFedRAMP()
	}
	if credential.Email == "" {
		credential.Email = firstNonEmpty(claims.Email, claims.ProfileEmail())
	}
	if err := validateCredential(credential, requireIdentity); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

func (claims identityClaims) AuthAccountID() string {
	if claims.Auth == nil {
		return ""
	}
	return claims.Auth.AccountID
}

func (claims identityClaims) AuthUserID() string {
	if claims.Auth == nil {
		return ""
	}
	return firstNonEmpty(claims.Auth.UserID, claims.Auth.UserID2)
}

func (claims identityClaims) AuthWorkspaceID() string {
	if claims.Auth == nil {
		return ""
	}
	return claims.Auth.WorkspaceID
}

func (claims identityClaims) AuthPlanType() string {
	if claims.Auth == nil {
		return ""
	}
	return claims.Auth.PlanType
}

func (claims identityClaims) AuthFedRAMP() bool {
	return claims.Auth != nil && claims.Auth.AccountIsFedRAMP
}

func (claims identityClaims) ProfileEmail() string {
	if claims.Profile == nil {
		return ""
	}
	return claims.Profile.Email
}

func validateCredential(credential Credential, requireIdentity bool) error {
	if credential.AccessToken == "" || credential.RefreshToken == "" {
		return errors.New("credential is missing OAuth tokens")
	}
	if len(credential.AccessToken) > maxTokenBytes || len(credential.RefreshToken) > maxTokenBytes {
		return errors.New("credential token is too large")
	}
	if strings.ContainsAny(credential.AccessToken, "\r\n") || strings.ContainsAny(credential.RefreshToken, "\r\n") {
		return errors.New("credential token contains invalid characters")
	}
	if !credential.ExpiresAt.IsZero() && credential.ExpiresAt.Before(time.Unix(0, 0)) {
		return errors.New("credential expiry is invalid")
	}
	if requireIdentity && credential.AccountID == "" {
		return errors.New("credential is missing account identity")
	}
	return nil
}

func jwtIdentity(token string) identityClaims {
	payload, ok := jwtPayload(token)
	if !ok {
		return identityClaims{}
	}
	var claims identityClaims
	if json.Unmarshal(payload, &claims) != nil {
		return identityClaims{}
	}
	return claims
}

func jwtExpiry(token string) (time.Time, bool) {
	payload, ok := jwtPayload(token)
	if !ok {
		return time.Time{}, false
	}
	var claims standardClaims
	if json.Unmarshal(payload, &claims) != nil || claims.ExpiresAt <= 0 {
		return time.Time{}, false
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	return expiresAt, !expiresAt.IsZero()
}

func jwtPayload(token string) ([]byte, bool) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[1] == "" {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil || len(payload) > maxCredentialFileBytes {
		return nil, false
	}
	return payload, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func readRegularFile(path string, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("credential path is empty")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat credential file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("credential file is a symbolic link")
	}
	if !linkInfo.Mode().IsRegular() {
		return nil, errors.New("credential file is not a regular file")
	}
	if linkInfo.Size() > maxBytes {
		return nil, errors.New("credential file is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("credential file is too large")
	}
	return data, nil
}

func newCipher(key []byte) (cipher.AEAD, error) {
	digest := sha256.Sum256(key)
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return nil, errors.New("create credential cipher")
	}
	return cipher.NewGCM(block)
}
