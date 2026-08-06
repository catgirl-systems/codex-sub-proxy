package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/go-playground/validator/v10"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	maxCredentialJSONBytes = 1 << 20
	maxCredentialFileBytes = envelope.MaxEnvelopeSize
	maxTokenBytes          = 64 << 10
)

var credentialSaveMu sync.Mutex

// Credential contains Codex OAuth material and its non-secret identity.
// SaveCredential encrypts the credential before it writes it to disk.
type Credential struct {
	AccessToken      string    `json:"access_token" validate:"required,max=65536"`
	IDToken          string    `json:"id_token,omitempty" validate:"max=65536"`
	RefreshToken     string    `json:"refresh_token" validate:"required,max=65536"`
	ExpiresAt        time.Time `json:"expires_at"`
	AccountID        string    `json:"account_id"`
	UserID           string    `json:"user_id"`
	WorkspaceID      string    `json:"workspace_id"`
	PlanType         string    `json:"plan_type"`
	AccountIsFedRAMP bool      `json:"account_is_fedramp"`
	Email            string    `json:"email,omitempty"`
}

var credentialValidation = func() *validator.Validate {
	instance := validator.New()
	instance.RegisterStructValidation(credentialStructValidation, Credential{})
	return instance
}()

func credentialStructValidation(sl validator.StructLevel) {
	credential, ok := sl.Current().Interface().(Credential)
	if !ok {
		return
	}
	if strings.ContainsAny(credential.AccessToken, "\r\n") {
		sl.ReportError(credential.AccessToken, "AccessToken", "AccessToken", "no_line_breaks", "")
	}
	if strings.ContainsAny(credential.IDToken, "\r\n") {
		sl.ReportError(credential.IDToken, "IDToken", "IDToken", "no_line_breaks", "")
	}
	if strings.ContainsAny(credential.RefreshToken, "\r\n") {
		sl.ReportError(credential.RefreshToken, "RefreshToken", "RefreshToken", "no_line_breaks", "")
	}
	if !credential.ExpiresAt.IsZero() && credential.ExpiresAt.Before(time.Unix(0, 0)) {
		sl.ReportError(credential.ExpiresAt, "ExpiresAt", "ExpiresAt", "non_negative", "")
	}
}

type codexAuthFile struct {
	Tokens       *codexTokenData `json:"tokens"`
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	ExpiresAt    int64           `json:"expires_at"`
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
	ExpiresAt    int64  `json:"expires_at"`
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

// EncryptCredential returns a versioned authenticated credential envelope.
func EncryptCredential(credential Credential, keys envelope.KeySet) ([]byte, error) {
	if err := credentialValidation.Struct(credential); err != nil {
		return nil, fmt.Errorf("invalid credential: %w", err)
	}
	plain, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("encode credential: %w", err)
	}
	encoded, err := envelope.Encrypt(plain, envelope.CredentialDomain, keys)
	if err != nil {
		return nil, fmt.Errorf("encrypt credential: %w", err)
	}
	return encoded, nil
}

// DecryptCredential opens a credential envelope written by SaveCredential.
func DecryptCredential(data []byte, keys envelope.KeySet) (Credential, error) {
	plain, err := envelope.Decrypt(data, envelope.CredentialDomain, keys)
	if err != nil {
		return Credential{}, fmt.Errorf("decrypt credential: %w", err)
	}
	var credential Credential
	if err := json.Unmarshal(plain, &credential); err != nil {
		return Credential{}, errors.New("decode credential")
	}
	if err := credentialValidation.Struct(credential); err != nil {
		return Credential{}, errors.New("invalid credential")
	}
	return credential, nil
}

// SaveCredential writes an encrypted credential with private-file permissions.
func SaveCredential(path string, credential Credential, keys envelope.KeySet) error {
	return SaveCredentialContext(context.Background(), path, credential, keys)
}

// SaveCredentialContext writes an encrypted credential while honoring ctx.
func SaveCredentialContext(ctx context.Context, path string, credential Credential, keys envelope.KeySet) error {
	_, err := SaveCredentialContextWithRollback(ctx, path, credential, keys)
	return err
}

// CredentialRollback restores the opaque envelope replaced by a credential save.
// Restore refuses to overwrite a path changed since the save.
type CredentialRollback struct {
	path     string
	previous []byte
	expected []byte
	existed  bool
}

// SaveCredentialContextWithRollback writes a credential and returns a guarded
// rollback for callers that must undo a later registry mutation.
func SaveCredentialContextWithRollback(ctx context.Context, path string, credential Credential, keys envelope.KeySet) (CredentialRollback, error) {
	if err := checkCredentialContext(ctx, "save credential"); err != nil {
		return CredentialRollback{}, err
	}
	if strings.TrimSpace(path) == "" {
		return CredentialRollback{}, errors.New("credential path is empty")
	}
	if err := credentialValidation.Struct(credential); err != nil {
		return CredentialRollback{}, err
	}
	encoded, err := EncryptCredential(credential, keys)
	if err != nil {
		return CredentialRollback{}, err
	}
	if err := checkCredentialContext(ctx, "encode credential"); err != nil {
		return CredentialRollback{}, err
	}
	credentialSaveMu.Lock()
	defer credentialSaveMu.Unlock()
	if err := checkCredentialContext(ctx, "write credential"); err != nil {
		return CredentialRollback{}, err
	}
	previous, existed, err := credentialSnapshot(path)
	if err != nil {
		return CredentialRollback{}, err
	}
	if err := writeCredential(ctx, path, encoded); err != nil {
		return CredentialRollback{}, err
	}
	return CredentialRollback{
		path:     path,
		previous: append([]byte(nil), previous...),
		expected: append([]byte(nil), encoded...),
		existed:  existed,
	}, nil
}

// Restore reverts the saved path atomically if no other writer replaced it.
func (rollback CredentialRollback) Restore(ctx context.Context) error {
	if err := checkCredentialContext(ctx, "restore credential"); err != nil {
		return err
	}
	if strings.TrimSpace(rollback.path) == "" {
		return errors.New("credential rollback path is empty")
	}
	credentialSaveMu.Lock()
	defer credentialSaveMu.Unlock()
	current, exists, err := credentialSnapshot(rollback.path)
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(current, rollback.expected) {
		return errors.New("credential path changed before restore")
	}
	if !rollback.existed {
		if err := checkCredentialContext(ctx, "remove credential"); err != nil {
			return err
		}
		if err := os.Remove(rollback.path); err != nil {
			return fmt.Errorf("remove credential: %w", err)
		}
		return nil
	}
	if err := checkCredentialContext(ctx, "restore credential"); err != nil {
		return err
	}
	return writeCredential(ctx, rollback.path, rollback.previous)
}

func saveCredential(ctx context.Context, path string, credential Credential, keys envelope.KeySet) error {
	_, err := SaveCredentialContextWithRollback(ctx, path, credential, keys)
	return err
}

func credentialSnapshot(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect credential path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, errors.New("credential path is a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("credential path is not a regular file")
	}
	if info.Size() > maxCredentialFileBytes {
		return nil, false, errors.New("credential file is too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read credential file: %w", err)
	}
	return data, true, nil
}

func saveCredentialIfUnchanged(ctx context.Context, path string, expected, replacement Credential, keys envelope.KeySet) (Credential, bool, error) {
	if err := checkCredentialContext(ctx, "compare credential"); err != nil {
		return Credential{}, false, err
	}
	if strings.TrimSpace(path) == "" {
		return Credential{}, false, errors.New("credential path is empty")
	}
	if err := credentialValidation.Struct(replacement); err != nil {
		return Credential{}, false, err
	}
	encoded, err := EncryptCredential(replacement, keys)
	if err != nil {
		return Credential{}, false, err
	}
	if err := checkCredentialContext(ctx, "encode credential"); err != nil {
		return Credential{}, false, err
	}
	credentialSaveMu.Lock()
	defer credentialSaveMu.Unlock()
	if err := checkCredentialContext(ctx, "load credential"); err != nil {
		return Credential{}, false, err
	}
	current, err := loadCredential(path, keys)
	if contextErr := checkCredentialContext(ctx, "load credential"); contextErr != nil {
		return Credential{}, false, contextErr
	}
	if err != nil {
		return Credential{}, false, err
	}
	if !sameCredential(current, expected) {
		return current, false, nil
	}
	if err := writeCredential(ctx, path, encoded); err != nil {
		return Credential{}, false, err
	}
	return replacement, true, nil
}

func checkCredentialContext(ctx context.Context, operation string) error {
	if ctx == nil {
		return fmt.Errorf("%s context is nil", operation)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func writeCredential(ctx context.Context, path string, encoded []byte) error {
	directory := filepath.Dir(path)
	if err := checkCredentialContext(ctx, "create credential directory"); err != nil {
		return err
	}
	mkdirErr := os.MkdirAll(directory, 0o700)
	if contextErr := checkCredentialContext(ctx, "create credential directory"); contextErr != nil {
		return contextErr
	}
	if mkdirErr != nil {
		return fmt.Errorf("create credential directory: %w", mkdirErr)
	}
	if err := checkCredentialContext(ctx, "inspect credential path"); err != nil {
		return err
	}
	info, lstatErr := os.Lstat(path)
	if contextErr := checkCredentialContext(ctx, "inspect credential path"); contextErr != nil {
		return contextErr
	}
	if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential path is a symbolic link")
	} else if lstatErr != nil && !os.IsNotExist(lstatErr) {
		return fmt.Errorf("inspect credential path: %w", lstatErr)
	}
	if err := checkCredentialContext(ctx, "create credential file"); err != nil {
		return err
	}
	file, createErr := os.CreateTemp(directory, ".credential-*.tmp")
	if contextErr := checkCredentialContext(ctx, "create credential file"); contextErr != nil {
		if file != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
		return contextErr
	}
	if createErr != nil {
		return fmt.Errorf("create credential file: %w", createErr)
	}
	temporary := file.Name()
	removeTemporary := true
	fileClosed := false
	defer func() {
		if !fileClosed {
			_ = file.Close()
		}
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := checkCredentialContext(ctx, "set credential permissions"); err != nil {
		return err
	}
	chmodErr := file.Chmod(0o600)
	if contextErr := checkCredentialContext(ctx, "set credential permissions"); contextErr != nil {
		return contextErr
	}
	if chmodErr != nil {
		return fmt.Errorf("set credential permissions: %w", chmodErr)
	}
	if err := checkCredentialContext(ctx, "write credential"); err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	if contextErr := checkCredentialContext(ctx, "write credential"); contextErr != nil {
		return contextErr
	}
	if writeErr != nil {
		return fmt.Errorf("write credential: %w", writeErr)
	}
	if err := checkCredentialContext(ctx, "sync credential"); err != nil {
		return err
	}
	syncErr := file.Sync()
	if contextErr := checkCredentialContext(ctx, "sync credential"); contextErr != nil {
		return contextErr
	}
	if syncErr != nil {
		return fmt.Errorf("sync credential: %w", syncErr)
	}
	if err := checkCredentialContext(ctx, "close credential"); err != nil {
		return err
	}
	closeErr := file.Close()
	fileClosed = true
	if contextErr := checkCredentialContext(ctx, "close credential"); contextErr != nil {
		return contextErr
	}
	if closeErr != nil {
		return fmt.Errorf("close credential: %w", closeErr)
	}
	if err := checkCredentialContext(ctx, "replace credential"); err != nil {
		return err
	}
	committed := false
	renameErr := os.Rename(temporary, path)
	if renameErr == nil {
		committed = true
		removeTemporary = false
	}
	if contextErr := checkCredentialContext(ctx, "replace credential"); contextErr != nil && !committed {
		return contextErr
	}
	if renameErr != nil {
		return fmt.Errorf("replace credential: %w", renameErr)
	}
	// Rename is the commit point; finish the directory sync even if cancellation
	// is observed afterward.
	if contextErr := checkCredentialContext(ctx, "open credential directory"); contextErr != nil && !committed {
		return contextErr
	}
	directoryFile, openErr := os.Open(directory)
	if contextErr := checkCredentialContext(ctx, "open credential directory"); contextErr != nil && !committed {
		if directoryFile != nil {
			_ = directoryFile.Close()
		}
		return contextErr
	}
	if openErr != nil {
		return fmt.Errorf("open credential directory: %w", openErr)
	}
	directoryClosed := false
	defer func() {
		if !directoryClosed {
			_ = directoryFile.Close()
		}
	}()
	if contextErr := checkCredentialContext(ctx, "sync credential directory"); contextErr != nil && !committed {
		return contextErr
	}
	directorySyncErr := directoryFile.Sync()
	if contextErr := checkCredentialContext(ctx, "sync credential directory"); contextErr != nil && !committed {
		return contextErr
	}
	if directorySyncErr != nil {
		return fmt.Errorf("sync credential directory: %w", directorySyncErr)
	}
	if contextErr := checkCredentialContext(ctx, "close credential directory"); contextErr != nil && !committed {
		return contextErr
	}
	directoryCloseErr := directoryFile.Close()
	directoryClosed = true
	if contextErr := checkCredentialContext(ctx, "close credential directory"); contextErr != nil && !committed {
		return contextErr
	}
	if directoryCloseErr != nil {
		return fmt.Errorf("close credential directory: %w", directoryCloseErr)
	}
	return nil
}

// LoadCredential reads and decrypts a credential without exposing token bytes.
func LoadCredential(path string, keys envelope.KeySet) (Credential, error) {
	if _, err := envelope.NewKeySet(keys.Active, keys.Previous...); err != nil {
		return Credential{}, err
	}
	return loadCredential(path, keys)
}

func loadCredential(path string, keys envelope.KeySet) (Credential, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Credential{}, errors.New("credential path is empty")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return Credential{}, fmt.Errorf("stat credential file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return Credential{}, errors.New("credential file is a symbolic link")
	}
	if !linkInfo.Mode().IsRegular() {
		return Credential{}, errors.New("credential file is not a regular file")
	}
	if linkInfo.Size() > maxCredentialFileBytes {
		return Credential{}, errors.New("credential file is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return Credential{}, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialFileBytes+1))
	if err != nil {
		return Credential{}, fmt.Errorf("read credential file: %w", err)
	}
	if int64(len(data)) > maxCredentialFileBytes {
		return Credential{}, errors.New("credential file is too large")
	}
	return DecryptCredential(data, keys)
}

// CredentialAvailable reports whether path contains a usable encrypted credential.
func CredentialAvailable(path string, keys envelope.KeySet) bool {
	credential, err := LoadCredential(path, keys)
	if err != nil ||
		strings.TrimSpace(credential.AccessToken) == "" ||
		strings.TrimSpace(credential.RefreshToken) == "" ||
		strings.TrimSpace(credential.AccountID) == "" {
		return false
	}
	return !credential.ExpiresAt.IsZero() && credential.ExpiresAt.After(time.Now())
}

// ImportCredential reads a Codex auth.json, Codex keyring home, or an OMP
// agent database and writes a new encrypted credential. The source is read only.
func ImportCredential(ctx context.Context, sourcePath, destinationPath string, keys envelope.KeySet) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("credential import context is nil")
	}
	destinationPath = strings.TrimSpace(destinationPath)
	if destinationPath == "" {
		return Credential{}, errors.New("credential destination path is empty")
	}
	if err := ValidateImportDestination(sourcePath, destinationPath); err != nil {
		return Credential{}, err
	}
	credential, err := ExtractCredential(ctx, sourcePath, keys)
	if err != nil {
		return Credential{}, err
	}
	if err := saveCredential(ctx, destinationPath, credential, keys); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

// ExtractCredential reads and validates a credential without writing it.
func ExtractCredential(ctx context.Context, sourcePath string, keys envelope.KeySet) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("credential import context is nil")
	}
	if _, err := envelope.NewKeySet(keys.Active, keys.Previous...); err != nil {
		return Credential{}, err
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return Credential{}, errors.New("credential source path is empty")
	}
	credential, _, err := readImportedCredential(ctx, sourcePath)
	if err != nil {
		return Credential{}, err
	}
	return credential, nil
}

// ValidateImportDestination rejects writes into a source Codex home and
// source/destination aliases before any credential is persisted.
func ValidateImportDestination(sourcePath, destinationPath string) error {
	if err := rejectCodexHomeAuthDestination(sourcePath, destinationPath); err != nil {
		return err
	}
	sourceInfo, statErr := os.Stat(strings.TrimSpace(sourcePath))
	if statErr == nil && sourceInfo.Mode().IsRegular() {
		destinationInfo, destinationErr := os.Stat(destinationPath)
		if destinationErr == nil && os.SameFile(sourceInfo, destinationInfo) {
			return errors.New("credential source and destination are the same file")
		}
		if destinationErr != nil && !os.IsNotExist(destinationErr) {
			return fmt.Errorf("inspect credential destination: %w", destinationErr)
		}
	}
	return nil
}

func rejectCodexHomeAuthDestination(sourcePath, destinationPath string) error {
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect credential source: %w", err)
	}
	if !sourceInfo.IsDir() {
		return nil
	}
	destinationParentInfo, err := os.Stat(filepath.Dir(destinationPath))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect credential destination directory: %w", err)
	}
	if os.SameFile(sourceInfo, destinationParentInfo) &&
		strings.EqualFold(filepath.Base(destinationPath), "auth.json") {
		return errors.New("credential destination is Codex home auth.json")
	}
	return nil
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
			return Credential{}, nil, errors.New("codex auth file is not a regular file")
		case authErr == nil:
			credential, err := readCredentialJSON(authPath)
			if err != nil {
				return Credential{}, nil, err
			}
			return credential, authInfo, nil
		case !os.IsNotExist(authErr):
			return Credential{}, nil, fmt.Errorf("inspect codex auth file: %w", authErr)
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
		credential, err := readOMPCredential(ctx, sourcePath)
		return credential, info, err
	}
	credential, err := readCredentialJSON(sourcePath)
	return credential, info, err
}

func readCredentialJSON(path string) (Credential, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Credential{}, errors.New("credential path is empty")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return Credential{}, fmt.Errorf("stat credential file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return Credential{}, errors.New("credential file is a symbolic link")
	}
	if !linkInfo.Mode().IsRegular() {
		return Credential{}, errors.New("credential file is not a regular file")
	}
	if linkInfo.Size() > maxCredentialJSONBytes {
		return Credential{}, errors.New("credential file is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return Credential{}, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialJSONBytes+1))
	if err != nil {
		return Credential{}, fmt.Errorf("read credential file: %w", err)
	}
	if int64(len(data)) > maxCredentialJSONBytes {
		return Credential{}, errors.New("credential file is too large")
	}
	credential, err := parseCredentialJSON(data)
	if err != nil {
		return Credential{}, fmt.Errorf("parse credential source: %w", err)
	}
	return credential, nil
}

func parseCredentialJSON(data []byte) (Credential, error) {
	if len(data) > maxCredentialJSONBytes {
		return Credential{}, errors.New("credential JSON is too large")
	}
	var auth codexAuthFile
	if err := json.Unmarshal(data, &auth); err != nil {
		return Credential{}, errors.New("invalid credential JSON")
	}
	accessToken := auth.AccessToken
	refreshToken := auth.RefreshToken
	idToken := auth.IDToken
	expiresAt := time.Time{}
	if auth.ExpiresAt > 0 {
		expiresAt = time.Unix(auth.ExpiresAt, 0)
	}
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
		if auth.Tokens.ExpiresAt > 0 {
			expiresAt = time.Unix(auth.Tokens.ExpiresAt, 0)
		}
		if accountID == "" {
			accountID = auth.Tokens.AccountID
		}
	}
	if accessToken == "" || refreshToken == "" {
		var omp ompCredentialData
		if err := json.Unmarshal(data, &omp); err == nil && omp.AccessToken != "" && omp.Refresh != "" {
			ompExpiresAt := time.Time{}
			if omp.Expires > 0 {
				ompExpiresAt = time.UnixMilli(omp.Expires)
			}
			return buildCredential(omp.AccessToken, omp.Refresh, idToken, ompExpiresAt, omp.AccountID, userID, omp.Workspace, omp.PlanType, fedramp, omp.Email, false)
		}
	}
	return buildCredential(accessToken, refreshToken, idToken, expiresAt, accountID, userID, workspaceID, planType, fedramp, email, false)
}

func readOMPCredential(ctx context.Context, path string) (Credential, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return Credential{}, fmt.Errorf("inspect OMP credential database: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return Credential{}, errors.New("OMP credential database is a symbolic link")
	}
	if !linkInfo.Mode().IsRegular() {
		return Credential{}, errors.New("OMP credential database is not a regular file")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return Credential{}, errors.New("resolve OMP credential database")
	}
	databaseURL := url.URL{
		Scheme:   "file",
		Path:     filepath.ToSlash(absolutePath),
		RawQuery: url.Values{"mode": []string{"ro"}}.Encode(),
	}
	db, err := gorm.Open(sqlite.Open(databaseURL.String()), &gorm.Config{})
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
	if err := db.WithContext(ctx).Raw("SELECT substr(data, 1, ?) AS data FROM auth_credentials WHERE provider = ? AND credential_type = ? AND disabled_cause IS NULL ORDER BY id ASC LIMIT 1", maxCredentialJSONBytes+1, "openai-codex", "oauth").Scan(&row).Error; err != nil {
		return Credential{}, errors.New("read OMP credential database")
	}
	if strings.TrimSpace(row.Data) == "" {
		return Credential{}, errors.New("omp codex credential is missing")
	}
	return parseCredentialJSON([]byte(row.Data))
}

func readCodexKeyring(ctx context.Context, codexHome string) ([]byte, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("codex keyring import is not supported on this platform")
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
		return nil, errors.New("read codex keyring")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, errors.New("read codex keyring")
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxCredentialJSONBytes+1))
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil {
		return nil, errors.New("codex keyring credential is unavailable")
	}
	if len(data) > maxCredentialJSONBytes {
		return nil, errors.New("codex keyring credential is too large")
	}
	return data, nil
}

type tokenIdentity struct {
	accountID, userID, workspaceID, planType, email string
	fedramp                                         bool
}

func (claims identityClaims) identity() tokenIdentity {
	identity := tokenIdentity{
		accountID:   firstNonEmpty(claims.AccountID, claims.AccountID2),
		userID:      firstNonEmpty(claims.UserID, claims.Subject),
		workspaceID: claims.WorkspaceID,
		email:       claims.Email,
	}
	if claims.Auth != nil {
		identity.accountID = firstNonEmpty(claims.Auth.AccountID, identity.accountID)
		identity.userID = firstNonEmpty(claims.Auth.UserID, claims.Auth.UserID2, identity.userID)
		identity.workspaceID = firstNonEmpty(claims.Auth.WorkspaceID, identity.workspaceID)
		identity.planType = claims.Auth.PlanType
		identity.fedramp = claims.Auth.AccountIsFedRAMP
	}
	if identity.email == "" && claims.Profile != nil {
		identity.email = claims.Profile.Email
	}
	return identity
}

func buildCredential(accessToken, refreshToken, idToken string, expiresAt time.Time, accountID, userID, workspaceID, planType string, fedramp bool, email string, requireIdentity bool) (Credential, error) {
	credential := Credential{
		AccessToken:      strings.TrimSpace(accessToken),
		IDToken:          strings.TrimSpace(idToken),
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
	accessIdentity := jwtIdentity(credential.AccessToken).identity()
	idIdentity := jwtIdentity(idToken).identity()
	if credential.AccountID == "" {
		credential.AccountID = firstNonEmpty(accessIdentity.accountID, idIdentity.accountID)
	}
	if credential.UserID == "" {
		credential.UserID = firstNonEmpty(accessIdentity.userID, idIdentity.userID)
	}
	if credential.WorkspaceID == "" {
		credential.WorkspaceID = firstNonEmpty(accessIdentity.workspaceID, idIdentity.workspaceID, credential.AccountID)
	}
	if credential.PlanType == "" {
		credential.PlanType = firstNonEmpty(accessIdentity.planType, idIdentity.planType)
	}
	if !credential.AccountIsFedRAMP {
		credential.AccountIsFedRAMP = accessIdentity.fedramp || idIdentity.fedramp
	}
	if credential.Email == "" {
		credential.Email = firstNonEmpty(accessIdentity.email, idIdentity.email)
	}
	if err := credentialValidation.Struct(credential); err != nil {
		return Credential{}, errors.New("invalid credential")
	}
	if requireIdentity && credential.AccountID == "" {
		return Credential{}, errors.New("credential is missing account identity")
	}
	return credential, nil
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
	if err != nil || len(payload) > maxCredentialJSONBytes {
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
