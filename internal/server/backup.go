package server

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"github.com/catgirl-systems/codex-sub-proxy/internal/version"
	"gorm.io/gorm"
)

const (
	backupFormat             = "csp-backup-v1"
	backupManifestName       = "manifest.json"
	backupDatabaseName       = "database.sqlite3"
	backupArtifactPrefix     = "artifacts/"
	backupMaxEntries         = 4096
	backupMaxEntrySize       = 256 << 20
	backupMaxTotalSize       = 512 << 20
	backupMaxManifestSize    = 1 << 20
	restoreMaxArchiveSize    = 768 << 20
	restoreMaxArchiveEntries = backupMaxEntries + 2
	restoreMarkerSuffix      = ".restore-marker"
)

type BackupEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type BackupManifest struct {
	Format        string              `json:"format"`
	SchemaVersion uint                `json:"schema_version"`
	AppVersion    string              `json:"app_version"`
	Timestamp     string              `json:"timestamp"`
	KeyVersions   map[string][]uint32 `json:"key_versions"`
	Entries       []BackupEntry       `json:"entries"`
}

type RestoreOptions struct {
	DatabasePath          string
	ArtifactRoot          string
	Input                 string
	Force                 bool
	PayloadKeyVersions    []uint32
	CredentialKeyVersions []uint32
	JournalKeyVersions    []uint32
	BusyTimeout           time.Duration
}

type restoreMarker struct {
	DatabasePath string `json:"database_path"`
	ArtifactRoot string `json:"artifact_root"`
	OldDatabase  string `json:"old_database"`
	OldArtifacts string `json:"old_artifacts"`
	NewDatabase  string `json:"new_database"`
	NewArtifacts string `json:"new_artifacts"`
}

type backupArtifact struct {
	record ArtifactRecord
	path   string
}

// CreateBackup writes one online SQLite snapshot and its referenced ciphertext.
func CreateBackup(ctx context.Context, db *gorm.DB, artifacts *ArtifactStore, destination, principal string) error {
	if ctx == nil {
		return errors.New("backup context is nil")
	}
	if db == nil {
		return errors.New("backup database is nil")
	}
	if strings.TrimSpace(principal) == "" {
		return errors.New("backup principal is empty")
	}
	output, err := validateBackupDestination(destination)
	if err != nil {
		return err
	}
	if artifacts != nil {
		artifacts.operationMu.Lock()
		defer artifacts.operationMu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := recordBackupAudit(ctx, db, principal); err != nil {
		return err
	}
	parent := filepath.Dir(output)
	snapshotFile, err := os.CreateTemp(parent, ".csp-backup-snapshot-*")
	if err != nil {
		return fmt.Errorf("create backup snapshot temporary file: %w", err)
	}
	snapshotPath := snapshotFile.Name()
	if err := snapshotFile.Close(); err != nil {
		_ = os.Remove(snapshotPath)
		return fmt.Errorf("close backup snapshot temporary file: %w", err)
	}
	if err := os.Remove(snapshotPath); err != nil {
		return fmt.Errorf("prepare backup snapshot path: %w", err)
	}
	defer os.Remove(snapshotPath)
	if err := vacuumInto(ctx, db, snapshotPath); err != nil {
		return err
	}
	if err := os.Chmod(snapshotPath, 0o600); err != nil {
		return fmt.Errorf("set backup snapshot permissions: %w", err)
	}
	snapshotInfo, err := privateRegularFile(snapshotPath, backupMaxEntrySize)
	if err != nil {
		return fmt.Errorf("validate backup snapshot: %w", err)
	}
	snapshotDigest, err := fileSHA256(snapshotPath, snapshotInfo.Size())
	if err != nil {
		return fmt.Errorf("hash backup snapshot: %w", err)
	}

	artifactFiles, keyVersions, totalSize, err := collectBackupArtifacts(artifacts, ctx)
	if err != nil {
		return err
	}
	if snapshotInfo.Size() > backupMaxTotalSize-totalSize {
		return errors.New("backup total size exceeds limit")
	}
	entries := make([]BackupEntry, 0, len(artifactFiles)+1)
	entries = append(entries, BackupEntry{Path: backupDatabaseName, Size: snapshotInfo.Size(), SHA256: hex.EncodeToString(snapshotDigest[:]), Mode: uint32(snapshotInfo.Mode().Perm())})
	for _, artifact := range artifactFiles {
		info, infoErr := artifactFileInfo(artifacts, artifact.record.RelativePath)
		if infoErr != nil {
			return fmt.Errorf("validate artifact %q: %w", artifact.record.ID, infoErr)
		}
		entries = append(entries, BackupEntry{Path: backupArtifactPrefix + artifact.record.RelativePath, Size: info.Size(), SHA256: hex.EncodeToString(artifact.record.CiphertextSHA256), Mode: uint32(info.Mode().Perm())})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	manifest := BackupManifest{
		Format:        backupFormat,
		SchemaVersion: currentSchemaVersion,
		AppVersion:    version.Version,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		KeyVersions:   keyVersions,
		Entries:       entries,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode backup manifest: %w", err)
	}
	if len(manifestBytes) > backupMaxManifestSize {
		return errors.New("backup manifest is too large")
	}
	if err := publishBackupTar(ctx, output, manifestBytes, snapshotPath, artifactFiles, artifacts); err != nil {
		return err
	}
	return nil
}

func recordBackupAudit(ctx context.Context, db *gorm.DB, principal string) error {
	auditID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate backup audit ID: %w", err)
	}
	now := time.Now().UTC()
	metadata := `{"format":"csp-backup-v1"}`
	if err := db.WithContext(ctx).Create(&AuditRecord{ID: auditID, EventType: "backup.create", Status: 200, CreatedAt: now, ExpiresAt: now.Add(adminAuditTTL), PrincipalName: principal, Action: "backup.create", Metadata: metadata}).Error; err != nil {
		return fmt.Errorf("record backup audit: %w", err)
	}
	return nil
}

func vacuumInto(ctx context.Context, db *gorm.DB, destination string) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get SQLite database for backup: %w", err)
	}
	if _, err := sqlDB.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return fmt.Errorf("create online SQLite snapshot: %w", err)
	}
	return nil
}

func collectBackupArtifacts(artifacts *ArtifactStore, ctx context.Context) ([]backupArtifact, map[string][]uint32, int64, error) {
	keyVersions := map[string][]uint32{}
	if artifacts == nil {
		return nil, keyVersions, 0, nil
	}
	var records []ArtifactRecord
	if err := artifacts.db.WithContext(ctx).Where("state = ? AND deleted_at IS NULL", artifactStateReady).Order("relative_path ASC").Find(&records).Error; err != nil {
		return nil, nil, 0, fmt.Errorf("load backup artifact records: %w", err)
	}
	if len(records) > backupMaxEntries {
		return nil, nil, 0, errors.New("backup has too many artifact entries")
	}
	files := make([]backupArtifact, 0, len(records))
	var total int64
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		if err := validateArtifactRecord(record); err != nil {
			return nil, nil, 0, fmt.Errorf("validate backup artifact %q: %w", record.ID, err)
		}
		if record.CiphertextSize > backupMaxEntrySize || record.CiphertextSize <= 0 {
			return nil, nil, 0, errors.New("backup artifact size is invalid")
		}
		if _, err := artifacts.readArtifactFile(record); err != nil {
			return nil, nil, 0, fmt.Errorf("verify backup artifact %q: %w", record.ID, err)
		}
		total += record.CiphertextSize
		if total < 0 || total > backupMaxTotalSize {
			return nil, nil, 0, errors.New("backup artifact total size exceeds limit")
		}
		files = append(files, backupArtifact{record: record, path: record.RelativePath})
		keyVersions["artifact"] = append(keyVersions["artifact"], record.KeyVersion)
	}
	keyVersions["artifact"] = uniqueSortedVersions(keyVersions["artifact"])
	return files, keyVersions, total, nil
}

func uniqueSortedVersions(values []uint32) []uint32 {
	if len(values) == 0 {
		return []uint32{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	result := values[:0]
	for _, value := range values {
		if value == 0 || (len(result) > 0 && result[len(result)-1] == value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func publishBackupTar(ctx context.Context, output string, manifest []byte, snapshotPath string, artifacts []backupArtifact, store *ArtifactStore) error {
	parent := filepath.Dir(output)
	temporary, err := os.OpenFile(filepath.Join(parent, ".csp-backup-"+filepath.Base(output)+".tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create backup temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	writer := tar.NewWriter(temporary)
	if err := writeTarBytes(writer, backupManifestName, manifest); err != nil {
		_ = writer.Close()
		return err
	}
	if err := copyTarFile(ctx, writer, backupDatabaseName, snapshotPath, backupMaxEntrySize); err != nil {
		_ = writer.Close()
		return err
	}
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			_ = writer.Close()
			return err
		}
		if err := copyArtifactTarFile(ctx, writer, backupArtifactPrefix+artifact.record.RelativePath, artifact.record, store); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close backup archive: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync backup archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close backup archive file: %w", err)
	}
	if _, err := os.Lstat(output); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	if err := os.Link(temporaryPath, output); err != nil {
		return fmt.Errorf("publish backup archive: %w", err)
	}
	removeTemporary = false
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("remove backup temporary link: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	return nil
}

func writeTarBytes(writer *tar.Writer, name string, data []byte) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup entry %q: %w", name, err)
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write backup entry %q: %w", name, err)
	}
	return nil
}

func copyTarFile(ctx context.Context, writer *tar.Writer, name, path string, maxSize int64) error {
	info, err := privateRegularFile(path, maxSize)
	if err != nil {
		return fmt.Errorf("validate backup file %q: %w", name, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open backup file %q: %w", name, err)
	}
	defer file.Close()
	header := &tar.Header{Name: name, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup header %q: %w", name, err)
	}
	if err := copyWithContext(ctx, writer, file, info.Size()); err != nil {
		return fmt.Errorf("copy backup file %q: %w", name, err)
	}
	return nil
}

func copyArtifactTarFile(ctx context.Context, writer *tar.Writer, name string, record ArtifactRecord, store *ArtifactStore) error {
	info, err := artifactFileInfo(store, record.RelativePath)
	if err != nil {
		return fmt.Errorf("validate backup artifact %q: %w", record.ID, err)
	}
	if info.Size() != record.CiphertextSize {
		return errors.New("backup artifact size changed")
	}
	file, err := store.root.OpenFile(record.RelativePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open backup artifact %q: %w", record.ID, err)
	}
	defer file.Close()
	header := &tar.Header{Name: name, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup artifact header %q: %w", record.ID, err)
	}
	if err := copyWithContext(ctx, writer, file, info.Size()); err != nil {
		return fmt.Errorf("copy backup artifact %q: %w", record.ID, err)
	}
	return nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader, size int64) error {
	reader := io.LimitReader(source, size+1)
	written, err := io.Copy(destination, reader)
	if err != nil {
		return err
	}
	if written != size {
		return errors.New("backup source size changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func artifactFileInfo(store *ArtifactStore, relative string) (os.FileInfo, error) {
	if store == nil || store.root == nil {
		return nil, errors.New("artifact store is closed")
	}
	if err := validateArtifactRelativePath(relative); err != nil {
		return nil, err
	}
	info, err := store.root.Lstat(relative)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) {
		return nil, errors.New("artifact is not a private regular file")
	}
	return info, nil
}

func privateRegularFile(path string, maxSize int64) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) || info.Mode().Perm() != 0o600 {
		return nil, errors.New("file is not a private regular file")
	}
	if info.Size() < 0 || info.Size() > maxSize {
		return nil, errors.New("file size exceeds limit")
	}
	return info, nil
}

func fileSHA256(path string, size int64) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	file, err := os.Open(path)
	if err != nil {
		return digest, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, size); err != nil {
		return digest, err
	}
	if _, err := file.Read(make([]byte, 1)); err != io.EOF {
		if err == nil {
			return digest, errors.New("file size changed")
		}
		return digest, err
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func validateBackupDestination(destination string) (string, error) {
	if strings.TrimSpace(destination) == "" {
		return "", errors.New("backup destination is empty")
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("resolve backup destination: %w", err)
	}
	if filepath.Clean(absolute) != absolute || absolute == string(filepath.Separator) {
		return "", errors.New("backup destination path is unsafe")
	}
	parent := filepath.Dir(absolute)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect backup destination parent: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("backup destination parent is not a directory")
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect backup destination: %w", err)
	}
	return absolute, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

// Restore validates an offline archive and atomically installs its database and artifacts.
func Restore(ctx context.Context, options RestoreOptions) error {
	if ctx == nil {
		return errors.New("restore context is nil")
	}
	if options.BusyTimeout <= 0 {
		options.BusyTimeout = 5 * time.Second
	}
	databasePath, err := absoluteCleanPath(options.DatabasePath)
	if err != nil {
		return fmt.Errorf("restore database path: %w", err)
	}
	artifactRoot, err := absoluteCleanPath(options.ArtifactRoot)
	if err != nil {
		return fmt.Errorf("restore artifact root: %w", err)
	}
	input, err := absoluteCleanPath(options.Input)
	if err != nil {
		return fmt.Errorf("restore input: %w", err)
	}
	if err := validateRestoreInput(input); err != nil {
		return err
	}
	lock, err := storage.AcquireApplicationLock(ctx, databasePath)
	if err != nil {
		return err
	}
	defer lock.Close()
	workParent, err := os.MkdirTemp(filepath.Dir(databasePath), ".csp-restore-*")
	if err != nil {
		return fmt.Errorf("create restore workspace: %w", err)
	}
	defer os.RemoveAll(workParent)
	stagedDB := filepath.Join(workParent, backupDatabaseName)
	stagedRoot := filepath.Join(workParent, "artifacts")
	if err := os.Mkdir(stagedRoot, 0o700); err != nil {
		return fmt.Errorf("create restore artifact root: %w", err)
	}
	if err := writePrivateFile(filepath.Join(stagedRoot, artifactRootSentinel), []byte("codex-sub-proxy artifact root v1\n"), 0o600); err != nil {
		return fmt.Errorf("write restore artifact sentinel: %w", err)
	}
	manifest, err := extractRestoreArchive(ctx, input, stagedDB, stagedRoot)
	if err != nil {
		return err
	}
	if err := validateRestoreManifest(manifest, options); err != nil {
		return err
	}
	if err := validateRestoredDatabase(ctx, stagedDB, stagedRoot, manifest, options.BusyTimeout); err != nil {
		return err
	}
	if err := syncDirectory(stagedRoot); err != nil {
		return err
	}
	if err := syncDirectory(workParent); err != nil {
		return err
	}
	if err := installRestoreSet(databasePath, artifactRoot, stagedDB, stagedRoot, options.Force); err != nil {
		return err
	}
	return nil
}

func extractRestoreArchive(ctx context.Context, input, stagedDB, stagedRoot string) (BackupManifest, error) {
	file, err := os.Open(input)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("open restore archive: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return BackupManifest{}, fmt.Errorf("stat restore archive: %w", err)
	}
	if info.Size() <= 0 || info.Size() > restoreMaxArchiveSize {
		return BackupManifest{}, errors.New("restore archive size is invalid")
	}
	limited := &countingReader{reader: io.LimitReader(file, restoreMaxArchiveSize+1)}
	reader := tar.NewReader(limited)
	seen := make(map[string]struct{})
	var manifest BackupManifest
	manifestRead := false
	var total int64
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return BackupManifest{}, err
		}
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return BackupManifest{}, fmt.Errorf("read restore archive: %w", nextErr)
		}
		entries++
		if entries > restoreMaxArchiveEntries {
			return BackupManifest{}, errors.New("restore archive has too many entries")
		}
		if header == nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > backupMaxEntrySize || header.Mode&0o777 != 0o600 {
			return BackupManifest{}, errors.New("restore archive entry type or mode is invalid")
		}
		if _, exists := seen[header.Name]; exists {
			return BackupManifest{}, errors.New("restore archive has duplicate entries")
		}
		seen[header.Name] = struct{}{}
		switch {
		case header.Name == backupManifestName:
			if manifestRead || header.Size > backupMaxManifestSize {
				return BackupManifest{}, errors.New("restore manifest is invalid")
			}
			data, readErr := io.ReadAll(io.LimitReader(reader, header.Size+1))
			if readErr != nil || int64(len(data)) != header.Size {
				return BackupManifest{}, errors.New("restore manifest size is invalid")
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return BackupManifest{}, fmt.Errorf("decode restore manifest: %w", err)
			}
			manifestRead = true
		case header.Name == backupDatabaseName:
			if !manifestRead || header.Size == 0 {
				return BackupManifest{}, errors.New("restore database entry is out of order")
			}
			if err := extractEntryFile(reader, stagedDB, header.Size); err != nil {
				return BackupManifest{}, err
			}
		case strings.HasPrefix(header.Name, backupArtifactPrefix):
			if !manifestRead || !validRestoreArtifactName(header.Name) {
				return BackupManifest{}, errors.New("restore artifact entry path is invalid")
			}
			path := filepath.Join(stagedRoot, strings.TrimPrefix(header.Name, backupArtifactPrefix))
			if err := extractEntryFile(reader, path, header.Size); err != nil {
				return BackupManifest{}, err
			}
		default:
			return BackupManifest{}, fmt.Errorf("restore archive entry %q is unknown", header.Name)
		}
		total += header.Size
		if total < 0 || total > backupMaxTotalSize {
			return BackupManifest{}, errors.New("restore archive content exceeds limit")
		}
	}
	if limited.count > restoreMaxArchiveSize {
		return BackupManifest{}, errors.New("restore archive is too large")
	}
	manifestPaths := make(map[string]struct{}, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		manifestPaths[entry.Path] = struct{}{}
	}
	archivePaths := make(map[string]struct{}, len(seen))
	for name := range seen {
		if name != backupManifestName {
			archivePaths[name] = struct{}{}
		}
	}
	if len(manifestPaths) != len(archivePaths) {
		return BackupManifest{}, errors.New("restore archive entries do not match manifest")
	}
	for name := range archivePaths {
		if _, ok := manifestPaths[name]; !ok {
			return BackupManifest{}, errors.New("restore archive contains an unlisted entry")
		}
	}
	var trailing [1]byte
	if _, err := file.Read(trailing[:]); err != io.EOF {
		return BackupManifest{}, errors.New("restore archive has trailing bytes")
	}
	if !manifestRead {
		return BackupManifest{}, errors.New("restore manifest is missing")
	}
	return manifest, nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (reader *countingReader) Read(data []byte) (int, error) {
	count, err := reader.reader.Read(data)
	reader.count += int64(count)
	return count, err
}

func extractEntryFile(reader io.Reader, path string, size int64) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create restore entry %q: %w", filepath.Base(path), err)
	}
	if _, err := io.CopyN(file, reader, size); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("extract restore entry: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync restore entry: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close restore entry: %w", err)
	}
	return nil
}

func writePrivateFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func validateRestoreManifest(manifest BackupManifest, options RestoreOptions) error {
	if manifest.Format != backupFormat || manifest.SchemaVersion != currentSchemaVersion || strings.TrimSpace(manifest.Timestamp) == "" {
		return errors.New("restore manifest format or schema is unsupported")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.Timestamp); err != nil {
		return errors.New("restore manifest timestamp is invalid")
	}
	if len(manifest.Entries) == 0 || len(manifest.Entries) > backupMaxEntries+1 {
		return errors.New("restore manifest entries are invalid")
	}
	entries := make(map[string]BackupEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if entry.Path == "" || entry.Size <= 0 || entry.Size > backupMaxEntrySize || len(entry.SHA256) != sha256.Size*2 || entry.Mode != 0o600 {
			return errors.New("restore manifest entry is invalid")
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return errors.New("restore manifest digest is invalid")
		}
		if _, exists := entries[entry.Path]; exists {
			return errors.New("restore manifest has duplicate entries")
		}
		entries[entry.Path] = entry
	}
	if _, ok := entries[backupDatabaseName]; !ok {
		return errors.New("restore manifest has no database entry")
	}
	for path := range entries {
		if path != backupDatabaseName && !validRestoreArtifactName(path) {
			return errors.New("restore manifest has unknown entry")
		}
	}
	if !versionsSortedUnique(manifest.KeyVersions["artifact"]) {
		return errors.New("restore manifest key versions are invalid")
	}
	if err := requireConfiguredVersions(manifest.KeyVersions["artifact"], options.PayloadKeyVersions); err != nil {
		return err
	}
	return nil
}

func requireConfiguredVersions(required, configured []uint32) error {
	if len(required) == 0 {
		return nil
	}
	allowed := make(map[uint32]struct{}, len(configured))
	for _, version := range configured {
		allowed[version] = struct{}{}
	}
	for _, version := range required {
		if _, ok := allowed[version]; !ok {
			return fmt.Errorf("restore requires unavailable encryption key version %d", version)
		}
	}
	return nil
}

func versionsSortedUnique(values []uint32) bool {
	for index, value := range values {
		if value == 0 || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func validRestoreArtifactName(name string) bool {
	if !strings.HasPrefix(name, backupArtifactPrefix) {
		return false
	}
	relative := strings.TrimPrefix(name, backupArtifactPrefix)
	return strings.HasSuffix(relative, ".bin") && validJournalUUID(strings.TrimSuffix(relative, ".bin"))
}

func validateRestoredDatabase(ctx context.Context, databasePath, artifactRoot string, manifest BackupManifest, busyTimeout time.Duration) error {
	if err := verifyManifestFiles(databasePath, artifactRoot, manifest); err != nil {
		return err
	}
	db, err := storage.Open(ctx, databasePath, busyTimeout)
	if err != nil {
		return fmt.Errorf("open restored SQLite database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var check string
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check); err != nil {
		return fmt.Errorf("check restored SQLite integrity: %w", err)
	}
	if check != "ok" {
		return fmt.Errorf("restored SQLite integrity check failed: %s", check)
	}
	var tableCount int
	if err := sqlDB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'artifacts'").Scan(&tableCount); err != nil || tableCount != 1 {
		return errors.New("restored database has no artifact table")
	}
	var records []ArtifactRecord
	if err := db.WithContext(ctx).Find(&records).Error; err != nil {
		return fmt.Errorf("load restored artifact records: %w", err)
	}
	for _, record := range records {
		if record.State != artifactStateReady || record.DeletedAt != nil {
			continue
		}
		if err := validateArtifactRecord(record); err != nil {
			return fmt.Errorf("validate restored artifact metadata: %w", err)
		}
		path := filepath.Join(artifactRoot, record.RelativePath)
		info, err := privateRegularFile(path, backupMaxEntrySize)
		if err != nil || info.Size() != record.CiphertextSize {
			return fmt.Errorf("validate restored artifact file %q: %w", record.ID, err)
		}
		digest, err := fileSHA256(path, info.Size())
		if err != nil || hex.EncodeToString(digest[:]) != hex.EncodeToString(record.CiphertextSHA256) {
			return fmt.Errorf("validate restored artifact digest %q", record.ID)
		}
	}
	return nil
}

func verifyManifestFiles(databasePath, artifactRoot string, manifest BackupManifest) error {
	for _, entry := range manifest.Entries {
		var path string
		if entry.Path == backupDatabaseName {
			path = databasePath
		} else {
			path = filepath.Join(artifactRoot, strings.TrimPrefix(entry.Path, backupArtifactPrefix))
		}
		info, err := privateRegularFile(path, backupMaxEntrySize)
		if err != nil || info.Size() != entry.Size {
			return fmt.Errorf("restore entry %q does not match manifest", entry.Path)
		}
		digest, err := fileSHA256(path, entry.Size)
		if err != nil || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("restore entry %q checksum mismatch", entry.Path)
		}
	}
	return nil
}

func validateRestoreInput(input string) error {
	info, err := os.Lstat(input)
	if err != nil {
		return fmt.Errorf("inspect restore archive: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) {
		return errors.New("restore archive is not a private regular file")
	}
	return nil
}

func absoluteCleanPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if filepath.Clean(absolute) != absolute || absolute == string(filepath.Separator) {
		return "", errors.New("path is unsafe")
	}
	return absolute, nil
}

func installRestoreSet(databasePath, artifactRoot, stagedDB, stagedRoot string, force bool) error {
	for _, path := range []string{databasePath, artifactRoot} {
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("restore target is a symlink")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if !force {
		if _, err := os.Lstat(databasePath); err == nil {
			return errors.New("restore database exists; use --force")
		}
		if _, err := os.Lstat(artifactRoot); err == nil {
			return errors.New("restore artifact root exists; use --force")
		}
	}
	marker := restoreMarker{DatabasePath: databasePath, ArtifactRoot: artifactRoot, OldDatabase: databasePath + ".restore-old", OldArtifacts: artifactRoot + ".restore-old", NewDatabase: stagedDB, NewArtifacts: stagedRoot}
	if err := writeRestoreMarker(marker); err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = recoverRestoreMarker(marker)
		}
	}()
	if force {
		if _, err := os.Lstat(databasePath); err == nil {
			if err := os.Rename(databasePath, marker.OldDatabase); err != nil {
				return fmt.Errorf("move old database: %w", err)
			}
		}
		if _, err := os.Lstat(artifactRoot); err == nil {
			if err := os.Rename(artifactRoot, marker.OldArtifacts); err != nil {
				return fmt.Errorf("move old artifact root: %w", err)
			}
		}
	}
	if err := os.Rename(stagedDB, databasePath); err != nil {
		return fmt.Errorf("install restored database: %w", err)
	}
	if err := os.Rename(stagedRoot, artifactRoot); err != nil {
		return fmt.Errorf("install restored artifact root: %w", err)
	}
	if err := syncDirectory(filepath.Dir(databasePath)); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(artifactRoot)); err != nil {
		return err
	}
	for _, path := range []string{marker.OldDatabase, marker.OldArtifacts} {
		if _, err := os.Lstat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("remove restore backup: %w", err)
			}
		}
	}
	if err := os.Remove(databasePath + restoreMarkerSuffix); err == nil {
		rollback = false
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rollback = false
	return nil
}

func writeRestoreMarker(marker restoreMarker) error {
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	path := marker.DatabasePath + restoreMarkerSuffix
	return writeAtomicPrivate(path, data)
}

func writeAtomicPrivate(path string, data []byte) error {
	parent := filepath.Dir(path)
	file, err := os.CreateTemp(parent, ".csp-marker-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

// RecoverRestore converges an interrupted restore before the database opens.
func RecoverRestore(databasePath string) error {
	path, err := absoluteCleanPath(databasePath)
	if err != nil {
		return err
	}
	markerPath := path + restoreMarkerSuffix
	data, err := os.ReadFile(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read restore marker: %w", err)
	}
	var marker restoreMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("decode restore marker: %w", err)
	}
	if marker.DatabasePath != path || marker.ArtifactRoot == "" || marker.NewDatabase == "" || marker.NewArtifacts == "" {
		return errors.New("restore marker is invalid")
	}
	return recoverRestoreMarker(marker)
}

func recoverRestoreMarker(marker restoreMarker) error {
	dbExists := exists(marker.DatabasePath)
	rootExists := exists(marker.ArtifactRoot)
	newDBExists := exists(marker.NewDatabase)
	newRootExists := exists(marker.NewArtifacts)
	if dbExists && rootExists {
		if newDBExists {
			_ = os.RemoveAll(marker.NewDatabase)
		}
		if newRootExists {
			_ = os.RemoveAll(marker.NewArtifacts)
		}
		_ = os.RemoveAll(marker.OldDatabase)
		_ = os.RemoveAll(marker.OldArtifacts)
		return os.Remove(marker.DatabasePath + restoreMarkerSuffix)
	}
	if !dbExists && exists(marker.OldDatabase) {
		if err := os.Rename(marker.OldDatabase, marker.DatabasePath); err != nil {
			return err
		}
	}
	if !rootExists && exists(marker.OldArtifacts) {
		if err := os.Rename(marker.OldArtifacts, marker.ArtifactRoot); err != nil {
			return err
		}
	}
	if exists(marker.NewDatabase) {
		_ = os.RemoveAll(marker.NewDatabase)
	}
	if exists(marker.NewArtifacts) {
		_ = os.RemoveAll(marker.NewArtifacts)
	}
	_ = os.RemoveAll(marker.OldDatabase)
	_ = os.RemoveAll(marker.OldArtifacts)
	return os.Remove(marker.DatabasePath + restoreMarkerSuffix)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
