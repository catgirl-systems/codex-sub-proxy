package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"gorm.io/gorm"
)

const (
	artifactFormatVersion      byte = 1
	artifactChunkFormatVersion byte = 1
	artifactHeaderSize              = 4 + 1 + 4
	artifactMaxChunks               = 64
	artifactMaxPlaintextSize        = 64 << 20
	artifactMaxOwnerFieldSize       = 255
	artifactStateWriting            = "writing"
	artifactStateReady              = "ready"
	artifactStateDeleting           = "deleting"
	artifactRootSentinel            = ".csp-artifact-root"
	artifactReconcileBatch          = 64
	artifactSentinelMode            = 0o600
)

var (
	artifactMagic      = [4]byte{'C', 'S', 'P', 'A'}
	artifactChunkMagic = [4]byte{'C', 'S', 'P', 'C'}
)

// ArtifactOwner identifies the lifecycle owner of one encrypted artifact.
type ArtifactOwner struct {
	RequestID      string
	ConversationID string
	APIKeyID       string
}

// ArtifactRecord stores only metadata and a relative ciphertext path.
type ArtifactRecord struct {
	ID               string     `gorm:"column:id;primaryKey;size:36"`
	RequestID        string     `gorm:"column:request_id;not null;size:36;index:idx_artifact_request"`
	ConversationID   string     `gorm:"column:conversation_id;not null;size:36;index:idx_artifact_conversation"`
	APIKeyID         string     `gorm:"column:api_key_id;size:255;index:idx_artifact_api_key"`
	ResultIndex      int        `gorm:"column:result_index;not null;uniqueIndex:idx_artifact_owner_result"`
	MIME             string     `gorm:"column:mime;not null;size:32"`
	PlaintextSize    int64      `gorm:"column:plaintext_size;not null"`
	CiphertextSize   int64      `gorm:"column:ciphertext_size;not null"`
	CiphertextSHA256 []byte     `gorm:"column:ciphertext_sha256;not null;size:32"`
	KeyVersion       uint32     `gorm:"column:key_version;not null"`
	RelativePath     string     `gorm:"column:relative_path;not null;uniqueIndex"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null;index"`
	ExpiresAt        time.Time  `gorm:"column:expires_at;not null;index"`
	DeletedAt        *time.Time `gorm:"column:deleted_at;index"`
	State            string     `gorm:"column:state;not null;size:16;index"`
	persisted        bool       `gorm:"-"`
}

func (ArtifactRecord) TableName() string { return "artifacts" }

// ArtifactStore owns encrypted files below one descriptor-anchored root.
type ArtifactStore struct {
	db          *gorm.DB
	root        *os.Root
	rootPath    string
	barrierPath string
	keys        envelope.KeySet
	ttl         time.Duration
	operationMu sync.RWMutex
	closeOnce   sync.Once
	closeErr    error
}

// ArtifactBarrierMode selects shared or exclusive artifact access.
type ArtifactBarrierMode int

const (
	ArtifactBarrierShared ArtifactBarrierMode = iota + 1
	ArtifactBarrierExclusive
)

const (
	artifactBarrierShared    = ArtifactBarrierShared
	artifactBarrierExclusive = ArtifactBarrierExclusive
)

type ArtifactBarrier struct {
	mu   sync.Mutex
	file *os.File
}

// ArtifactBarrierPath returns the lock file associated with an artifact root.
func ArtifactBarrierPath(rootPath string) string {
	return rootPath + ".artifact.lock"
}

// AcquireArtifactBarrier waits for a shared or exclusive artifact snapshot lock.
func AcquireArtifactBarrier(ctx context.Context, rootPath string, mode ArtifactBarrierMode) (*ArtifactBarrier, error) {
	if ctx == nil {
		return nil, errors.New("artifact barrier context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if mode != artifactBarrierShared && mode != artifactBarrierExclusive {
		return nil, errors.New("artifact barrier mode is invalid")
	}
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || rootPath == string(filepath.Separator) {
		return nil, errors.New("artifact barrier root is invalid")
	}
	parent := filepath.Dir(rootPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact barrier parent: %w", err)
	}
	file, err := os.OpenFile(ArtifactBarrierPath(rootPath), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open artifact barrier: %w", err)
	}
	flags := syscall.LOCK_NB
	if mode == artifactBarrierExclusive {
		flags |= syscall.LOCK_EX
	} else {
		flags |= syscall.LOCK_SH
	}
	for {
		err = syscall.Flock(int(file.Fd()), flags)
		if err == nil {
			return &ArtifactBarrier{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire artifact barrier: %w", err)
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (barrier *ArtifactBarrier) Close() error {
	if barrier == nil {
		return nil
	}
	barrier.mu.Lock()
	defer barrier.mu.Unlock()
	if barrier.file == nil {
		return nil
	}
	file := barrier.file
	barrier.file = nil
	return errors.Join(syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
}

// MigrateArtifacts creates the artifact metadata table.
func MigrateArtifacts(db *gorm.DB) error {
	if db == nil {
		return errors.New("artifact database is nil")
	}
	if err := db.AutoMigrate(&ArtifactRecord{}); err != nil {
		return fmt.Errorf("migrate artifacts: %w", err)
	}
	return nil
}

// NewArtifactStore validates the key set, adopts a private artifact root, and
// reconciles durable metadata before the store can publish files.
func NewArtifactStore(db *gorm.DB, rootPath string, keys envelope.KeySet, ttl time.Duration) (*ArtifactStore, error) {
	return newArtifactStore(db, rootPath, keys, ttl, nil)
}

// NewArtifactStoreWithBarrier adopts a root while the caller owns its barrier.
func NewArtifactStoreWithBarrier(db *gorm.DB, rootPath string, keys envelope.KeySet, ttl time.Duration, barrier *ArtifactBarrier) (*ArtifactStore, error) {
	if barrier == nil {
		return nil, errors.New("artifact barrier is nil")
	}
	return newArtifactStore(db, rootPath, keys, ttl, barrier)
}

func newArtifactStore(db *gorm.DB, rootPath string, keys envelope.KeySet, ttl time.Duration, heldBarrier *ArtifactBarrier) (*ArtifactStore, error) {
	if db == nil {
		return nil, errors.New("artifact database is nil")
	}
	if ttl <= 0 {
		return nil, errors.New("artifact TTL must be positive")
	}
	validatedKeys, err := envelope.NewKeySet(keys.Active, keys.Previous...)
	if err != nil {
		return nil, fmt.Errorf("validate artifact encryption keys: %w", err)
	}
	var barrier *ArtifactBarrier
	if heldBarrier == nil {
		barrier, err = AcquireArtifactBarrier(context.Background(), rootPath, artifactBarrierShared)
		if err != nil {
			return nil, err
		}
		defer barrier.Close()
	} else {
		barrier = heldBarrier
	}
	root, err := prepareArtifactRoot(rootPath)
	if err != nil {
		return nil, err
	}
	if err := MigrateArtifacts(db); err != nil {
		_ = root.Close()
		return nil, err
	}
	store := &ArtifactStore{db: db, root: root, rootPath: rootPath, barrierPath: ArtifactBarrierPath(rootPath), keys: validatedKeys, ttl: ttl}
	if err := store.reconcileWithBarrier(context.Background(), barrier); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the descriptor-anchored artifact root.
func (s *ArtifactStore) Close() error {
	if s == nil {
		return nil
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.root == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closeErr = s.root.Close()
		s.root = nil
	})
	return s.closeErr
}
func (s *ArtifactStore) acquireOperation(ctx context.Context) (*ArtifactBarrier, error) {
	if s == nil {
		return nil, errors.New("artifact store is closed")
	}
	if ctx == nil {
		return nil, errors.New("artifact operation context is nil")
	}
	barrier, err := AcquireArtifactBarrier(ctx, s.rootPath, ArtifactBarrierShared)
	if err != nil {
		return nil, err
	}
	s.operationMu.Lock()
	if s.root == nil {
		s.operationMu.Unlock()
		_ = barrier.Close()
		return nil, errors.New("artifact store is closed")
	}
	return barrier, nil
}

func (s *ArtifactStore) releaseOperation(barrier *ArtifactBarrier) {
	_ = barrier.Close()
	s.operationMu.Unlock()
}

// Save encrypts one image and atomically records its ciphertext path.
func (s *ArtifactStore) Save(ctx context.Context, owner ArtifactOwner, resultIndex int, mimeType string, plaintext []byte) (ArtifactRecord, error) {
	barrier, err := s.acquireOperation(ctx)
	if err != nil {
		return ArtifactRecord{}, err
	}
	defer s.releaseOperation(barrier)
	if err := ctx.Err(); err != nil {
		return ArtifactRecord{}, err
	}
	if err := validateArtifactOwner(owner); err != nil {
		return ArtifactRecord{}, err
	}
	if err := s.checkArtifactOwner(ctx, owner); err != nil {
		return ArtifactRecord{}, err
	}
	if resultIndex < 0 {
		return ArtifactRecord{}, errors.New("artifact result index is invalid")
	}
	if len(plaintext) == 0 || len(plaintext) > artifactMaxPlaintextSize {
		return ArtifactRecord{}, errors.New("artifact plaintext size is invalid")
	}
	actualMIME, ok := artifactImageMIME(plaintext)
	if !ok {
		return ArtifactRecord{}, errors.New("artifact MIME type is unsupported")
	}
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	if mimeType == "" {
		mimeType = actualMIME
	}
	if mimeType != actualMIME {
		return ArtifactRecord{}, errors.New("artifact MIME type does not match content")
	}
	var existing ArtifactRecord
	err = s.db.WithContext(ctx).Where("request_id = ? AND conversation_id = ? AND api_key_id = ? AND result_index = ?", owner.RequestID, owner.ConversationID, owner.APIKeyID, resultIndex).First(&existing).Error
	if err == nil {
		if existing.MIME != mimeType || existing.PlaintextSize != int64(len(plaintext)) || existing.State != artifactStateReady {
			return ArtifactRecord{}, errors.New("artifact replay conflicts with existing record")
		}
		return existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return ArtifactRecord{}, fmt.Errorf("load artifact replay record: %w", err)
	}

	artifactID, err := newJournalUUID()
	if err != nil {
		return ArtifactRecord{}, fmt.Errorf("generate artifact ID: %w", err)
	}
	chunks, err := encryptArtifactChunks(owner, artifactID, mimeType, plaintext, s.keys)
	if err != nil {
		return ArtifactRecord{}, err
	}
	ciphertextSize := int64(artifactHeaderSize)
	for _, chunk := range chunks {
		ciphertextSize += 4 + int64(len(chunk))
	}
	if ciphertextSize <= 0 {
		return ArtifactRecord{}, errors.New("artifact ciphertext size is invalid")
	}
	relativePath := artifactID + ".bin"
	tempPath := "." + artifactID + ".tmp"
	now := time.Now().UTC()
	digest := sha256ArtifactFile(chunks)
	record := ArtifactRecord{
		ID:               artifactID,
		RequestID:        owner.RequestID,
		ConversationID:   owner.ConversationID,
		APIKeyID:         owner.APIKeyID,
		ResultIndex:      resultIndex,
		MIME:             mimeType,
		PlaintextSize:    int64(len(plaintext)),
		CiphertextSize:   ciphertextSize,
		CiphertextSHA256: append([]byte(nil), digest[:]...),
		KeyVersion:       s.keys.Active.Version,
		RelativePath:     relativePath,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.ttl),
		State:            artifactStateWriting,
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := checkArtifactOwnerTx(tx, owner); err != nil {
			return err
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("store artifact writing metadata: %w", err)
		}
		return nil
	}); err != nil {
		return ArtifactRecord{}, err
	}
	metadataCreated := true
	defer func() {
		if metadataCreated {
			cleanupCtx := context.WithoutCancel(ctx)
			_ = s.db.WithContext(cleanupCtx).Where("id = ? AND state = ?", record.ID, artifactStateWriting).Delete(&ArtifactRecord{}).Error
			_ = s.removeArtifactFile(relativePath)
		}
	}()

	file, err := s.root.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ArtifactRecord{}, fmt.Errorf("create artifact temporary file: %w", err)
	}
	tempExists := true
	defer func() {
		_ = file.Close()
		if tempExists {
			_ = s.root.Remove(tempPath)
		}
	}()
	if err := writeArtifactFile(file, chunks); err != nil {
		return ArtifactRecord{}, err
	}
	if err := file.Sync(); err != nil {
		return ArtifactRecord{}, fmt.Errorf("sync artifact file: %w", err)
	}
	if err := file.Close(); err != nil {
		return ArtifactRecord{}, fmt.Errorf("close artifact file: %w", err)
	}
	if _, err := s.root.Lstat(relativePath); err == nil {
		return ArtifactRecord{}, errors.New("artifact final path collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ArtifactRecord{}, fmt.Errorf("inspect artifact final path: %w", err)
	}
	if err := s.root.Rename(tempPath, relativePath); err != nil {
		return ArtifactRecord{}, fmt.Errorf("publish artifact file: %w", err)
	}
	tempExists = false
	if err := syncArtifactRoot(s.root); err != nil {
		return ArtifactRecord{}, err
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := checkArtifactOwnerTx(tx, owner); err != nil {
			return err
		}
		var current ArtifactRecord
		if err := tx.Where("id = ? AND state = ?", record.ID, artifactStateWriting).First(&current).Error; err != nil {
			return fmt.Errorf("load artifact writing metadata: %w", err)
		}
		result := tx.Model(&ArtifactRecord{}).Where("id = ? AND state = ?", record.ID, artifactStateWriting).Updates(map[string]any{"state": artifactStateReady})
		if result.Error != nil {
			return fmt.Errorf("finalize artifact metadata: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return errors.New("artifact metadata was changed during publication")
		}
		return nil
	}); err != nil {
		return ArtifactRecord{}, fmt.Errorf("finalize artifact publication: %w", err)
	}
	metadataCreated = false
	record.State = artifactStateReady
	record.persisted = true
	return record, nil
}

func (s *ArtifactStore) Read(ctx context.Context, id string) ([]byte, error) {
	barrier, err := s.acquireOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer s.releaseOperation(barrier)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validJournalUUID(id) {
		return nil, errors.New("artifact ID is invalid")
	}
	var record ArtifactRecord
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&record).Error; err != nil {
		return nil, fmt.Errorf("load artifact metadata: %w", err)
	}
	if record.State != artifactStateReady || record.DeletedAt != nil {
		return nil, errors.New("artifact is unavailable")
	}
	if err := validateArtifactRecord(record); err != nil {
		return nil, err
	}
	encoded, err := s.readArtifactFile(record)
	if err != nil {
		return nil, err
	}
	return decryptArtifactFile(encoded, record, s.keys)
}

func (s *ArtifactStore) readArtifactFile(record ArtifactRecord) ([]byte, error) {
	if err := validateArtifactRelativePath(record.RelativePath); err != nil {
		return nil, err
	}
	info, err := s.root.Lstat(record.RelativePath)
	if err != nil {
		return nil, fmt.Errorf("inspect artifact file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) || info.Size() != record.CiphertextSize {
		return nil, errors.New("artifact file metadata is invalid")
	}
	if record.CiphertextSize > int64(artifactHeaderSize)+int64(artifactMaxChunks)*(4+envelope.MaxEnvelopeSize) {
		return nil, errors.New("artifact ciphertext size is too large")
	}
	file, err := s.root.OpenFile(record.RelativePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open artifact file: %w", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat artifact file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) || info.Size() != record.CiphertextSize {
		return nil, errors.New("artifact file metadata changed")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, record.CiphertextSize+1))
	if err != nil {
		return nil, fmt.Errorf("read artifact file: %w", err)
	}
	if int64(len(encoded)) != record.CiphertextSize {
		return nil, errors.New("artifact file size changed")
	}
	digest := sha256.Sum256(encoded)
	if len(record.CiphertextSHA256) != sha256.Size || subtle.ConstantTimeCompare(digest[:], record.CiphertextSHA256) != 1 {
		return nil, errors.New("artifact ciphertext digest mismatch")
	}
	return encoded, nil
}

// MarkDeleting claims a bounded set of artifacts before filesystem I/O.
func (s *ArtifactStore) MarkDeleting(ctx context.Context, ids []string) ([]ArtifactRecord, error) {
	barrier, err := s.acquireOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer s.releaseOperation(barrier)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > artifactMaxChunks*artifactMaxChunks {
		return nil, errors.New("artifact delete batch is invalid")
	}
	var records []ArtifactRecord
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id IN ?", ids).Find(&records).Error; err != nil {
			return fmt.Errorf("load artifact delete batch: %w", err)
		}
		if len(records) == 0 {
			return nil
		}
		result := tx.Model(&ArtifactRecord{}).Where("id IN ? AND state = ?", ids, artifactStateReady).Updates(map[string]any{"state": artifactStateDeleting})
		if result.Error != nil {
			return fmt.Errorf("mark artifacts deleting: %w", result.Error)
		}
		for index := range records {
			if records[index].State == artifactStateReady {
				records[index].State = artifactStateDeleting
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return records, nil
}

// RemoveMarked deletes ciphertext first and finalizes the DB rows afterward.
func (s *ArtifactStore) RemoveMarked(ctx context.Context, records []ArtifactRecord) error {
	barrier, err := s.acquireOperation(ctx)
	if err != nil {
		return err
	}
	defer s.releaseOperation(barrier)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.State != artifactStateDeleting {
			continue
		}
		if err := s.removeArtifactFile(record.RelativePath); err != nil {
			return fmt.Errorf("remove artifact %q: %w", record.ID, err)
		}
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			result := tx.Where("id = ? AND state = ?", record.ID, artifactStateDeleting).Delete(&ArtifactRecord{})
			if result.Error != nil {
				return fmt.Errorf("delete artifact metadata %q: %w", record.ID, result.Error)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func validateArtifactOwner(owner ArtifactOwner) error {
	if strings.TrimSpace(owner.RequestID) == "" || strings.TrimSpace(owner.ConversationID) == "" {
		return errors.New("artifact owner is incomplete")
	}
	if len(owner.RequestID) > artifactMaxOwnerFieldSize || len(owner.ConversationID) > artifactMaxOwnerFieldSize || len(owner.APIKeyID) > artifactMaxOwnerFieldSize {
		return errors.New("artifact owner is too large")
	}
	return nil
}

func validateArtifactRecord(record ArtifactRecord) error {
	if !validJournalUUID(record.ID) || record.ResultIndex < 0 || record.PlaintextSize <= 0 || record.PlaintextSize > artifactMaxPlaintextSize || record.CiphertextSize <= artifactHeaderSize || len(record.CiphertextSHA256) != sha256.Size || record.KeyVersion == 0 || record.State != artifactStateReady {
		return errors.New("artifact metadata is invalid")
	}
	if record.RelativePath != record.ID+".bin" {
		return errors.New("artifact path metadata is invalid")
	}
	if err := validateArtifactOwner(ArtifactOwner{RequestID: record.RequestID, ConversationID: record.ConversationID, APIKeyID: record.APIKeyID}); err != nil {
		return err
	}
	if record.MIME != "image/png" && record.MIME != "image/jpeg" && record.MIME != "image/webp" {
		return errors.New("artifact MIME is invalid")
	}
	return nil
}

func prepareArtifactRoot(rootPath string) (*os.Root, error) {
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || rootPath == string(filepath.Separator) {
		return nil, errors.New("artifact root must be an absolute non-root clean path")
	}
	info, err := os.Lstat(rootPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect artifact root: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(rootPath), 0o700); err != nil {
			return nil, fmt.Errorf("create artifact root parent: %w", err)
		}
		if err := os.Mkdir(rootPath, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create artifact root: %w", err)
		}
		info, err = os.Lstat(rootPath)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect artifact root: %w", err)
	}
	if err := validateArtifactRootInfo(info); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open artifact root: %w", err)
	}
	rootInfo, err := root.Lstat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("verify artifact root descriptor: %w", err)
	}
	if err := validateArtifactRootInfo(rootInfo); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := ensureArtifactSentinel(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func validateArtifactRootInfo(info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("artifact root is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Getuid()) {
		return errors.New("artifact root is not owned by the current user")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o700 != 0o700 {
		return errors.New("artifact root permissions are not private")
	}
	return nil
}

func ensureArtifactSentinel(root *os.Root) error {
	info, err := root.Lstat(artifactRootSentinel)
	if errors.Is(err, os.ErrNotExist) {
		directory, openErr := root.Open(".")
		if openErr != nil {
			return fmt.Errorf("inspect artifact root contents: %w", openErr)
		}
		entries, readErr := directory.ReadDir(-1)
		closeErr := directory.Close()
		if readErr != nil {
			return fmt.Errorf("read artifact root contents: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close artifact root contents: %w", closeErr)
		}
		if len(entries) != 0 {
			return errors.New("artifact root is not empty for ownership adoption")
		}
		file, createErr := root.OpenFile(artifactRootSentinel, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, artifactSentinelMode)
		if createErr != nil {
			return fmt.Errorf("create artifact ownership sentinel: %w", createErr)
		}
		if err := writeArtifactBytes(file, []byte("codex-sub-proxy artifact root v1\n")); err != nil {
			_ = file.Close()
			_ = root.Remove(artifactRootSentinel)
			return fmt.Errorf("write artifact ownership sentinel: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = root.Remove(artifactRootSentinel)
			return fmt.Errorf("sync artifact ownership sentinel: %w", err)
		}
		if err := file.Close(); err != nil {
			_ = root.Remove(artifactRootSentinel)
			return fmt.Errorf("close artifact ownership sentinel: %w", err)
		}
		if err := syncArtifactRoot(root); err != nil {
			_ = root.Remove(artifactRootSentinel)
			return err
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect artifact ownership sentinel: %w", err)
	}
	if err := validateArtifactSentinelInfo(info); err != nil {
		return err
	}
	file, err := root.OpenFile(artifactRootSentinel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open artifact ownership sentinel: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return fmt.Errorf("read artifact ownership sentinel: %w", err)
	}
	if string(data) != "codex-sub-proxy artifact root v1\n" {
		return errors.New("artifact ownership sentinel is invalid")
	}
	return nil
}

func validateArtifactSentinelInfo(info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) || info.Mode().Perm() != artifactSentinelMode {
		return errors.New("artifact ownership sentinel is not private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Getuid()) {
		return errors.New("artifact ownership sentinel is not owned by the current user")
	}
	return nil
}

func syncArtifactRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open artifact root for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync artifact root: %w", err)
	}
	return nil
}

func validateArtifactRelativePath(relative string) error {
	if relative == "" || relative == artifactRootSentinel || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || filepath.Base(relative) != relative || strings.ContainsRune(relative, filepath.Separator) {
		return errors.New("artifact path is invalid")
	}
	return nil
}

func artifactHasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func (s *ArtifactStore) removeArtifactFile(relative string) error {
	if err := validateArtifactRelativePath(relative); err != nil {
		return err
	}
	info, err := s.root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect artifact file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) {
		return errors.New("artifact file is not a private regular file")
	}
	if err := s.root.Remove(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unlink artifact file: %w", err)
	}
	return nil
}

func checkArtifactOwnerTx(tx *gorm.DB, owner ArtifactOwner) error {
	var request RequestRecord
	if err := tx.Where("request_id = ?", owner.RequestID).First(&request).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("artifact owner request is missing")
		}
		return fmt.Errorf("load artifact owner request: %w", err)
	}
	if request.ConversationID != owner.ConversationID || request.APIKeyID != owner.APIKeyID {
		return errors.New("artifact owner request does not match")
	}
	if request.DeletingAt != nil {
		return errors.New("artifact owner request is deleting")
	}
	if request.TerminalAt != nil {
		return errors.New("artifact owner request is terminal")
	}
	var conversation ConversationRecord
	if err := tx.Where("id = ?", owner.ConversationID).First(&conversation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("artifact owner conversation is missing")
		}
		return fmt.Errorf("load artifact owner conversation: %w", err)
	}
	if conversation.DeletingAt != nil {
		return errors.New("artifact owner conversation is deleting")
	}
	return nil
}

func (s *ArtifactStore) checkArtifactOwner(ctx context.Context, owner ArtifactOwner) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return checkArtifactOwnerTx(tx, owner)
	})
}

// Reconcile removes only recognized crash remnants and repairs durable phases.
func (s *ArtifactStore) Reconcile(ctx context.Context) error {
	barrier, err := s.acquireOperation(ctx)
	if err != nil {
		return err
	}
	defer s.releaseOperation(barrier)
	return s.reconcileLocked(ctx)
}

func (s *ArtifactStore) reconcileWithBarrier(ctx context.Context, barrier *ArtifactBarrier) error {
	if s == nil {
		return errors.New("artifact store is closed")
	}
	if barrier == nil {
		return errors.New("artifact barrier is nil")
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.root == nil {
		return errors.New("artifact store is closed")
	}
	return s.reconcileBody(ctx)
}

func (s *ArtifactStore) reconcileLocked(ctx context.Context) error {
	return s.reconcileBody(ctx)
}

func (s *ArtifactStore) reconcileBody(ctx context.Context) error {
	if ctx == nil {
		return errors.New("artifact reconciliation context is nil")
	}
	if err := ensureArtifactSentinel(s.root); err != nil {
		return err
	}
	var errs []error
	removed := false
	directory, err := s.root.Open(".")
	if err != nil {
		return fmt.Errorf("open artifact root for reconciliation: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = directory.Close()
			return err
		}
		entries, readErr := directory.ReadDir(artifactReconcileBatch)
		for _, entry := range entries {
			name := entry.Name()
			if name == artifactRootSentinel {
				continue
			}
			kind, id := artifactFileKind(name)
			if kind == "" {
				errs = append(errs, fmt.Errorf("unrecognized artifact root entry %q", name))
				continue
			}
			info, infoErr := s.root.Lstat(name)
			if infoErr != nil {
				if errors.Is(infoErr, os.ErrNotExist) {
					continue
				}
				errs = append(errs, fmt.Errorf("inspect artifact root entry %q: %w", name, infoErr))
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !artifactHasSingleLink(info) {
				errs = append(errs, fmt.Errorf("artifact root entry %q is not a private regular file", name))
				continue
			}
			if kind == "temp" {
				if err := s.removeArtifactFile(name); err != nil {
					errs = append(errs, fmt.Errorf("remove stale artifact temporary file %q: %w", name, err))
				} else {
					removed = true
				}
				continue
			}
			var record ArtifactRecord
			recordErr := s.db.WithContext(ctx).Where("id = ? AND relative_path = ?", id, name).First(&record).Error
			if errors.Is(recordErr, gorm.ErrRecordNotFound) {
				recognized, shapeErr := s.recognizedCiphertext(name, info)
				if shapeErr != nil {
					errs = append(errs, shapeErr)
				} else if !recognized {
					errs = append(errs, fmt.Errorf("unrecognized artifact ciphertext %q", name))
				} else if err := s.removeArtifactFile(name); err != nil {
					errs = append(errs, fmt.Errorf("remove orphan artifact %q: %w", name, err))
				} else {
					removed = true
				}
				continue
			}
			if recordErr != nil {
				errs = append(errs, fmt.Errorf("load artifact reconciliation record %q: %w", name, recordErr))
				continue
			}
			switch record.State {
			case artifactStateWriting:
				ready := record
				ready.State = artifactStateReady
				encoded, readFileErr := s.readArtifactFile(ready)
				if errors.Is(readFileErr, os.ErrNotExist) {
					if err := s.db.WithContext(ctx).Delete(&record).Error; err != nil {
						errs = append(errs, fmt.Errorf("remove missing writing artifact %q: %w", record.ID, err))
					}
				} else if readFileErr != nil {
					errs = append(errs, fmt.Errorf("verify writing artifact %q: %w", record.ID, readFileErr))
				} else if _, decryptErr := decryptArtifactFile(encoded, ready, s.keys); decryptErr != nil {
					errs = append(errs, fmt.Errorf("verify writing artifact %q: %w", record.ID, decryptErr))
				} else if err := s.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("id = ? AND state = ?", record.ID, artifactStateWriting).Update("state", artifactStateReady).Error; err != nil {
					errs = append(errs, fmt.Errorf("finalize writing artifact %q: %w", record.ID, err))
				}
			case artifactStateReady:
				if _, readFileErr := s.readArtifactFile(record); errors.Is(readFileErr, os.ErrNotExist) {
					if err := s.db.WithContext(ctx).Delete(&record).Error; err != nil {
						errs = append(errs, fmt.Errorf("remove missing artifact %q: %w", record.ID, err))
					}
				} else if readFileErr != nil {
					errs = append(errs, fmt.Errorf("verify artifact %q: %w", record.ID, readFileErr))
				}
			case artifactStateDeleting:
				if err := s.removeArtifactFile(name); err != nil {
					errs = append(errs, fmt.Errorf("remove deleting artifact %q: %w", record.ID, err))
				} else if err := s.db.WithContext(ctx).Delete(&record).Error; err != nil {
					errs = append(errs, fmt.Errorf("remove deleting artifact metadata %q: %w", record.ID, err))
				} else {
					removed = true
				}
			default:
				errs = append(errs, fmt.Errorf("artifact %q has unknown state %q", record.ID, record.State))
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				errs = append(errs, fmt.Errorf("read artifact root: %w", readErr))
			}
			break
		}
		if len(entries) == 0 {
			break
		}
	}
	if err := directory.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close artifact root reconciliation: %w", err))
	}
	lastID := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var records []ArtifactRecord
		query := s.db.WithContext(ctx).Where("state IN ? AND id > ?", []string{artifactStateWriting, artifactStateReady, artifactStateDeleting}, lastID).Order("id ASC").Limit(artifactReconcileBatch)
		if err := query.Find(&records).Error; err != nil {
			errs = append(errs, fmt.Errorf("load artifact reconciliation metadata: %w", err))
			break
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			lastID = record.ID
			if err := validateArtifactRelativePath(record.RelativePath); err != nil {
				errs = append(errs, fmt.Errorf("artifact %q path is invalid: %w", record.ID, err))
				continue
			}
			if _, err := s.root.Lstat(record.RelativePath); errors.Is(err, os.ErrNotExist) {
				if err := s.db.WithContext(ctx).Delete(&record).Error; err != nil {
					errs = append(errs, fmt.Errorf("remove missing artifact metadata %q: %w", record.ID, err))
				}
			} else if err != nil {
				errs = append(errs, fmt.Errorf("inspect artifact metadata path %q: %w", record.ID, err))
			}
		}
	}
	if removed {
		if err := syncArtifactRoot(s.root); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func artifactFileKind(name string) (string, string) {
	switch {
	case strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp"):
		id := strings.TrimSuffix(strings.TrimPrefix(name, "."), ".tmp")
		if validJournalUUID(id) {
			return "temp", id
		}
	case strings.HasSuffix(name, ".bin"):
		id := strings.TrimSuffix(name, ".bin")
		if validJournalUUID(id) {
			return "final", id
		}
	}
	return "", ""
}

func (s *ArtifactStore) recognizedCiphertext(name string, info os.FileInfo) (bool, error) {
	if info.Size() < artifactHeaderSize || info.Size() > int64(artifactHeaderSize)+int64(artifactMaxChunks)*(4+envelope.MaxEnvelopeSize) {
		return false, fmt.Errorf("artifact ciphertext %q has an invalid size", name)
	}
	file, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, fmt.Errorf("open artifact ciphertext %q: %w", name, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, info.Size()+1))
	if err != nil {
		return false, fmt.Errorf("read artifact ciphertext %q: %w", name, err)
	}
	return validArtifactCiphertextShape(data), nil
}

func validArtifactCiphertextShape(data []byte) bool {
	if len(data) < artifactHeaderSize || !sameArtifactMagic(data[:4], artifactMagic[:]) || data[4] != artifactFormatVersion {
		return false
	}
	count := int(binary.BigEndian.Uint32(data[5:9]))
	if count <= 0 || count > artifactMaxChunks {
		return false
	}
	offset := artifactHeaderSize
	for range count {
		if len(data)-offset < 4 {
			return false
		}
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if length <= 0 || length > envelope.MaxEnvelopeSize || length > len(data)-offset {
			return false
		}
		offset += length
	}
	return offset == len(data)
}

func writeArtifactFile(file *os.File, chunks [][]byte) error {
	var header [artifactHeaderSize]byte
	copy(header[:4], artifactMagic[:])
	header[4] = artifactFormatVersion
	binary.BigEndian.PutUint32(header[5:], uint32(len(chunks)))
	if err := writeArtifactBytes(file, header[:]); err != nil {
		return fmt.Errorf("write artifact header: %w", err)
	}
	for index, chunk := range chunks {
		if len(chunk) == 0 || len(chunk) > envelope.MaxEnvelopeSize {
			return fmt.Errorf("artifact chunk %d size is invalid", index)
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(chunk)))
		if err := writeArtifactBytes(file, length[:]); err != nil {
			return fmt.Errorf("write artifact chunk length: %w", err)
		}
		if err := writeArtifactBytes(file, chunk); err != nil {
			return fmt.Errorf("write artifact chunk: %w", err)
		}
	}
	return nil
}

func writeArtifactBytes(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func encryptArtifactChunks(owner ArtifactOwner, artifactID, mimeType string, plaintext []byte, keys envelope.KeySet) ([][]byte, error) {
	overhead, err := encodeArtifactChunk(owner, artifactID, mimeType, 0, 1, nil)
	if err != nil {
		return nil, err
	}
	maxChunkData := envelope.MaxPlaintextSize - len(overhead)
	if maxChunkData <= 0 {
		return nil, errors.New("artifact chunk metadata is too large")
	}
	count := (len(plaintext) + maxChunkData - 1) / maxChunkData
	if count == 0 || count > artifactMaxChunks {
		return nil, errors.New("artifact chunk count is invalid")
	}
	chunks := make([][]byte, 0, count)
	for index, offset := 0, 0; index < count; index++ {
		end := offset + maxChunkData
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunkPlain, err := encodeArtifactChunk(owner, artifactID, mimeType, index, count, plaintext[offset:end])
		if err != nil {
			return nil, fmt.Errorf("encode artifact chunk %d: %w", index, err)
		}
		encrypted, err := envelope.Encrypt(chunkPlain, envelope.PayloadDomain, keys)
		if err != nil {
			return nil, fmt.Errorf("encrypt artifact chunk %d: %w", index, err)
		}
		chunks = append(chunks, encrypted)
		offset = end
	}
	return chunks, nil
}

func encodeArtifactChunk(owner ArtifactOwner, artifactID, mimeType string, index, total int, data []byte) ([]byte, error) {
	if index < 0 || total <= 0 || index >= total || len(data) > envelope.MaxPlaintextSize {
		return nil, errors.New("artifact chunk metadata is invalid")
	}
	fields := []string{artifactID, mimeType, owner.RequestID, owner.ConversationID, owner.APIKeyID}
	for _, field := range fields {
		if len(field) > int(^uint16(0)) {
			return nil, errors.New("artifact chunk metadata is too large")
		}
	}
	length := 4 + 1 + 4 + 4 + 2 + len(artifactID) + 2 + len(mimeType) + 2 + len(owner.RequestID) + 2 + len(owner.ConversationID) + 2 + len(owner.APIKeyID) + 4 + len(data)
	if length > envelope.MaxPlaintextSize {
		return nil, errors.New("artifact chunk is too large")
	}
	encoded := make([]byte, length)
	copy(encoded[:4], artifactChunkMagic[:])
	encoded[4] = artifactChunkFormatVersion
	binary.BigEndian.PutUint32(encoded[5:9], uint32(index))
	binary.BigEndian.PutUint32(encoded[9:13], uint32(total))
	offset := 13
	for _, field := range fields {
		binary.BigEndian.PutUint16(encoded[offset:offset+2], uint16(len(field)))
		offset += 2
		copy(encoded[offset:], field)
		offset += len(field)
	}
	binary.BigEndian.PutUint32(encoded[offset:offset+4], uint32(len(data)))
	offset += 4
	copy(encoded[offset:], data)
	return encoded, nil
}

func decryptArtifactFile(encoded []byte, record ArtifactRecord, keys envelope.KeySet) ([]byte, error) {
	if len(encoded) < artifactHeaderSize || !sameArtifactMagic(encoded[:4], artifactMagic[:]) || encoded[4] != artifactFormatVersion {
		return nil, errors.New("artifact header is invalid")
	}
	count := binary.BigEndian.Uint32(encoded[5:9])
	if count == 0 || count > artifactMaxChunks {
		return nil, errors.New("artifact chunk count is invalid")
	}
	output := make([]byte, 0, record.PlaintextSize)
	offset := artifactHeaderSize
	for index := uint32(0); index < count; index++ {
		if len(encoded)-offset < 4 {
			return nil, errors.New("artifact chunk length is truncated")
		}
		chunkLength := binary.BigEndian.Uint32(encoded[offset : offset+4])
		offset += 4
		if chunkLength == 0 || chunkLength > envelope.MaxEnvelopeSize || uint64(chunkLength) > uint64(len(encoded)-offset) {
			return nil, errors.New("artifact chunk length is invalid")
		}
		chunk := encoded[offset : offset+int(chunkLength)]
		offset += int(chunkLength)
		if len(chunk) < 9 || binary.BigEndian.Uint32(chunk[5:9]) != record.KeyVersion {
			return nil, errors.New("artifact chunk key version is invalid")
		}
		plain, err := envelope.Decrypt(chunk, envelope.PayloadDomain, keys)
		if err != nil {
			return nil, fmt.Errorf("decrypt artifact chunk %d: %w", index, err)
		}
		data, err := decodeArtifactChunk(plain, record, int(index), int(count))
		if err != nil {
			return nil, fmt.Errorf("decode artifact chunk %d: %w", index, err)
		}
		if len(data) > artifactMaxPlaintextSize-len(output) {
			return nil, errors.New("artifact plaintext size is too large")
		}
		output = append(output, data...)
	}
	if offset != len(encoded) || int64(len(output)) != record.PlaintextSize {
		return nil, errors.New("artifact plaintext size is invalid")
	}
	return output, nil
}

func decodeArtifactChunk(plain []byte, record ArtifactRecord, expectedIndex, expectedTotal int) ([]byte, error) {
	if len(plain) < 13 || !sameArtifactMagic(plain[:4], artifactChunkMagic[:]) || plain[4] != artifactChunkFormatVersion || int(binary.BigEndian.Uint32(plain[5:9])) != expectedIndex || int(binary.BigEndian.Uint32(plain[9:13])) != expectedTotal {
		return nil, errors.New("artifact chunk metadata is invalid")
	}
	offset := 13
	fields := make([]string, 0, 5)
	for range 5 {
		if len(plain)-offset < 2 {
			return nil, errors.New("artifact chunk metadata is truncated")
		}
		length := int(binary.BigEndian.Uint16(plain[offset : offset+2]))
		offset += 2
		if length > len(plain)-offset {
			return nil, errors.New("artifact chunk metadata length is invalid")
		}
		fields = append(fields, string(plain[offset:offset+length]))
		offset += length
	}
	if fields[0] != record.ID || fields[1] != record.MIME || fields[2] != record.RequestID || fields[3] != record.ConversationID || fields[4] != record.APIKeyID {
		return nil, errors.New("artifact chunk owner metadata conflicts")
	}
	if len(plain)-offset < 4 {
		return nil, errors.New("artifact chunk data length is truncated")
	}
	dataLength := int(binary.BigEndian.Uint32(plain[offset : offset+4]))
	offset += 4
	if dataLength != len(plain)-offset {
		return nil, errors.New("artifact chunk data length is invalid")
	}
	return plain[offset:], nil
}

func sameArtifactMagic(got, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	var difference byte
	for index := range got {
		difference |= got[index] ^ want[index]
	}
	return difference == 0
}

func sha256ArtifactFile(chunks [][]byte) [sha256.Size]byte {
	digest := sha256.New()
	var header [artifactHeaderSize]byte
	copy(header[:4], artifactMagic[:])
	header[4] = artifactFormatVersion
	binary.BigEndian.PutUint32(header[5:], uint32(len(chunks)))
	_, _ = digest.Write(header[:])
	for _, chunk := range chunks {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(chunk)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(chunk)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}
func artifactImageMIME(data []byte) (string, bool) {
	var actual string
	switch {
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		actual = "image/png"
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		actual = "image/jpeg"
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		actual = "image/webp"
	default:
		return "", false
	}
	detected := strings.ToLower(strings.Split(http.DetectContentType(data), ";")[0])
	if detected != actual {
		return "", false
	}
	return actual, true
}
