package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

const maxVersions = 10
const softDeleteTTL = 30 * 24 * time.Hour

type KVEntry struct {
	Path      string          `json:"path"`
	Version   int             `json:"version"`
	Value     json.RawMessage `json:"value"`
	CreatedAt time.Time       `json:"created_at"`
	DeletedAt *time.Time      `json:"deleted_at,omitempty"`
}

type KVMeta struct {
	Path           string     `json:"path"`
	CurrentVersion int        `json:"current_version"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

type KVStore struct {
	db     *storage.DB
	crypto *storage.Crypto
}

func NewKVStore(db *storage.DB, crypto *storage.Crypto) *KVStore {
	return &KVStore{db: db, crypto: crypto}
}

// Get retrieves the specified version of a secret (0 = latest).
func (s *KVStore) Get(path string, version int) (*KVEntry, error) {
	meta, err := s.getMeta(path)
	if err != nil {
		return nil, err
	}
	if meta.DeletedAt != nil {
		return nil, fmt.Errorf("secret %q has been deleted", path)
	}

	if version == 0 {
		version = meta.CurrentVersion
	}
	if version < 1 || version > meta.CurrentVersion {
		return nil, fmt.Errorf("version %d not found for %q", version, path)
	}

	return s.getVersion(path, version)
}

// Set writes a new version of the secret and prunes old versions.
func (s *KVStore) Set(path string, value json.RawMessage) (*KVEntry, error) {
	meta, err := s.getMeta(path)
	if errors.Is(err, storage.ErrNotFound) {
		meta = &KVMeta{Path: path, CurrentVersion: 0}
	} else if err != nil {
		return nil, err
	}

	// Undelete if previously deleted.
	meta.DeletedAt = nil
	meta.CurrentVersion++

	entry := &KVEntry{
		Path:      path,
		Version:   meta.CurrentVersion,
		Value:     value,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.writeVersion(entry); err != nil {
		return nil, err
	}
	if err := s.writeMeta(meta); err != nil {
		return nil, err
	}

	// Prune oldest version if we exceed maxVersions.
	if meta.CurrentVersion > maxVersions {
		oldest := meta.CurrentVersion - maxVersions
		_ = s.deleteVersion(path, oldest)
	}

	return entry, nil
}

// Delete soft-deletes a secret.
func (s *KVStore) Delete(path string) error {
	meta, err := s.getMeta(path)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	meta.DeletedAt = &now
	return s.writeMeta(meta)
}

// Versions returns all stored versions for a path.
func (s *KVStore) Versions(path string) ([]*KVEntry, error) {
	meta, err := s.getMeta(path)
	if err != nil {
		return nil, err
	}

	var versions []*KVEntry
	oldest := meta.CurrentVersion - maxVersions + 1
	if oldest < 1 {
		oldest = 1
	}
	for v := oldest; v <= meta.CurrentVersion; v++ {
		entry, err := s.getVersion(path, v)
		if err != nil {
			continue
		}
		// Omit secret value from version listing.
		entry.Value = nil
		versions = append(versions, entry)
	}
	return versions, nil
}

// Rollback promotes an old version as a new write, making it the current version.
func (s *KVStore) Rollback(path string, version int) (*KVEntry, error) {
	old, err := s.Get(path, version)
	if err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}
	return s.Set(path, old.Value)
}

// List returns direct children of a path prefix.
func (s *KVStore) List(prefix string) ([]string, error) {
	return s.db.ListDirect("secrets/kv/" + prefix)
}

func (s *KVStore) getMeta(path string) (*KVMeta, error) {
	data, err := s.db.Get("secrets/kv/" + path + "/__meta")
	if err != nil {
		return nil, err
	}
	plain, err := s.crypto.Decrypt("secrets/kv/"+path+"/__meta", data)
	if err != nil {
		return nil, err
	}
	var meta KVMeta
	return &meta, json.Unmarshal(plain, &meta)
}

func (s *KVStore) writeMeta(meta *KVMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	enc, err := s.crypto.Encrypt("secrets/kv/"+meta.Path+"/__meta", data)
	if err != nil {
		return err
	}
	return s.db.Set("secrets/kv/"+meta.Path+"/__meta", enc)
}

func (s *KVStore) getVersion(path string, version int) (*KVEntry, error) {
	key := fmt.Sprintf("secrets/kv/%s/v%d", path, version)
	data, err := s.db.Get(key)
	if err != nil {
		return nil, err
	}
	plain, err := s.crypto.Decrypt(key, data)
	if err != nil {
		return nil, err
	}
	var entry KVEntry
	return &entry, json.Unmarshal(plain, &entry)
}

func (s *KVStore) writeVersion(entry *KVEntry) error {
	key := fmt.Sprintf("secrets/kv/%s/v%d", entry.Path, entry.Version)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	enc, err := s.crypto.Encrypt(key, data)
	if err != nil {
		return err
	}
	return s.db.Set(key, enc)
}

func (s *KVStore) deleteVersion(path string, version int) error {
	key := fmt.Sprintf("secrets/kv/%s/v%d", path, version)
	return s.db.Delete(key)
}
