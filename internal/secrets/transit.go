package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

type TransitKeyVersion struct {
	Version   int       `json:"version"`
	Key       []byte    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

type TransitKeyMeta struct {
	Name           string              `json:"name"`
	CurrentVersion int                 `json:"current_version"`
	Versions       []TransitKeyVersion `json:"versions"`
}

type TransitStore struct {
	db     *storage.DB
	crypto *storage.Crypto
}

func NewTransitStore(db *storage.DB, crypto *storage.Crypto) *TransitStore {
	return &TransitStore{db: db, crypto: crypto}
}

// CreateKey creates a new named transit key with version 1.
func (s *TransitStore) CreateKey(name string) error {
	_, err := s.loadMeta(name)
	if err == nil {
		return fmt.Errorf("transit key %q already exists", name)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	meta := &TransitKeyMeta{
		Name:           name,
		CurrentVersion: 1,
		Versions: []TransitKeyVersion{
			{Version: 1, Key: key, CreatedAt: time.Now().UTC()},
		},
	}
	return s.saveMeta(meta)
}

// Rotate creates a new key version; old versions are retained for decryption.
func (s *TransitStore) Rotate(name string) error {
	meta, err := s.loadMeta(name)
	if err != nil {
		return err
	}
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return err
	}
	meta.CurrentVersion++
	meta.Versions = append(meta.Versions, TransitKeyVersion{
		Version:   meta.CurrentVersion,
		Key:       newKey,
		CreatedAt: time.Now().UTC(),
	})
	return s.saveMeta(meta)
}

// Encrypt encrypts plaintext and returns a versioned ciphertext string.
// Format: vault:vN:<base64(nonce||ciphertext)>
func (s *TransitStore) Encrypt(name string, plaintext []byte) (string, error) {
	meta, err := s.loadMeta(name)
	if err != nil {
		return "", err
	}
	kv := meta.currentKeyVersion()
	ct, err := aesgcmEncryptBytes(kv.Key, plaintext)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(ct)
	return fmt.Sprintf("vault:v%d:%s", kv.Version, encoded), nil
}

// Decrypt decrypts a versioned ciphertext string.
func (s *TransitStore) Decrypt(name, ciphertext string) ([]byte, error) {
	version, encoded, err := parseVaultCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	meta, err := s.loadMeta(name)
	if err != nil {
		return nil, err
	}
	kv := meta.keyVersion(version)
	if kv == nil {
		return nil, fmt.Errorf("key version %d not found for %q", version, name)
	}
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}
	return aesgcmDecryptBytes(kv.Key, ct)
}

// Info returns key metadata (no key material).
func (s *TransitStore) Info(name string) (*TransitKeyMeta, error) {
	meta, err := s.loadMeta(name)
	if err != nil {
		return nil, err
	}
	// Strip key material from response.
	safe := &TransitKeyMeta{
		Name:           meta.Name,
		CurrentVersion: meta.CurrentVersion,
	}
	for _, v := range meta.Versions {
		safe.Versions = append(safe.Versions, TransitKeyVersion{
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
		})
	}
	return safe, nil
}

func (m *TransitKeyMeta) currentKeyVersion() *TransitKeyVersion {
	return m.keyVersion(m.CurrentVersion)
}

func (m *TransitKeyMeta) keyVersion(v int) *TransitKeyVersion {
	for i := range m.Versions {
		if m.Versions[i].Version == v {
			return &m.Versions[i]
		}
	}
	return nil
}

func (s *TransitStore) loadMeta(name string) (*TransitKeyMeta, error) {
	storageKey := "secrets/transit/" + name
	data, err := s.db.Get(storageKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("transit key %q not found", name)
		}
		return nil, err
	}
	plain, err := s.crypto.Decrypt(storageKey, data)
	if err != nil {
		return nil, err
	}
	var meta TransitKeyMeta
	return &meta, json.Unmarshal(plain, &meta)
}

func (s *TransitStore) saveMeta(meta *TransitKeyMeta) error {
	storageKey := "secrets/transit/" + meta.Name
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	enc, err := s.crypto.Encrypt(storageKey, data)
	if err != nil {
		return err
	}
	return s.db.Set(storageKey, enc)
}

func parseVaultCiphertext(ct string) (version int, encoded string, err error) {
	parts := strings.SplitN(ct, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return 0, "", errors.New("invalid ciphertext format, expected vault:vN:<data>")
	}
	_, err = fmt.Sscanf(parts[1], "v%d", &version)
	if err != nil {
		return 0, "", fmt.Errorf("invalid version %q: %w", parts[1], err)
	}
	return version, parts[2], nil
}

func aesgcmEncryptBytes(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, len(nonce)+len(ct))
	copy(out, nonce)
	copy(out[len(nonce):], ct)
	return out, nil
}

func aesgcmDecryptBytes(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	ct := data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
