package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	masterKeyLen = 32
	saltLen      = 32
	nonceLen     = 12

	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
)

// masterKeyFile is the on-disk format for the encrypted master key.
type masterKeyFile struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Crypto holds the decrypted master key and provides encryption operations.
type Crypto struct {
	masterKey []byte
}

// NewCrypto creates a Crypto from an already-decrypted master key.
func NewCrypto(masterKey []byte) *Crypto {
	return &Crypto{masterKey: masterKey}
}

// GenerateMasterKey generates a new random 256-bit master key.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, masterKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	return key, nil
}

// SaveMasterKey encrypts masterKey with passphrase and writes it to path.
func SaveMasterKey(path string, masterKey []byte, passphrase []byte) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	derived := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, masterKeyLen)
	defer zeroBytes(derived)

	ciphertext, nonce, err := aesgcmEncrypt(derived, masterKey)
	if err != nil {
		return fmt.Errorf("encrypt master key: %w", err)
	}

	data, err := json.Marshal(masterKeyFile{Salt: salt, Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadMasterKey decrypts the master key file at path using passphrase.
func LoadMasterKey(path string, passphrase []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read master key file: %w", err)
	}

	var mkf masterKeyFile
	if err := json.Unmarshal(data, &mkf); err != nil {
		return nil, fmt.Errorf("parse master key file: %w", err)
	}

	derived := argon2.IDKey(passphrase, mkf.Salt, argon2Time, argon2Memory, argon2Threads, masterKeyLen)
	defer zeroBytes(derived)

	masterKey, err := aesgcmDecrypt(derived, mkf.Ciphertext, mkf.Nonce)
	if err != nil {
		return nil, errors.New("incorrect passphrase or corrupted master key file")
	}
	return masterKey, nil
}

// DeriveKey derives a per-path AES-256 key from the master key using HKDF-SHA256.
func (c *Crypto) DeriveKey(path string) ([]byte, error) {
	r := hkdf.New(sha256.New, c.masterKey, nil, []byte(path))
	key := make([]byte, masterKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf derive key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using a key derived from path.
func (c *Crypto) Encrypt(path string, plaintext []byte) ([]byte, error) {
	key, err := c.DeriveKey(path)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)

	ciphertext, nonce, err := aesgcmEncrypt(key, plaintext)
	if err != nil {
		return nil, err
	}

	// Format: nonce || ciphertext
	out := make([]byte, nonceLen+len(ciphertext))
	copy(out[:nonceLen], nonce)
	copy(out[nonceLen:], ciphertext)
	return out, nil
}

// Decrypt decrypts data (nonce || ciphertext) using a key derived from path.
func (c *Crypto) Decrypt(path string, data []byte) ([]byte, error) {
	if len(data) < nonceLen {
		return nil, errors.New("ciphertext too short")
	}
	key, err := c.DeriveKey(path)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)

	nonce := data[:nonceLen]
	ciphertext := data[nonceLen:]
	return aesgcmDecrypt(key, ciphertext, nonce)
}

// HashArgon2id returns the Argon2id hash of a password with a random salt.
// Output format: salt || hash (both saltLen and masterKeyLen bytes).
func HashArgon2id(password []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hash := argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, masterKeyLen)
	out := make([]byte, saltLen+masterKeyLen)
	copy(out[:saltLen], salt)
	copy(out[saltLen:], hash)
	zeroBytes(hash)
	return out, nil
}

// VerifyArgon2id checks password against a stored hash (salt || hash).
func VerifyArgon2id(password, stored []byte) bool {
	if len(stored) < saltLen+masterKeyLen {
		return false
	}
	salt := stored[:saltLen]
	expected := stored[saltLen:]
	actual := argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, masterKeyLen)
	defer zeroBytes(actual)
	return subtle32Equal(actual, expected)
}

func aesgcmEncrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesgcmDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ZeroBytes zeroes a byte slice (exported for callers holding master key material).
func ZeroBytes(b []byte) { zeroBytes(b) }

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// subtle32Equal is a constant-time comparison that works for any length.
func subtle32Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
