package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

type TOTPRecord struct {
	Name   string `json:"name"`
	Secret []byte `json:"secret"` // raw bytes (stored base32 for display)
	Policy string `json:"policy"`
}

type TOTPAuth struct {
	db *storage.DB
}

func NewTOTPAuth(db *storage.DB) *TOTPAuth {
	return &TOTPAuth{db: db}
}

// GenerateSecret creates a new TOTP shared secret (20 random bytes, base32-encoded for display).
func GenerateSecret() (raw []byte, base32Str string, err error) {
	raw = make([]byte, 20)
	if _, err = rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generate totp secret: %w", err)
	}
	base32Str = base32.StdEncoding.EncodeToString(raw)
	return raw, base32Str, nil
}

// RegisterTOTP stores the TOTP record for a service.
func (a *TOTPAuth) RegisterTOTP(rec TOTPRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.db.Set("auth/services/totp/"+rec.Name, data)
}

// Verify checks a TOTP code (±1 window tolerance) for the named service.
func (a *TOTPAuth) Verify(serviceName string, code uint32) (*TOTPRecord, error) {
	data, err := a.db.Get("auth/services/totp/" + serviceName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("service %q not found", serviceName)
		}
		return nil, err
	}
	var rec TOTPRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	for delta := int64(-1); delta <= 1; delta++ {
		counter := uint64((now / 30) + delta)
		expected := hotp(rec.Secret, counter)
		if expected == code {
			return &rec, nil
		}
	}
	return nil, errors.New("invalid TOTP code")
}

func (a *TOTPAuth) GetTOTP(name string) (*TOTPRecord, error) {
	data, err := a.db.Get("auth/services/totp/" + name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("totp service %q not found", name)
		}
		return nil, err
	}
	var rec TOTPRecord
	return &rec, json.Unmarshal(data, &rec)
}

// hotp computes HMAC-SHA1-based OTP per RFC 4226.
func hotp(secret []byte, counter uint64) uint32 {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(msg)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := (uint32(h[offset])&0x7f)<<24 |
		uint32(h[offset+1])<<16 |
		uint32(h[offset+2])<<8 |
		uint32(h[offset+3])
	return code % uint32(math.Pow10(6))
}
