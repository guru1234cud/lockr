package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

const challengeLen = 32
const challengeTTL = 60 * time.Second

type ServiceRecord struct {
	Name      string `json:"name"`
	PublicKey []byte `json:"public_key"`
	Policy    string `json:"policy"`
}

type pendingChallenge struct {
	challenge []byte
	service   string
	expiresAt time.Time
}

type Ed25519Auth struct {
	db         *storage.DB
	mu         sync.Mutex
	challenges map[string]*pendingChallenge // keyed by challenge hex
}

func NewEd25519Auth(db *storage.DB) *Ed25519Auth {
	return &Ed25519Auth{
		db:         db,
		challenges: make(map[string]*pendingChallenge),
	}
}

// GenerateChallenge returns a 32-byte random challenge for the named service.
func (a *Ed25519Auth) GenerateChallenge(serviceName string) ([]byte, error) {
	if _, err := a.GetService(serviceName); err != nil {
		return nil, fmt.Errorf("unknown service %q", serviceName)
	}

	challenge := make([]byte, challengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%x", challenge)
	a.mu.Lock()
	a.challenges[key] = &pendingChallenge{
		challenge: challenge,
		service:   serviceName,
		expiresAt: time.Now().Add(challengeTTL),
	}
	a.mu.Unlock()

	// Prune expired challenges opportunistically.
	go a.pruneExpired()

	return challenge, nil
}

// Verify checks the signed challenge and returns the service record on success.
func (a *Ed25519Auth) Verify(challenge, signature []byte) (*ServiceRecord, error) {
	key := fmt.Sprintf("%x", challenge)

	a.mu.Lock()
	pc, ok := a.challenges[key]
	if ok {
		delete(a.challenges, key) // one-time use
	}
	a.mu.Unlock()

	if !ok {
		return nil, errors.New("challenge not found or already used")
	}
	if time.Now().After(pc.expiresAt) {
		return nil, errors.New("challenge expired")
	}

	// Constant-time challenge comparison.
	if subtle.ConstantTimeCompare(pc.challenge, challenge) != 1 {
		return nil, errors.New("challenge mismatch")
	}

	svc, err := a.GetService(pc.service)
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(ed25519.PublicKey(svc.PublicKey), challenge, signature) {
		return nil, errors.New("invalid signature")
	}
	return svc, nil
}

// RegisterService stores the service's public key and policy.
func (a *Ed25519Auth) RegisterService(rec ServiceRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.db.Set("auth/services/"+rec.Name, data)
}

// GetService retrieves a service record by name.
func (a *Ed25519Auth) GetService(name string) (*ServiceRecord, error) {
	data, err := a.db.Get("auth/services/" + name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("service %q not found", name)
		}
		return nil, err
	}
	var rec ServiceRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// DeleteService removes a service (revokes access immediately).
func (a *Ed25519Auth) DeleteService(name string) error {
	return a.db.Delete("auth/services/" + name)
}

func (a *Ed25519Auth) pruneExpired() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, pc := range a.challenges {
		if now.After(pc.expiresAt) {
			delete(a.challenges, k)
		}
	}
}
