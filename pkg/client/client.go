// Package client provides a Go client for the Lockr secrets manager API.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Client authenticates with Lockr using Ed25519 challenge-response and
// provides typed methods for all secret operations.
type Client struct {
	addr      string
	privKey   ed25519.PrivateKey
	token     string
	http      *http.Client
}

// Options configures the Lockr client.
type Options struct {
	Addr       string // e.g. "https://lockr:8300"
	PrivKeyHex string // hex-encoded Ed25519 private key
	PrivKeyPath string // path to file containing hex-encoded private key
	CAPath     string // path to CA cert for TLS verification
	AdminToken string // admin token (alternative to Ed25519)
}

// New creates a new Lockr client. Call Authenticate before making requests.
func New(opts Options) (*Client, error) {
	tlsCfg, err := buildTLSConfig(opts.CAPath)
	if err != nil {
		return nil, err
	}

	c := &Client{
		addr: opts.Addr,
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   15 * time.Second,
		},
		token: opts.AdminToken,
	}

	if opts.PrivKeyPath != "" {
		data, err := os.ReadFile(opts.PrivKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		opts.PrivKeyHex = string(bytes.TrimSpace(data))
	}

	if opts.PrivKeyHex != "" {
		keyBytes, err := hex.DecodeString(opts.PrivKeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode private key: %w", err)
		}
		c.privKey = ed25519.PrivateKey(keyBytes)
	}

	return c, nil
}

// Authenticate performs Ed25519 challenge-response and stores the session token.
func (c *Client) Authenticate(ctx context.Context, serviceName string) error {
	if c.privKey == nil {
		return fmt.Errorf("no private key configured")
	}

	// Step 1: get challenge.
	var challengeResp struct {
		Data struct {
			Challenge string `json:"challenge"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/challenge",
		map[string]string{"service": serviceName}, &challengeResp); err != nil {
		return fmt.Errorf("get challenge: %w", err)
	}

	challengeBytes, err := hex.DecodeString(challengeResp.Data.Challenge)
	if err != nil {
		return fmt.Errorf("decode challenge: %w", err)
	}

	// Step 2: sign challenge.
	sig := ed25519.Sign(c.privKey, challengeBytes)

	// Step 3: verify + get token.
	var verifyResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/verify", map[string]string{
		"challenge": challengeResp.Data.Challenge,
		"signature": hex.EncodeToString(sig),
	}, &verifyResp); err != nil {
		return fmt.Errorf("verify challenge: %w", err)
	}

	c.token = verifyResp.Data.Token
	return nil
}

// KVGet reads a secret at the given path. version=0 returns the latest.
func (c *Client) KVGet(ctx context.Context, path string, version int) (map[string]any, error) {
	url := "/v1/secrets/kv/" + path
	if version > 0 {
		url += fmt.Sprintf("?version=%d", version)
	}
	var resp struct {
		Data map[string]any `json:"data"`
		Err  string         `json:"error"`
	}
	if err := c.doJSON(ctx, "GET", url, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return nil, fmt.Errorf("%s", resp.Err)
	}
	if val, ok := resp.Data["value"].(map[string]any); ok {
		return val, nil
	}
	return resp.Data, nil
}

// KVSet writes a secret at the given path.
func (c *Client) KVSet(ctx context.Context, path string, value map[string]any) error {
	var resp struct{ Err string `json:"error"` }
	return c.doJSON(ctx, "PUT", "/v1/secrets/kv/"+path, value, &resp)
}

// KVDelete soft-deletes a secret.
func (c *Client) KVDelete(ctx context.Context, path string) error {
	var resp struct{ Err string `json:"error"` }
	return c.doJSON(ctx, "DELETE", "/v1/secrets/kv/"+path, nil, &resp)
}

// TransitEncrypt encrypts plaintext using a named key.
func (c *Client) TransitEncrypt(ctx context.Context, keyName, plaintext string) (string, error) {
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
		Err string `json:"error"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/secrets/transit/"+keyName+"/encrypt",
		map[string]string{"plaintext": plaintext}, &resp); err != nil {
		return "", err
	}
	if resp.Err != "" {
		return "", fmt.Errorf("%s", resp.Err)
	}
	return resp.Data.Ciphertext, nil
}

// TransitDecrypt decrypts a ciphertext using a named key.
func (c *Client) TransitDecrypt(ctx context.Context, keyName, ciphertext string) (string, error) {
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
		Err string `json:"error"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/secrets/transit/"+keyName+"/decrypt",
		map[string]string{"ciphertext": ciphertext}, &resp); err != nil {
		return "", err
	}
	if resp.Err != "" {
		return "", fmt.Errorf("%s", resp.Err)
	}
	return resp.Data.Plaintext, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("lockr request: %w", err)
	}
	defer resp.Body.Close()

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func buildTLSConfig(caPath string) (*tls.Config, error) {
	if caPath == "" {
		return &tls.Config{MinVersion: tls.VersionTLS13}, nil
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}
