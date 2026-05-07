package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/etherance/lockr/internal/config"
	"github.com/etherance/lockr/internal/server"
	"github.com/etherance/lockr/internal/storage"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	devMode bool

	// Shared flags for client commands.
	serverAddr string
	keyPath    string
	serviceID  string
	caPath     string
	adminToken string
	outputFmt  string
)

func main() {
	root := &cobra.Command{
		Use:   "lockr",
		Short: "Lockr — self-hosted secrets manager",
	}

	// Global flags.
	root.PersistentFlags().StringVar(&serverAddr, "addr", envOr("LOCKR_ADDR", "https://localhost:8300"), "Lockr server address")
	root.PersistentFlags().StringVar(&keyPath, "key", envOr("LOCKR_KEY", ""), "Path to Ed25519 private key")
	root.PersistentFlags().StringVar(&serviceID, "identity", envOr("LOCKR_SERVICE", ""), "Service identity for Ed25519 authentication")
	root.PersistentFlags().StringVar(&caPath, "ca", envOr("LOCKR_CA", ""), "Path to CA certificate")
	root.PersistentFlags().StringVar(&adminToken, "token", envOr("LOCKR_TOKEN", ""), "Admin token")
	root.PersistentFlags().StringVar(&outputFmt, "output", "text", "Output format: text|json")

	root.AddCommand(
		serverCmd(),
		initCmd(),
		enrollCmd(),
		revokeCmd(),
		getCmd(),
		setCmd(),
		deleteCmd(),
		listCmd(),
		statusCmd(),
		adminCmd(),
		auditCmd(),
		transitCmd(),
		dbCmd(),
		debugCmd(),
		policyCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the Lockr server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil && !devMode {
				return fmt.Errorf("load config: %w (use --dev for dev mode)", err)
			}
			if devMode || cfg == nil {
				cfg = config.Defaults()
				cfg.Server.Addr = "0.0.0.0:8300"
			}
			srv := server.New(cfg)
			return srv.Run(devMode)
		},
	}
	cmd.Flags().StringVar(&cfgFile, "config", "/etc/lockr/config.yml", "Config file path")
	cmd.Flags().BoolVar(&devMode, "dev", false, "Dev mode: no TLS, no auth, in-memory storage")
	return cmd
}

func initCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "First-time setup: generate master key and TLS certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(dataDir)
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", "/var/lib/lockr", "Data directory")
	return cmd
}

func runInit(dataDir string) error {
	for _, d := range []string{
		dataDir,
		filepath.Join(dataDir, "data"),
	} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("create data directory %s: %w", d, err)
		}
	}

	for _, d := range []string{"/etc/lockr/tls", "/etc/lockr/policies"} {
		if err := os.MkdirAll(d, 0700); err != nil {
			fmt.Printf("Warning: could not create %s: %v\n", d, err)
		}
	}

	// Generate master key.
	masterKey, err := storage.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}

	fmt.Print("Enter passphrase to protect master key: ")
	passphrase, err := readPassphrase()
	if err != nil {
		return err
	}

	mkPath := filepath.Join(dataDir, "master.key.enc")
	if err := storage.SaveMasterKey(mkPath, masterKey, passphrase); err != nil {
		return fmt.Errorf("save master key: %w", err)
	}
	storage.ZeroBytes(masterKey)
	fmt.Printf("Master key saved to %s\n", mkPath)

	// Generate self-signed CA + server cert.
	if err := generateTLSCerts("/etc/lockr/tls"); err != nil {
		fmt.Printf("Warning: could not generate TLS certs: %v\n", err)
		fmt.Println("You can generate them manually or use your own certificates.")
	} else {
		fmt.Println("TLS certificates generated in /etc/lockr/tls/")
	}

	// Write example config.
	cfgPath := "/etc/lockr/config.yml"
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		exampleCfg := fmt.Sprintf(`server:
  addr: "0.0.0.0:8300"
  tls_cert: "/etc/lockr/tls/server.crt"
  tls_key: "/etc/lockr/tls/server.key"
  tls_ca: "/etc/lockr/tls/ca.crt"

storage:
  data_dir: "%s/data"
  master_key_path: "%s/master.key.enc"

audit:
  log_file: "%s/audit.log"

policy:
  dir: "/etc/lockr/policies"

session:
  ttl: "1h"
  max_ttl: "24h"

log_level: "info"
`, dataDir, dataDir, dataDir)
		if err := os.WriteFile(cfgPath, []byte(exampleCfg), 0600); err != nil {
			fmt.Printf("Warning: could not write config: %v\n", err)
		} else {
			fmt.Printf("Config written to %s\n", cfgPath)
		}
	}

	fmt.Println("\nLockr initialized. Start the server with:")
	fmt.Println("  LOCKR_PASSPHRASE=<your-passphrase> lockr server")
	return nil
}

func enrollCmd() *cobra.Command {
	var service, authMethod, policyName, outputDir string
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Register a new service",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newAdminClient()
			resp, err := client.post("/v1/sys/enroll", map[string]string{
				"service":     service,
				"auth_method": authMethod,
				"policy":      policyName,
			})
			if err != nil {
				return err
			}
			if outputDir != "" && authMethod != "totp" {
				return saveEnrollmentKeys(outputDir, service, resp)
			}
			printResponse(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&service, "service", "", "Service name")
	cmd.Flags().StringVar(&authMethod, "auth", "ed25519", "Auth method: ed25519|totp")
	cmd.Flags().StringVar(&policyName, "policy", "", "Policy name")
	cmd.Flags().StringVar(&outputDir, "output", "", "Output directory for keys")
	cmd.MarkFlagRequired("service")
	cmd.MarkFlagRequired("policy")
	return cmd
}

func revokeCmd() *cobra.Command {
	var service string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a service's access",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newAdminClient()
			resp, err := client.del("/v1/sys/revoke/" + service)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&service, "service", "", "Service name")
	cmd.MarkFlagRequired("service")
	return cmd
}

func getCmd() *cobra.Command {
	var version int
	var field string
	cmd := &cobra.Command{
		Use:   "get <path>",
		Short: "Read a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			url := "/v1/secrets/kv/" + args[0]
			if version > 0 {
				url += "?version=" + strconv.Itoa(version)
			}
			resp, err := client.get(url)
			if err != nil {
				return err
			}
			if field != "" {
				if data, ok := resp["data"].(map[string]any); ok {
					if v, ok := data["value"]; ok {
						if valMap, ok := v.(map[string]any); ok {
							fmt.Println(valMap[field])
							return nil
						}
					}
				}
			}
			printResponse(resp)
			return nil
		},
	}
	cmd.Flags().IntVar(&version, "version", 0, "Specific version (0 = latest)")
	cmd.Flags().StringVar(&field, "field", "", "Extract a single JSON field")
	return cmd
}

func setCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <path> <json-value>",
		Short: "Write a secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var value json.RawMessage
			if err := json.Unmarshal([]byte(args[1]), &value); err != nil {
				return fmt.Errorf("value must be valid JSON: %w", err)
			}
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.put("/v1/secrets/kv/"+args[0], value)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	return cmd
}

func deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <path>",
		Short: "Soft-delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.del("/v1/secrets/kv/" + args[0])
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <path>",
		Short: "List secrets at path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if len(path) == 0 || path[len(path)-1] != '/' {
				path += "/"
			}
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.get("/v1/secrets/kv/" + path)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Health and status info",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newAdminClient()
			resp, err := client.get("/v1/sys/health")
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
}

func adminCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Manage admin tokens"}

	create := &cobra.Command{
		Use:   "create",
		Short: "Create an admin token",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			client := newAdminClient()
			resp, err := client.post("/v1/sys/admin/create", map[string]string{"name": name})
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	create.Flags().String("name", "", "Admin name")
	create.MarkFlagRequired("name")

	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an admin token",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			client := newAdminClient()
			resp, err := client.del("/v1/sys/admin/" + name)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	revoke.Flags().String("name", "", "Admin name")
	revoke.MarkFlagRequired("name")

	cmd.AddCommand(create, revoke)
	return cmd
}

func auditCmd() *cobra.Command {
	var service, since, path string
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "View audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := "/v1/sys/audit?"
			if service != "" {
				url += "service=" + service + "&"
			}
			if since != "" {
				url += "since=" + since + "&"
			}
			if path != "" {
				url += "path=" + path + "&"
			}
			if limit > 0 {
				url += "limit=" + strconv.Itoa(limit)
			}
			client := newAdminClient()
			resp, err := client.get(url)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&service, "service", "", "Filter by service")
	cmd.Flags().StringVar(&since, "since", "", "Duration filter (e.g. 24h)")
	cmd.Flags().StringVar(&path, "path", "", "Filter by path prefix")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max entries")
	return cmd
}

func transitCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "transit", Short: "Transit encryption operations"}

	encrypt := &cobra.Command{
		Use:  "encrypt <keyname>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plaintext, _ := cmd.Flags().GetString("plaintext")
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.post("/v1/secrets/transit/"+args[0]+"/encrypt", map[string]string{"plaintext": plaintext})
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	encrypt.Flags().String("plaintext", "", "Plaintext to encrypt")

	decrypt := &cobra.Command{
		Use:  "decrypt <keyname>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ct, _ := cmd.Flags().GetString("ciphertext")
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.post("/v1/secrets/transit/"+args[0]+"/decrypt", map[string]string{"ciphertext": ct})
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	decrypt.Flags().String("ciphertext", "", "Ciphertext to decrypt")

	rotate := &cobra.Command{
		Use:  "rotate <keyname>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.post("/v1/secrets/transit/"+args[0]+"/rotate", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.AddCommand(encrypt, decrypt, rotate)
	return cmd
}

func dbCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Database dynamic credentials"}

	configCmd := &cobra.Command{
		Use:   "config <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Configure a DB dynamic credential role",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newAdminClient()
			resp, err := client.get("/v1/secrets/db/" + args[0] + "/config")
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	credsCmd := &cobra.Command{
		Use:   "creds <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Request dynamic DB credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.post("/v1/secrets/db/"+args[0]+"/creds", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	cmd.AddCommand(configCmd, credsCmd)
	return cmd
}

func debugCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "debug",
		Short: "Debug current identity and policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newServiceClient()
			if err != nil {
				return err
			}
			resp, err := client.get("/v1/auth/whoami")
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
}

func policyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "policy reload",
		Short: "Reload policies from disk",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newAdminClient()
			resp, err := client.post("/v1/sys/policy/reload", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func loadConfig() (*config.Config, error) {
	path := cfgFile
	if path == "" {
		path = "/etc/lockr/config.yml"
	}
	return config.Load(path)
}

func generateTLSCerts(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// CA key + cert.
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Lockr CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return err
	}
	caPrivDER, err := x509.MarshalPKCS8PrivateKey(caPriv)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.key"), "PRIVATE KEY", caPrivDER); err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	// Server key + cert.
	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lockr"},
		DNSNames:     []string{"lockr", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", srvDER); err != nil {
		return err
	}
	srvPrivDER, err := x509.MarshalPKCS8PrivateKey(srvPriv)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, "server.key"), "PRIVATE KEY", srvPrivDER)
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func saveEnrollmentKeys(dir, service string, resp map[string]any) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected response format")
	}
	privHex, _ := data["private_key"].(string)
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	keyPath := filepath.Join(dir, service+".key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(privBytes)), 0600); err != nil {
		return err
	}
	fmt.Printf("Private key saved to %s\n", keyPath)
	printResponse(resp)
	return nil
}

func readPassphrase() ([]byte, error) {
	// Simple stdin read — in production, use golang.org/x/term for no-echo.
	var pass string
	fmt.Scanln(&pass)
	if pass == "" {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	return []byte(pass), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printResponse(resp map[string]any) {
	if outputFmt == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(resp)
		return
	}
	if data, ok := resp["data"]; ok && data != nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
	} else if errMsg, ok := resp["error"].(string); ok {
		fmt.Fprintln(os.Stderr, "Error:", errMsg)
		os.Exit(1)
	}
}

// ── HTTP client ───────────────────────────────────────────────────────────────

type lockrClient struct {
	addr      string
	token     string
	tlsConfig *tls.Config
}

func newAdminClient() *lockrClient {
	return &lockrClient{addr: serverAddr, token: adminToken, tlsConfig: buildTLSConfig()}
}

func newServiceClient() (*lockrClient, error) {
	client := &lockrClient{addr: serverAddr, token: adminToken, tlsConfig: buildTLSConfig()}
	if client.token != "" {
		return client, nil
	}
	if keyPath == "" {
		return nil, fmt.Errorf("service commands require --key/LOCKR_KEY or --token/LOCKR_TOKEN")
	}
	if serviceID == "" {
		return nil, fmt.Errorf("service commands require --identity/LOCKR_SERVICE when using --key")
	}
	if err := client.authenticateEd25519(serviceID, keyPath); err != nil {
		return nil, err
	}
	return client, nil
}

func buildTLSConfig() *tls.Config {
	if caPath == "" {
		fmt.Fprintln(os.Stderr, "Warning: --ca not provided; TLS certificate verification is disabled. Use --ca or LOCKR_CA in production.")
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read CA file %s (%v); TLS certificate verification is disabled.\n", caPath, err)
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
}

func (c *lockrClient) get(path string) (map[string]any, error) {
	return c.do("GET", path, nil)
}

func (c *lockrClient) post(path string, body any) (map[string]any, error) {
	return c.do("POST", path, body)
}

func (c *lockrClient) put(path string, body any) (map[string]any, error) {
	return c.do("PUT", path, body)
}

func (c *lockrClient) del(path string) (map[string]any, error) {
	return c.do("DELETE", path, nil)
}

func (c *lockrClient) authenticateEd25519(identity, keyPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	keyBytes, err := hex.DecodeString(string(bytes.TrimSpace(keyData)))
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key length %d, want %d", len(keyBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(keyBytes)

	challengeResp, err := c.post("/v1/auth/challenge", map[string]string{"service": identity})
	if err != nil {
		return fmt.Errorf("request challenge: %w", err)
	}
	challengeHex, err := responseDataString(challengeResp, "challenge")
	if err != nil {
		return fmt.Errorf("read challenge response: %w", err)
	}
	challenge, err := hex.DecodeString(challengeHex)
	if err != nil {
		return fmt.Errorf("decode challenge: %w", err)
	}

	signature := ed25519.Sign(priv, challenge)
	verifyResp, err := c.post("/v1/auth/verify", map[string]string{
		"challenge": challengeHex,
		"signature": hex.EncodeToString(signature),
	})
	if err != nil {
		return fmt.Errorf("verify challenge: %w", err)
	}
	token, err := responseDataString(verifyResp, "token")
	if err != nil {
		return fmt.Errorf("read verify response: %w", err)
	}
	c.token = token
	return nil
}

func responseDataString(resp map[string]any, field string) (string, error) {
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", fmt.Errorf("%s", errMsg)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("missing data object")
	}
	value, ok := data[field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("missing data.%s", field)
	}
	return value, nil
}

func (c *lockrClient) do(method, path string, body any) (map[string]any, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: c.tlsConfig},
		Timeout:   15 * time.Second,
	}

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), method, c.addr+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}
