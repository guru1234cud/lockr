# Lockr — Features & Usage Reference

Lockr is a self-hosted secrets manager written in Go. It runs as a single binary with embedded storage, encrypted secrets at rest, service authentication via Ed25519, policy-based access control, and full audit logging.

---

## Core Features

| Feature | Description |
|---|---|
| KV Secrets | Store and version JSON secrets at arbitrary paths |
| Transit Encryption | Encrypt/decrypt data with named AES keys (key never exposed) |
| Dynamic DB Credentials | Short-lived Postgres users created on demand |
| Ed25519 Auth | Challenge-response authentication for services |
| TOTP Auth | Time-based one-time password for services |
| User Auth | Username + password (Argon2id) for human operators |
| Admin Tokens | Long-lived `lkat_` tokens for system administration |
| Policy Engine | YAML + built-in policies with deny-by-default |
| Audit Log | Every request logged with identity, path, status, and duration |
| TLS 1.3 | Self-signed CA generated at init; HTTPS enforced in production |
| Go SDK | `pkg/client` for embedding Lockr auth in Go services |

---

## Getting Started

### 1. Initialize

```bash
lockr init --data-dir /var/lib/lockr
```

Generates a master key, TLS certificates, and the first admin token. Save the printed token.

### 2. Start the server

```bash
# Production
lockr server --config /etc/lockr/config.yml

# Development (no TLS, no auth, in-memory storage)
lockr server --dev
```

### 3. Check health

```bash
lockr status --addr https://localhost:8300 --ca /etc/lockr/tls/ca.crt
```

---

## Environment Variables

```bash
export LOCKR_ADDR=https://localhost:8300
export LOCKR_CA=/etc/lockr/tls/ca.crt
export LOCKR_TOKEN=lvt_...          # session or admin token
export LOCKR_SERVICE=my-app         # service name (Ed25519 auth)
export LOCKR_KEY=./keys/my-app.key  # Ed25519 private key path
export LOCKR_PASSPHRASE=...         # master key passphrase (server)
```

All `--addr`, `--ca`, `--token`, `--identity`, and `--key` flags read from these variables when not specified.

---

## Authentication

### Human operators — log in with username/password

```bash
lockr login --username alice --ca /etc/lockr/tls/ca.crt
# Prints: lvt_<session-token>

export LOCKR_TOKEN=lvt_...
```

### Services — enroll and authenticate with Ed25519

```bash
# Admin enrolls the service
lockr enroll --service my-app --auth ed25519 --policy readwrite \
  --output ./keys/ --token lkat_... --ca /etc/lockr/tls/ca.crt

# Service authenticates (CLI wraps challenge-response automatically)
lockr get prod/api/db \
  --identity my-app --key ./keys/my-app.key \
  --ca /etc/lockr/tls/ca.crt
```

### Admin token login

```bash
lockr admin create --name ops --token lkat_... --ca /etc/lockr/tls/ca.crt
# Prints a new lkat_ token for "ops"
```

### Check current identity

```bash
lockr debug --token lvt_... --ca /etc/lockr/tls/ca.crt
```

---

## KV Secrets

### Write a secret

```bash
lockr set prod/api/db '{"username":"api","password":"s3cret"}' \
  --token lvt_... --ca /etc/lockr/tls/ca.crt
```

### Read a secret

```bash
lockr get prod/api/db --token lvt_... --ca /etc/lockr/tls/ca.crt

# Read a single field
lockr get prod/api/db --field password --token lvt_... --ca /etc/lockr/tls/ca.crt

# Read a specific version (default is latest)
lockr get prod/api/db --version 2 --token lvt_... --ca /etc/lockr/tls/ca.crt
```

### List secrets at a path

```bash
lockr list prod/api/ --token lvt_... --ca /etc/lockr/tls/ca.crt
```

### Delete a secret

```bash
lockr delete prod/api/db --token lvt_... --ca /etc/lockr/tls/ca.crt
```

Up to 5 versions are retained per secret.

---

## Transit Encryption

Transit lets services encrypt/decrypt data without ever seeing the key.

### Create a key (admin)

```bash
# Done via API; key creation requires admin token
curl -X POST https://localhost:8300/v1/secrets/transit/payments-key/create \
  -H "Authorization: Bearer lkat_..." \
  --cacert /etc/lockr/tls/ca.crt
```

### Encrypt data

```bash
lockr transit encrypt payments-key --plaintext "card-4242" \
  --identity my-app --key ./keys/my-app.key --ca /etc/lockr/tls/ca.crt
# Prints: <ciphertext>
```

### Decrypt data

```bash
lockr transit decrypt payments-key --ciphertext "<ciphertext>" \
  --identity my-app --key ./keys/my-app.key --ca /etc/lockr/tls/ca.crt
# Prints: card-4242
```

### Rotate a key

```bash
lockr transit rotate payments-key --token lkat_... --ca /etc/lockr/tls/ca.crt
```

---

## Dynamic Database Credentials

Lockr creates short-lived Postgres users on demand and cleans them up automatically.

### Configure a DB connection (admin)

```bash
curl -X PUT https://localhost:8300/v1/secrets/db/prod-pg/config \
  -H "Authorization: Bearer lkat_..." \
  -H "Content-Type: application/json" \
  --cacert /etc/lockr/tls/ca.crt \
  -d '{"host":"db.example.com","port":5432,"dbname":"app","username":"lockr-admin","password":"..."}'
```

### Request temporary credentials

```bash
lockr db creds prod-pg \
  --identity my-app --key ./keys/my-app.key --ca /etc/lockr/tls/ca.crt
# Prints: username, password, lease_id, expires_at
```

### List active leases (admin)

```bash
curl https://localhost:8300/v1/secrets/db/prod-pg/creds \
  -H "Authorization: Bearer lkat_..." \
  --cacert /etc/lockr/tls/ca.crt
```

---

## User Management (Admin)

```bash
# Create a user
lockr user create --username alice --policy readonly \
  --token lkat_... --ca /etc/lockr/tls/ca.crt

# List users
lockr user list --token lkat_... --ca /etc/lockr/tls/ca.crt

# Change policy
lockr user set-policy --username alice --policy readwrite \
  --token lkat_... --ca /etc/lockr/tls/ca.crt

# Reset password
lockr user reset-password --username alice \
  --token lkat_... --ca /etc/lockr/tls/ca.crt

# Delete user
lockr user delete --username alice \
  --token lkat_... --ca /etc/lockr/tls/ca.crt
```

---

## Service Management (Admin)

```bash
# Enroll a service with Ed25519
lockr enroll --service my-app --auth ed25519 --policy readwrite \
  --output ./keys/ --token lkat_... --ca /etc/lockr/tls/ca.crt

# Enroll a service with TOTP
lockr enroll --service ci-runner --auth totp --policy readonly \
  --token lkat_... --ca /etc/lockr/tls/ca.crt

# Revoke a service
lockr revoke --service my-app --token lkat_... --ca /etc/lockr/tls/ca.crt
```

---

## Policy Engine

### Built-in policies

| Policy | Capabilities |
|---|---|
| `readonly` | `read`, `list` on `secrets/kv/*` |
| `readwrite` | `read`, `write`, `delete`, `list` on `secrets/kv/*`; `encrypt`, `decrypt` on `secrets/transit/*` |
| `admin` | Full access to KV, transit, and DB engines |
| `root` | All capabilities on all paths (dev mode only) |

### Custom YAML policy example

```yaml
# /etc/lockr/policies/payments.yml
name: payments
rules:
  - path: secrets/kv/prod/payments/*
    capabilities: [read, write, list]
  - path: secrets/transit/payments-key
    capabilities: [encrypt, decrypt]
  - path: secrets/kv/prod/internal/*
    capabilities: []   # explicit deny
```

### Reload policies without restart

```bash
lockr policy reload --token lkat_... --ca /etc/lockr/tls/ca.crt
# or: kill -HUP <server-pid>
```

---

## Audit Log

```bash
# All recent events
lockr audit --token lkat_... --ca /etc/lockr/tls/ca.crt

# Filter by identity
lockr audit --service user:alice --token lkat_... --ca /etc/lockr/tls/ca.crt

# Filter by time window and path prefix
lockr audit --since 24h --path prod/payments/ \
  --limit 100 --token lkat_... --ca /etc/lockr/tls/ca.crt
```

Each audit entry includes: `id`, `timestamp`, `identity`, `auth_method`, `operation`, `path`, `source_ip`, `request_id`, `status`, `duration_ms`.

---

## Go SDK

```go
import lockr "github.com/etherance/lockr/pkg/client"

c, err := lockr.New(lockr.Options{
    Addr:        "https://localhost:8300",
    PrivKeyPath: "./keys/my-app.key",
    CAPath:      "/etc/lockr/tls/ca.crt",
})
if err != nil {
    panic(err)
}

// Authenticate (challenge-response handled automatically)
if err := c.Authenticate(ctx, "my-app"); err != nil {
    panic(err)
}

// Read a secret
secret, err := c.KVGet(ctx, "prod/api/db", 0)  // 0 = latest version

// Write a secret
err = c.KVSet(ctx, "prod/api/db", map[string]any{"password": "new"})

// Transit encrypt/decrypt
cipher, err := c.TransitEncrypt(ctx, "payments-key", "card-4242")
plain, err  := c.TransitDecrypt(ctx, "payments-key", cipher)
```

---

## HTTP API — Quick Reference

All authenticated routes require:
```
Authorization: Bearer <token>
```

Every response is wrapped as:
```json
{ "data": { ... }, "error": null, "request_id": "..." }
```

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/sys/health` | None | Health check |
| `POST` | `/v1/auth/login` | None | User login |
| `POST` | `/v1/auth/challenge` | None | Ed25519 challenge |
| `POST` | `/v1/auth/verify` | None | Ed25519 verify |
| `POST` | `/v1/auth/totp` | None | TOTP login |
| `POST` | `/v1/auth/admin/login` | None | Admin token login |
| `GET` | `/v1/auth/whoami` | Session | Current identity |
| `DELETE` | `/v1/auth/session` | Session | Logout |
| `GET` | `/v1/secrets/kv/<path>` | Session | Read KV secret |
| `PUT` | `/v1/secrets/kv/<path>` | Session | Write KV secret |
| `DELETE` | `/v1/secrets/kv/<path>` | Session | Delete KV secret |
| `GET` | `/v1/secrets/kv/<path>/` | Session | List KV path |
| `POST` | `/v1/secrets/transit/<key>/encrypt` | Session | Encrypt data |
| `POST` | `/v1/secrets/transit/<key>/decrypt` | Session | Decrypt data |
| `POST` | `/v1/secrets/transit/<key>/rotate` | Admin | Rotate key |
| `POST` | `/v1/secrets/db/<name>/creds` | Session | Get DB credentials |
| `GET` | `/v1/sys/status` | Admin | Server status |
| `POST` | `/v1/sys/enroll` | Admin | Enroll service |
| `DELETE` | `/v1/sys/revoke/<service>` | Admin | Revoke service |
| `GET` | `/v1/sys/audit` | Admin | Query audit log |
| `POST` | `/v1/sys/users` | Admin | Create user |
| `GET` | `/v1/sys/users` | Admin | List users |
| `DELETE` | `/v1/sys/users/<name>` | Admin | Delete user |
| `POST` | `/v1/sys/admin/create` | Admin | Create admin token |
| `DELETE` | `/v1/sys/admin/<name>` | Admin | Delete admin token |
| `POST` | `/v1/sys/policy/reload` | Admin | Reload policies |

---

## Security Model

- **Master key**: AES-256-GCM derived via HKDF-SHA256; stored encrypted with the server passphrase
- **Secrets at rest**: Each secret encrypted with a per-path key derived from the master key
- **Session tokens**: SHA256 lookup key + Argon2id hash stored (plaintext never persists)
- **TLS**: 1.3 minimum; self-signed CA from `lockr init`
- **Policies**: Deny-by-default; explicit deny rules override allows

---

## Default Paths

```
Server:       https://localhost:8300
Config:       /etc/lockr/config.yml
Data:         /var/lib/lockr/data
Master key:   /var/lib/lockr/master.key.enc
Policies:     /etc/lockr/policies/
CA cert:      /etc/lockr/tls/ca.crt
```
