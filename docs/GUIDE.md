# Lockr — Self-Hosted Secrets Manager: Complete Guide

Lockr is a self-hosted secrets manager. It stores encrypted secrets, issues short-lived session tokens to services, enforces fine-grained policies, and logs every operation. This guide covers everything from first-time setup to how a new server connects and uses the API.

---

## Table of Contents

1. [How It Works (Overview)](#how-it-works)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [First-Time Server Setup](#first-time-server-setup)
5. [Configuration Reference](#configuration-reference)
6. [Starting the Server](#starting-the-server)
7. [Admin Tokens](#admin-tokens)
8. [Policies](#policies)
9. [Enrolling a New Service (How a New Server Connects)](#enrolling-a-new-service)
10. [Service Authentication Flow](#service-authentication-flow)
11. [CLI Reference — All Commands](#cli-reference)
12. [HTTP API Reference — All Endpoints](#http-api-reference)
13. [Go Client SDK](#go-client-sdk)
14. [Docker / Docker Compose](#docker--docker-compose)
15. [Token Types](#token-types)
16. [Internal Architecture](#internal-architecture)

---

## How It Works

```
Your Service                   Lockr Server
    |                               |
    |-- 1. POST /v1/auth/challenge -->|  (send service name)
    |<-- challenge bytes ------------|
    |                               |
    |-- 2. POST /v1/auth/verify ---->|  (sign challenge with private key)
    |<-- session token (lvt_...) ----|
    |                               |
    |-- 3. GET /v1/secrets/kv/... -->|  (use session token in header)
    |<-- secret value ---------------|
```

Every service gets a **keypair** at enroll time. The private key lives only on the service. Lockr stores the public key. Authentication is a **challenge-response** — no passwords are ever sent over the wire.

---

## Requirements

- Go 1.21+ (to build from source)  
- Linux / macOS (or Docker)  
- Port `8300` open (configurable)

---

## Installation

### Option A — Build from source

```bash
git clone https://github.com/etherance/lockr
cd lockr
go build -o lockr ./cmd/lockr
sudo mv lockr /usr/local/bin/lockr
```

### Option B — Docker

```bash
docker pull ghcr.io/etherance/lockr:latest
```

See [Docker / Docker Compose](#docker--docker-compose) below.

---

## First-Time Server Setup

Run this **once** on the machine that will host Lockr:

```bash
sudo lockr init --data-dir /var/lib/lockr
```

What it does step by step:

| Step | What happens |
|------|-------------|
| 1 | Creates `/var/lib/lockr/`, `/var/lib/lockr/data/`, `/etc/lockr/tls/`, `/etc/lockr/policies/` |
| 2 | Generates a random **master encryption key** (32 bytes) |
| 3 | Prompts you for a **passphrase** to encrypt the master key |
| 4 | Saves the encrypted master key to `/var/lib/lockr/master.key.enc` |
| 5 | Generates a self-signed **CA certificate** + **server TLS certificate** in `/etc/lockr/tls/` |
| 6 | Writes a starter config to `/etc/lockr/config.yml` |

After `init`, your `/etc/lockr/tls/` will contain:

```
ca.crt      ← distribute this to all services (for TLS verification)
ca.key      ← keep secret, never distribute
server.crt  ← used by the Lockr server
server.key  ← used by the Lockr server
```

> **Important:** Back up `master.key.enc` and remember your passphrase. Without these, all secrets are unrecoverable.

---

## Configuration Reference

Default config location: `/etc/lockr/config.yml`

```yaml
server:
  addr: "0.0.0.0:8300"              # listen address
  tls_cert: "/etc/lockr/tls/server.crt"
  tls_key:  "/etc/lockr/tls/server.key"
  tls_ca:   "/etc/lockr/tls/ca.crt" # optional: for mTLS client verification

storage:
  data_dir:        "/var/lib/lockr/data"         # BadgerDB data directory
  master_key_path: "/var/lib/lockr/master.key.enc"

audit:
  log_file: "/var/lib/lockr/audit.log"

policy:
  dir: "/etc/lockr/policies"   # .yaml policy files loaded from here

dynamic_secrets:
  credential_janitor_interval: "5m"  # how often to clean up expired DB leases

session:
  ttl:     "1h"    # default session token lifetime
  max_ttl: "24h"   # maximum allowed session lifetime

log_level: "info"  # debug | info | warn | error
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `LOCKR_PASSPHRASE` | Passphrase to unlock the master key on startup |
| `LOCKR_ADDR` | Override server address for CLI client |
| `LOCKR_KEY` | Path to Ed25519 private key for CLI client |
| `LOCKR_CA` | Path to CA cert for CLI client |
| `LOCKR_TOKEN` | Admin token for CLI client |

---

## Starting the Server

### Normal mode (production)

```bash
LOCKR_PASSPHRASE=your-passphrase lockr server --config /etc/lockr/config.yml
```

### Dev mode (no TLS, no auth, in-memory storage — for local testing only)

```bash
lockr server --dev
```

> In dev mode: no passphrase needed, all auth checks are bypassed, data is not persisted.

### As a systemd service

```ini
# /etc/systemd/system/lockr.service
[Unit]
Description=Lockr Secrets Manager
After=network.target

[Service]
ExecStart=/usr/local/bin/lockr server --config /etc/lockr/config.yml
Environment=LOCKR_PASSPHRASE=your-passphrase
Restart=on-failure
User=lockr

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now lockr
```

---

## Admin Tokens

The **first admin token** is created using the CLI directly against the server. You must be running the server first.

### Create the first admin token (dev mode, then lock down)

```bash
# Start in dev mode temporarily
lockr server --dev &

# Create admin token
lockr admin create --name root --addr https://localhost:8300

# Output:
# {
#   "name": "root",
#   "token": "lkat_XXXXXXXXXXXXXXXXXX"
# }
```

Save the token — it is shown **only once**.

### Create additional admin tokens

```bash
lockr admin create --name ops-team \
  --addr https://lockr:8300 \
  --token lkat_XXXXXXXXX
```

### Revoke an admin token

```bash
lockr admin revoke --name ops-team \
  --addr https://lockr:8300 \
  --token lkat_XXXXXXXXX
```

Admin tokens are prefixed `lkat_`. They have **full access** to all admin routes.

---

## Policies

Policies are YAML files in `/etc/lockr/policies/`. Each file defines what paths and operations a service identity can access.

### Policy file format

```yaml
# /etc/lockr/policies/api-server.yaml
name: api-server
description: "Policy for the main API backend service"

rules:
  - path: "secrets/kv/prod/api/*"
    capabilities: [read]

  - path: "secrets/kv/prod/db/*"
    capabilities: [read]

  - path: "secrets/transit/payments-key"
    capabilities: [encrypt, decrypt]

  - path: "secrets/db/postgres/main"
    capabilities: [read]
```

### Available capabilities

| Capability | Allows |
|-----------|--------|
| `read` | GET secrets |
| `write` | PUT/create secrets |
| `delete` | DELETE secrets |
| `list` | List keys at a path prefix |
| `encrypt` | Transit encrypt |
| `decrypt` | Transit decrypt |

### Wildcard matching

Use `*` at the end of a path to match all sub-paths:
- `secrets/kv/prod/*` — matches anything under `prod/`

### Reload policies without restarting

```bash
lockr policy reload --addr https://lockr:8300 --token lkat_XXX
```

---

## Enrolling a New Service

This is how you register a new server/service so it can connect to Lockr.

### Step 1 — Create a policy for the service

```bash
cat > /etc/lockr/policies/my-api.yaml << EOF
name: my-api
description: "My API service"

rules:
  - path: "secrets/kv/prod/my-api/*"
    capabilities: [read, write]
EOF
```

Reload policies:

```bash
lockr policy reload --addr https://lockr:8300 --token lkat_XXX
```

### Step 2 — Enroll the service

```bash
lockr enroll \
  --service my-api \
  --auth ed25519 \
  --policy my-api \
  --output ./certs/my-api \
  --addr https://lockr:8300 \
  --token lkat_XXX
```

This generates a keypair, registers the public key with Lockr, and saves the private key to `./certs/my-api/my-api.key`.

Output:
```json
{
  "service": "my-api",
  "auth_method": "ed25519",
  "policy": "my-api",
  "public_key": "a1b2c3...",
  "private_key": "d4e5f6..."
}
```

> **Important:** The private key is shown **only once**. Save it securely. Copy it to the service machine.

### Step 3 — Copy credentials to the service machine

```bash
# Copy the private key and CA cert to your service machine
scp ./certs/my-api/my-api.key user@my-api-server:/etc/my-api/lockr.key
scp /etc/lockr/tls/ca.crt user@my-api-server:/etc/my-api/lockr-ca.crt
```

### Step 4 — Configure the service to connect

Set environment variables on the service:

```bash
export LOCKR_ADDR="https://lockr-server:8300"
export LOCKR_KEY="/etc/my-api/lockr.key"
export LOCKR_CA="/etc/my-api/lockr-ca.crt"
```

### Step 5 — Test the connection

```bash
lockr debug \
  --addr https://lockr-server:8300 \
  --key /etc/my-api/lockr.key \
  --ca /etc/my-api/lockr-ca.crt

# Output:
# {
#   "identity": "my-api",
#   "policy": "my-api",
#   "server_time": "2026-04-26T06:00:00Z"
# }
```

### Revoking a service

```bash
lockr revoke --service my-api \
  --addr https://lockr:8300 \
  --token lkat_XXX
```

---

## Service Authentication Flow

When a service starts up, it authenticates using Ed25519 challenge-response. Here is the exact flow:

### 1. Request a challenge

```http
POST /v1/auth/challenge
Content-Type: application/json

{"service": "my-api"}
```

Response:
```json
{
  "data": {
    "challenge": "a1b2c3d4...",  // 32-byte hex-encoded random bytes
    "service": "my-api"
  }
}
```

The challenge is valid for **60 seconds** and is **single-use**.

### 2. Sign the challenge

Using the service's Ed25519 private key, sign the raw challenge bytes.

### 3. Verify and get a session token

```http
POST /v1/auth/verify
Content-Type: application/json

{
  "challenge": "a1b2c3d4...",
  "signature": "e5f6a7b8..."  // hex-encoded Ed25519 signature
}
```

Response:
```json
{
  "data": {
    "token": "lvt_XXXXXXXXXXXXXXXXXX",
    "identity": "my-api",
    "policy": "my-api",
    "expires_in": 3600
  }
}
```

### 4. Use the session token

Include the token in every subsequent request:

```http
GET /v1/secrets/kv/prod/my-api/db-password
Authorization: Bearer lvt_XXXXXXXXXXXXXXXXXX
```

Or use the header `X-Lockr-Token: lvt_XXXXXXXXXXXXXXXXXX`.

---

## CLI Reference

All CLI commands accept these global flags:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `LOCKR_ADDR` | `https://localhost:8300` | Lockr server URL |
| `--token` | `LOCKR_TOKEN` | — | Admin token |
| `--key` | `LOCKR_KEY` | — | Path to Ed25519 private key |
| `--ca` | `LOCKR_CA` | — | Path to CA certificate |
| `--output` | — | `text` | Output format: `text` or `json` |

### `lockr server`

Start the Lockr server.

```bash
lockr server [--config /etc/lockr/config.yml] [--dev]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `/etc/lockr/config.yml` | Path to config file |
| `--dev` | `false` | Dev mode: no TLS, no auth, in-memory |

---

### `lockr init`

First-time setup. Generates master key, TLS certs, and config.

```bash
lockr init [--data-dir /var/lib/lockr]
```

---

### `lockr enroll`

Register a new service with Lockr.

```bash
lockr enroll --service <name> --policy <policy-name> [--auth ed25519|totp] [--output <dir>]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--service` | ✅ | Service name |
| `--policy` | ✅ | Policy name to attach |
| `--auth` | — | Auth method: `ed25519` (default) or `totp` |
| `--output` | — | Directory to save the private key file |

---

### `lockr revoke`

Revoke a service's access immediately.

```bash
lockr revoke --service <name>
```

---

### `lockr get`

Read a secret.

```bash
lockr get <path> [--version N] [--field <key>]
```

| Flag | Description |
|------|-------------|
| `--version` | Read a specific version (0 = latest) |
| `--field` | Extract a single JSON field from the secret value |

Example:
```bash
lockr get prod/my-api/db --field password
```

---

### `lockr set`

Write a secret. Value must be valid JSON.

```bash
lockr set <path> '<json>'
```

Example:
```bash
lockr set prod/my-api/db '{"host":"db.internal","password":"s3cr3t"}'
```

---

### `lockr delete`

Soft-delete a secret (versioned; data is not permanently destroyed).

```bash
lockr delete <path>
```

---

### `lockr list`

List secret keys at a path prefix.

```bash
lockr list <path/>
```

---

### `lockr status`

Check server health.

```bash
lockr status
```

---

### `lockr admin create`

Create a new admin token.

```bash
lockr admin create --name <name>
```

---

### `lockr admin revoke`

Revoke an admin token by name.

```bash
lockr admin revoke --name <name>
```

---

### `lockr audit`

View the audit log.

```bash
lockr audit [--service <name>] [--since <duration>] [--path <prefix>] [--limit N]
```

| Flag | Description |
|------|-------------|
| `--service` | Filter by service identity |
| `--since` | Duration filter e.g. `24h`, `1h30m` |
| `--path` | Filter by path prefix |
| `--limit` | Max number of entries to return |

---

### `lockr transit encrypt`

Encrypt data using a named transit key.

```bash
lockr transit encrypt <keyname> --plaintext "hello world"
```

---

### `lockr transit decrypt`

Decrypt data using a named transit key.

```bash
lockr transit decrypt <keyname> --ciphertext "vault:v1:..."
```

---

### `lockr transit rotate`

Rotate a transit key (new version created; old versions still decrypt).

```bash
lockr transit rotate <keyname>
```

---

### `lockr db creds`

Request dynamic database credentials.

```bash
lockr db creds <role-name>
```

---

### `lockr db config`

View a dynamic DB credential role configuration.

```bash
lockr db config <role-name>
```

---

### `lockr debug`

Show current identity and policy (verifies connectivity and auth).

```bash
lockr debug
```

---

### `lockr policy reload`

Reload all policy files from disk without restarting the server.

```bash
lockr policy reload
```

---

## HTTP API Reference

All authenticated routes require:
```
Authorization: Bearer <token>
```
or
```
X-Lockr-Token: <token>
```

Every response has a `data` field on success or an `error` string on failure.

---

### Public Routes (no auth required)

#### `GET /v1/sys/health`

Health check.

**Response:**
```json
{"data": {"status": "ok", "time": "2026-04-26T06:00:00Z"}}
```

---

#### `POST /v1/auth/challenge`

Get a challenge to begin Ed25519 authentication.

**Body:**
```json
{"service": "my-api"}
```

**Response:**
```json
{"data": {"challenge": "a1b2c3...", "service": "my-api"}}
```

---

#### `POST /v1/auth/verify`

Submit a signed challenge to receive a session token.

**Body:**
```json
{"challenge": "a1b2c3...", "signature": "d4e5f6..."}
```

**Response:**
```json
{
  "data": {
    "token": "lvt_...",
    "identity": "my-api",
    "policy": "my-api",
    "expires_in": 3600
  }
}
```

---

#### `POST /v1/auth/totp`

Login using a TOTP code (for services enrolled with `--auth totp`).

**Body:**
```json
{"service": "my-api", "code": 123456}
```

**Response:** same as `/v1/auth/verify`

---

#### `POST /v1/auth/admin/login`

Exchange an admin token for a session token.

**Body:**
```json
{"token": "lkat_..."}
```

**Response:** same as `/v1/auth/verify`

---

### Authenticated Routes

#### `DELETE /v1/auth/session`

Logout / revoke the current session token.

**Response:**
```json
{"data": {"status": "logged out"}}
```

---

#### `GET /v1/auth/whoami`

Show current identity and policy.

**Response:**
```json
{"data": {"identity": "my-api", "policy": "my-api", "server_time": "..."}}
```

---

### KV Secrets

#### `GET /v1/secrets/kv/<path>`

Read a secret. Append `/` to list keys at that prefix.

| Query Param | Description |
|-------------|-------------|
| `version=N` | Read version N (0 or omit = latest) |

Append `/versions` to the path to list all versions:
```
GET /v1/secrets/kv/prod/db/versions
```

**Response:**
```json
{"data": {"path": "prod/db", "version": 3, "value": {"host": "...", "password": "..."}}}
```

---

#### `PUT /v1/secrets/kv/<path>`

Write a secret. Body is any JSON value.

**Body:**
```json
{"host": "db.internal", "password": "s3cr3t"}
```

**Response:** returns metadata only (value is never echoed back).

---

#### `DELETE /v1/secrets/kv/<path>`

Soft-delete a secret.

**Response:**
```json
{"data": {"status": "deleted"}}
```

---

### Transit Encryption

#### `POST /v1/secrets/transit/<keyname>/create`

Create a new named encryption key. *(Admin)*

---

#### `POST /v1/secrets/transit/<keyname>/encrypt`

Encrypt plaintext.

**Body:**
```json
{"plaintext": "hello world"}
```

**Response:**
```json
{"data": {"ciphertext": "lockr:v1:base64..."}}
```

---

#### `POST /v1/secrets/transit/<keyname>/decrypt`

Decrypt ciphertext.

**Body:**
```json
{"ciphertext": "lockr:v1:base64..."}
```

**Response:**
```json
{"data": {"plaintext": "hello world"}}
```

---

#### `POST /v1/secrets/transit/<keyname>/rotate`

Rotate the key (creates a new version). Old ciphertexts still decrypt.

---

#### `GET /v1/secrets/transit/<keyname>/info`

Get key metadata (current version, created_at, etc).

---

### Dynamic DB Credentials

#### `GET /v1/secrets/db/<role>/config`

View a DB role configuration. *(Admin)*

#### `PUT /v1/secrets/db/<role>/config`

Configure a DB dynamic credential role. *(Admin)*

#### `POST /v1/secrets/db/<role>/creds`

Generate temporary database credentials.

**Response:**
```json
{"data": {"username": "lockr-abc123", "password": "...", "lease_id": "...", "ttl": "1h"}}
```

#### `GET /v1/secrets/db/<role>/creds`

List active leases for a role.

#### `DELETE /v1/secrets/db/<role>/creds/<lease-id>`

Revoke a specific DB credential lease.

#### `POST /v1/secrets/db/<role>/test`

Test the DB connection for a role. *(Admin)*

---

### System / Admin Routes

All routes below require an admin token (`lkat_...`).

#### `GET /v1/sys/status`

Detailed server status (uptime, goroutines, memory).

#### `POST /v1/sys/enroll`

Enroll a new service.

**Body:**
```json
{"service": "my-api", "auth_method": "ed25519", "policy": "my-api"}
```

#### `DELETE /v1/sys/revoke/<service>`

Revoke a service immediately.

#### `GET /v1/sys/audit`

Query the audit log.

| Query Param | Description |
|-------------|-------------|
| `service` | Filter by identity |
| `since` | Duration e.g. `24h` |
| `path` | Path prefix filter |
| `limit` | Max results |

#### `POST /v1/sys/admin/create`

Create an admin token.

**Body:**
```json
{"name": "ops", "policy": "admin"}
```

#### `DELETE /v1/sys/admin/<name>`

Delete an admin token.

#### `POST /v1/sys/policy/reload`

Reload all policy files from disk.

---

## Go Client SDK

Import path: `github.com/etherance/lockr/pkg/client`

### Setup

```go
import "github.com/etherance/lockr/pkg/client"

c, err := client.New(client.Options{
    Addr:        "https://lockr-server:8300",
    PrivKeyPath: "/etc/my-api/lockr.key",   // path to hex-encoded Ed25519 private key
    CAPath:      "/etc/my-api/lockr-ca.crt", // path to CA cert
})
```

### Authenticate

```go
ctx := context.Background()
err = c.Authenticate(ctx, "my-api") // performs challenge-response automatically
```

### Read a secret

```go
val, err := c.KVGet(ctx, "prod/my-api/db", 0) // 0 = latest version
fmt.Println(val["password"])
```

### Write a secret

```go
err = c.KVSet(ctx, "prod/my-api/db", map[string]any{
    "host":     "db.internal",
    "password": "s3cr3t",
})
```

### Delete a secret

```go
err = c.KVDelete(ctx, "prod/my-api/db")
```

### Transit encryption

```go
ct, err := c.TransitEncrypt(ctx, "payments-key", "4111111111111111")
pt, err := c.TransitDecrypt(ctx, "payments-key", ct)
```

### Using an admin token instead of a keypair

```go
c, err := client.New(client.Options{
    Addr:       "https://lockr-server:8300",
    AdminToken: "lkat_XXXXXXXXXX",
    CAPath:     "/etc/lockr/lockr-ca.crt",
})
// No need to call Authenticate()
```

---

## Docker / Docker Compose

### Build and run with Docker Compose

```bash
cd deployments/

# Copy and edit config
cp ../config.example.yml config.yml
# Edit config.yml to match your paths

# Create TLS dir and run init first
mkdir -p tls policies
# Run init to generate certs and master key
docker run --rm -v $(pwd)/tls:/etc/lockr/tls \
  -v $(pwd):/var/lib/lockr \
  ghcr.io/etherance/lockr lockr init --data-dir /var/lib/lockr

# Start the stack
LOCKR_PASSPHRASE=your-passphrase docker compose up -d
```

### docker-compose.yml structure

```yaml
services:
  lockr:
    build:
      context: ..
      dockerfile: deployments/Dockerfile
    ports:
      - "8300:8300"
    volumes:
      - lockr_data:/var/lib/lockr
      - ./policies:/etc/lockr/policies
      - ./config.yml:/etc/lockr/config.yml
      - ./tls:/etc/lockr/tls
    environment:
      LOCKR_PASSPHRASE: ${LOCKR_PASSPHRASE}
    restart: unless-stopped

  # Your service connecting to lockr:
  # your-api:
  #   volumes:
  #     - ./certs/your-api.key:/certs/client.key:ro
  #     - ./tls/ca.crt:/certs/ca.crt:ro
  #   environment:
  #     LOCKR_ADDR: "https://lockr:8300"
  #     LOCKR_KEY: "/certs/client.key"
  #     LOCKR_CA: "/certs/ca.crt"
```

### Health check

```bash
curl -k https://localhost:8300/v1/sys/health
# {"data":{"status":"ok","time":"..."}}
```

---

## Token Types

| Prefix | Type | Created by | Used for |
|--------|------|-----------|---------|
| `lkat_` | Admin token | `lockr admin create` | Direct admin API access |
| `lvt_` | Session token | Auth endpoints | All secret operations |

- Admin tokens (`lkat_`) are long-lived and stored as Argon2id hashes.
- Session tokens (`lvt_`) expire after the configured TTL (default 1h).
- Both token types are accepted in `Authorization: Bearer` or `X-Lockr-Token` headers.

---

## Internal Architecture

```
cmd/lockr/main.go          CLI entry point, all commands
internal/
  api/
    server.go              HTTP server setup
    router.go              Route definitions + middleware chain
    middleware.go          Auth, audit, request-ID middleware
    auth_handlers.go       Challenge, verify, TOTP, admin login, whoami
    kv_handlers.go         KV get, put, delete
    transit_handlers.go    Transit encrypt, decrypt, rotate, info, create
    db_handlers.go         Dynamic DB credential generation
    sys_handlers.go        Enroll, revoke, audit, admin CRUD, policy reload
    response.go            JSON response helpers
  auth/
    admin.go               Admin token create/verify/delete (Argon2id hashes)
    session.go             Session token issue/validate/revoke
    ed25519.go             Ed25519 challenge generation and verification
    totp.go                TOTP secret generation and verification (RFC 6238)
  storage/
    badger.go              BadgerDB wrapper (get/set/delete/list/TTL)
    crypto.go              Master key generation, Argon2id hash/verify, AES-GCM
  secrets/
    kv.go                  Versioned KV store on top of storage
    transit.go             Transit encryption key management
    db.go                  Dynamic DB credential roles and leases
  config/                  Config loading and defaults
  policy/                  Policy file loading and capability checking
  audit/                   Audit log writing and querying
pkg/
  client/client.go         Public Go client SDK
```

### Storage layout (BadgerDB keys)

| Key prefix | Contents |
|-----------|---------|
| `auth/services/<name>` | Ed25519 service records |
| `auth/services/totp/<name>` | TOTP service records |
| `auth/sessions/<hash>` | Session token hashes + metadata |
| `auth/admins/<name>` | Admin token hashes + metadata |
| `secrets/kv/<path>` | Versioned KV entries |
| `secrets/transit/<key>` | Transit key versions |
| `secrets/db/<role>` | DB role configs and leases |

All secret values are **encrypted at rest** using AES-256-GCM with a key derived from the master key.
