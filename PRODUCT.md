Lockr is a self-hosted secrets manager built for small development teams and startups. It runs as a single Go binary with no external database, no cloud account, and no agents required. The entire system — storage, encryption, authentication, and API — is contained in one executable that you drop on your server.

The problem Lockr solves is straightforward. Most secrets managers are either too complex to self-host (HashiCorp Vault requires a storage backend like Consul or etcd), locked to a specific cloud (AWS Secrets Manager, GCP Secret Manager), or SaaS products where your secrets live on someone else's infrastructure. Lockr is none of those things. It is designed for teams running Docker Compose stacks or self-hosted VMs who want proper secrets management without the operational overhead.


---


WHAT LOCKR STORES

Lockr manages three categories of secrets.

Static KV Secrets are the most common use case. You store a JSON object at a path, and any authorized service can read it. For example, a path like secrets/prod/stripe holds the value {"key":"sk_live_abc123","env":"prod"}. Lockr keeps the last five versions of every secret, so you can recover a previous value if needed. Deleted secrets are soft-deleted and recoverable for 30 days.

Dynamic Database Credentials are generated on demand. Instead of storing a shared Postgres password, Lockr connects to your database using an admin credential and creates a short-lived user with a random username and password when a service requests it. The user is automatically dropped when the TTL expires (default one hour). This means your application never holds a long-lived database credential.

Transit Encryption is encryption as a service. Your application sends plaintext to Lockr and receives back an encrypted ciphertext string in the format vault:v1:<data>. Your application never manages encryption keys directly. When you rotate the key, Lockr creates a new version — old ciphertext still decrypts using the previous version, so you can migrate gradually.


---


ENCRYPTION

Every secret value is encrypted with AES-256-GCM before it is written to disk. Lockr does not encrypt the entire database — it encrypts each secret individually, so a corrupted entry does not affect others.

The master key is a 256-bit random key stored in a file called master.key.enc. It is never stored in plaintext. When you run lockr init, Lockr generates this master key and encrypts it using Argon2id (a memory-hard password hashing algorithm) applied to your passphrase. To start the server, you provide the passphrase via the LOCKR_PASSPHRASE environment variable or an interactive prompt.

Per-path key derivation means each secret path has its own encryption key, derived from the master key using HKDF-SHA256 with the path as the derivation input. Compromising the key for one secret path does not expose any other secret.

The server uses TLS 1.3 exclusively. There is no TLS 1.2 fallback. Lockr generates a self-signed CA and server certificate during initialization so you do not need to configure your own certificates to get started, though you can replace them with your own.


---


AUTHENTICATION

Lockr supports four authentication methods. You can use different methods for different services depending on what fits your stack.

Ed25519 Challenge-Response is the primary method for production services. During enrollment, Lockr generates an Ed25519 keypair and gives the private key to your service. The private key never leaves that machine. On every authentication, Lockr sends a random 32-byte challenge, the service signs it with its private key, and Lockr verifies the signature against the stored public key. Revoking access is instant — delete the public key from Lockr and that service can no longer authenticate.

TOTP is available for legacy applications or runtimes that cannot perform Ed25519 signing. It uses RFC 6238 (the same standard as Google Authenticator) with a 30-second window and ±1 window clock skew tolerance. The shared secret is generated at enrollment. Lockr does not need to look up anything in the database to verify a TOTP code — it recomputes the expected value from the shared secret and the current timestamp.

Admin Tokens are long-lived tokens for human operators and CI/CD pipelines. They are created with lockr admin create --name=<name>, stored as Argon2id hashes in the database, and scoped to a named policy. Every action taken with an admin token is fully logged with the admin's identity.

Dev Mode is for local development only. Start the server with lockr server --dev and all authentication is bypassed, TLS is disabled, and storage is in-memory. Data is wiped when the server stops. The server prints a loud warning banner so you cannot accidentally mistake it for a production instance.

After any successful authentication (Ed25519 or TOTP), Lockr issues a session token in the format lvt_<random>. This token is valid for one hour by default. Only the Argon2id hash of the token is stored — the plaintext token is never persisted.


---


POLICY ENGINE

Access control is defined in YAML files stored on disk. Each file defines a named policy with a list of rules. Rules specify a path pattern and a list of capabilities (read, write, delete, list, encrypt, decrypt).

Path patterns support a single trailing wildcard. The pattern secrets/kv/prod/* matches all paths under secrets/kv/prod/ but not paths at a deeper level unless you use secrets/kv/prod/api/*.

Explicit deny rules override allow rules. If no rule matches a request, the default is deny. Services are assigned a policy by name at enrollment time.

Policy files can be reloaded at runtime by sending a SIGHUP signal to the Lockr process, or by calling the POST /v1/sys/policy/reload endpoint. No server restart is required.

An example policy:

  name: api-server

  rules:
    - path: "secrets/kv/prod/api/*"
      capabilities: [read]

    - path: "secrets/kv/prod/db/*"
      capabilities: [read]

    - path: "secrets/transit/payments-key"
      capabilities: [encrypt, decrypt]

    - path: "secrets/db/postgres/main"
      capabilities: [read]


---


AUDIT LOGGING

Every request is logged. This includes reads, writes, deletes, authentication attempts, enrollments, and revocations. The log entry records the identity of the caller, the authentication method used, the operation, the path, the source IP, the request ID, the result (allowed or denied), and the duration in milliseconds.

Secret values are never written to the audit log. Not in plaintext. Not encrypted. Never.

Audit entries are written to two places simultaneously: a queryable BadgerDB table (so you can filter by service, time range, or path using the API), and an append-only newline-delimited JSON flat file (audit.log). The flat file is never modified or truncated — only appended to.


---


INSTALLATION AND SETUP

Prerequisites: a Linux server or VM, Docker, or any environment that can run a Go binary. No other dependencies.

Step 1 — Download or build the binary.

  go build -o lockr ./cmd/lockr

Step 2 — Run first-time initialization.

  lockr init --data-dir /var/lib/lockr

This generates the master key, encrypts it with your passphrase, creates a self-signed CA and server certificate, and writes a starter config file to /etc/lockr/config.yml.

Step 3 — Start the server.

  LOCKR_PASSPHRASE=yourpassphrase lockr server

The server listens on port 8300 over HTTPS by default.

Step 4 — Create an admin token (first run only).

  lockr admin create --name=bootstrap --addr=https://localhost:8300

Save the token. You will need it for all admin operations.

Step 5 — Write your first secret.

  lockr set secrets/prod/stripe '{"key":"sk_live_abc123"}' \
    --addr https://localhost:8300 \
    --token <your-admin-token>

Step 6 — Enroll your application service.

  lockr enroll --service=api-server --auth=ed25519 --policy=api-server \
    --output=./certs \
    --addr https://localhost:8300 \
    --token <your-admin-token>

This generates an Ed25519 keypair and saves the private key to ./certs/api-server.key. The public key is registered in Lockr. Give the private key to your application.

Step 7 — Read the secret from your application.

  Go:
    c, _ := client.New(client.Options{
        Addr:        "https://lockr:8300",
        PrivKeyPath: "./certs/api-server.key",
        CAPath:      "./certs/ca.crt",
    })
    c.Authenticate(ctx, "api-server")
    secret, _ := c.KVGet(ctx, "secrets/prod/stripe", 0)
    fmt.Println(secret["key"])

  Python:
    vault = LockrClient("https://lockr:8300", key_path="./certs/api-server.key", ca_path="./certs/ca.crt")
    vault.authenticate("api-server")
    stripe = vault.kv_get("secrets/prod/stripe")
    print(stripe["key"])

  curl (dev mode only):
    curl http://localhost:8300/v1/secrets/kv/secrets/prod/stripe


---


DOCKER COMPOSE DEPLOYMENT

The recommended production deployment is Docker Compose.

  services:
    lockr:
      image: lockr:latest
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
      healthcheck:
        test: ["CMD", "lockr", "status", "--addr", "https://localhost:8300"]
        interval: 30s
        timeout: 5s
        retries: 3

    your-api:
      depends_on:
        lockr:
          condition: service_healthy
      volumes:
        - ./certs/your-api.key:/certs/client.key:ro
        - ./tls/ca.crt:/certs/ca.crt:ro
      environment:
        LOCKR_ADDR: "https://lockr:8300"
        LOCKR_KEY: "/certs/client.key"
        LOCKR_CA: "/certs/ca.crt"

  volumes:
    lockr_data:


---


CLI REFERENCE

All commands accept --addr (or LOCKR_ADDR env var), --token (or LOCKR_TOKEN), --ca (or LOCKR_CA), and --output json for machine-readable output.

  lockr server                         Start the server
    --config <path>                    Config file (default /etc/lockr/config.yml)
    --dev                              Dev mode

  lockr init                           First-time setup
    --data-dir <path>                  Data directory (default /var/lib/lockr)

  lockr enroll                         Register a service
    --service <name>
    --auth ed25519|totp
    --policy <name>
    --output <dir>                     Where to save the generated keypair

  lockr revoke --service <name>        Revoke a service immediately

  lockr get <path>                     Read a secret
    --version <N>                      Specific version (default latest)
    --field <key>                      Extract one JSON field

  lockr set <path> <json>              Write a secret

  lockr delete <path>                  Soft-delete a secret

  lockr list <path>                    List secrets at a path

  lockr transit encrypt <keyname>      Encrypt a value
    --plaintext <value>

  lockr transit decrypt <keyname>      Decrypt a value
    --ciphertext <value>

  lockr transit rotate <keyname>       Rotate a transit key

  lockr db creds <name>                Request dynamic database credentials

  lockr admin create --name <name>     Create an admin token

  lockr admin revoke --name <name>     Revoke an admin token

  lockr audit                          View audit log
    --service <name>
    --since <duration>                 e.g. 24h, 1h30m
    --path <prefix>
    --limit <N>

  lockr policy reload                  Reload policies from disk

  lockr status                         Health and status info

  lockr debug                          Show current identity and policy


---


API OVERVIEW

All endpoints are under /v1/. All responses use the envelope:
  {"data": {}, "error": null, "request_id": "..."}

Authentication endpoints (no token required):
  POST /v1/auth/challenge              Get a challenge for Ed25519 auth
  POST /v1/auth/verify                 Submit signed challenge, receive session token
  POST /v1/auth/totp                   TOTP login
  POST /v1/auth/admin/login            Admin token login

Authenticated endpoints:
  GET  /v1/auth/whoami                 Current identity and policy
  DELETE /v1/auth/session              Logout

  GET  /v1/secrets/kv/<path>           Read secret (add ?version=N for specific version)
  PUT  /v1/secrets/kv/<path>           Write secret
  DELETE /v1/secrets/kv/<path>         Soft-delete secret
  GET  /v1/secrets/kv/<path>/versions  List all versions
  GET  /v1/secrets/kv/<path>/          List secrets at path (directory listing)

  POST /v1/secrets/transit/<key>/create    Create a new transit key
  POST /v1/secrets/transit/<key>/encrypt   Encrypt plaintext
  POST /v1/secrets/transit/<key>/decrypt   Decrypt ciphertext
  POST /v1/secrets/transit/<key>/rotate    Rotate key
  GET  /v1/secrets/transit/<key>/info      Key metadata

  POST /v1/secrets/db/<name>/creds                    Request dynamic DB credentials
  DELETE /v1/secrets/db/<name>/creds/<lease_id>       Revoke before TTL
  GET  /v1/secrets/db/<name>/config                   View DB config
  PUT  /v1/secrets/db/<name>/config                   Write DB config

Admin-only endpoints:
  GET  /v1/sys/health                  Health check (unauthenticated)
  GET  /v1/sys/status                  Server status
  POST /v1/sys/enroll                  Enroll a service
  DELETE /v1/sys/revoke/<service>      Revoke a service
  GET  /v1/sys/audit                   Query audit log
  POST /v1/sys/admin/create            Create admin token
  DELETE /v1/sys/admin/<name>          Delete admin token
  POST /v1/sys/policy/reload           Reload policies


---


CONFIGURATION FILE

  server:
    addr: "0.0.0.0:8300"
    tls_cert: "/etc/lockr/tls/server.crt"
    tls_key: "/etc/lockr/tls/server.key"
    tls_ca: "/etc/lockr/tls/ca.crt"

  storage:
    data_dir: "/var/lib/lockr/data"
    master_key_path: "/var/lib/lockr/master.key.enc"

  audit:
    log_file: "/var/lib/lockr/audit.log"

  policy:
    dir: "/etc/lockr/policies"

  dynamic_secrets:
    credential_janitor_interval: "5m"

  session:
    ttl: "1h"
    max_ttl: "24h"

  log_level: "info"


---


DATA STORED ON DISK

  /var/lib/lockr/
  ├── data/               BadgerDB directory (all secrets, encrypted)
  ├── audit.log           Append-only audit log (newline-delimited JSON)
  ├── master.key.enc      Argon2id-protected master key
  └── config.yml          Server configuration

Policy files live separately at /etc/lockr/policies/ so they can be version-controlled independently from secret data.


---


ENVIRONMENT VARIABLES

  LOCKR_PASSPHRASE    Master key passphrase (required to start the server)
  LOCKR_ADDR          Server address for CLI commands
  LOCKR_KEY           Path to Ed25519 private key for CLI commands
  LOCKR_CA            Path to CA certificate for CLI commands
  LOCKR_TOKEN         Admin token for CLI commands


---


LANGUAGE SUPPORT

Lockr ships with client examples for Go, Python, and Node.js. Any HTTP client that supports Ed25519 signing works. The authentication flow is:

  1. POST /v1/auth/challenge with {"service": "<name>"}
     → receive a hex-encoded 32-byte challenge

  2. Sign the challenge bytes with your Ed25519 private key

  3. POST /v1/auth/verify with {"challenge": "<hex>", "signature": "<hex>"}
     → receive a session token

  4. Include the token as Authorization: Bearer <token> on all subsequent requests


---


WHAT LOCKR DOES NOT DO

Lockr intentionally excludes: cloud provider integrations (AWS, GCP, Azure), LDAP or OIDC authentication, external storage backends, replication or high availability, namespaces or multi-tenancy, a web UI, MySQL dynamic credentials, auto-rotation of static secrets, and any enterprise features. These are not planned. The goal is to remain small and operationally simple.


---


TECHNICAL DETAILS

Binary size: approximately 15MB statically compiled.
Default port: 8300.
Storage engine: BadgerDB (LSM-tree embedded key-value store).
Encryption: AES-256-GCM per secret, HKDF-SHA256 key derivation, Argon2id for passwords.
Auth crypto: Ed25519 (Go standard library), HMAC-SHA1 for TOTP (RFC 4226/6238).
TLS: version 1.3 minimum, self-signed CA generated on init.
IDs: ULID (lexicographically sortable, millisecond precision) for request IDs, audit entry IDs, and lease IDs.
Session tokens: lvt_ prefix, 32 random bytes, only the Argon2id hash is stored.
Admin tokens: lkat_ prefix, 32 random bytes, only the Argon2id hash is stored.
Go version: 1.24+.
License: open source.
