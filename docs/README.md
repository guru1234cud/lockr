# Lockr Documentation

Lockr is a self-hosted secrets manager written in Go. It stores secrets in embedded BadgerDB, encrypts secret values at rest, authenticates users and services, enforces policies, and writes audit logs.

This documentation is organized by task so operators and developers can jump directly to what they need.

## Task Guides

- [Install and Build](./install-and-build.md): build the binary, run tests, and start local development.
- [Initialize the Server](./initialize-server.md): generate the master key, TLS certificates, admin token, and config.
- [Run the Server](./run-server.md): start Lockr in dev mode or production mode.
- [Configuration](./configuration.md): understand every config section.
- [Authentication](./authentication.md): user login, admin tokens, service Ed25519 auth, sessions, and dev mode.
- [Policies](./policies.md): built-in policies, custom YAML policies, capabilities, and path matching.
- [KV Secrets](./kv-secrets.md): write, read, list, version, and delete KV secrets.
- [Transit Encryption](./transit-encryption.md): encrypt and decrypt data without exposing key material.
- [Admin and Audit](./admin-and-audit.md): manage users, services, admin tokens, and audit logs.
- [API Reference](./api-reference.md): HTTP routes, auth requirements, and policy checks.
- [Client Usage](./client-usage.md): CLI, user login, service auth, Go SDK, and examples.
- [Deployment](./deployment.md): Docker Compose and production layout.
- [Development](./development.md): code layout, commands, tests, and known gaps.

## Quick Start (Production)

```bash
# 1. Build
go build -o lockr ./cmd/lockr

# 2. Initialize — creates master key, TLS, config, and first admin token
sudo lockr init --data-dir /var/lib/lockr
# Save the lkat_... token printed

# 3. Fix permissions
sudo chmod 755 /etc/lockr && sudo chmod 755 /etc/lockr/tls

# 4. Start the server
LOCKR_PASSPHRASE='<passphrase>' sudo lockr server --config /etc/lockr/config.yml

# 5. Create a user (built-in policies — no files needed)
lockr user create --username alice --policy readonly \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt

# 6. Login as that user
lockr login --username alice --ca /etc/lockr/tls/ca.crt

# 7. Use secrets
lockr get prod/db-password --token <lvt_token> --ca /etc/lockr/tls/ca.crt
```

## Built-in Policies

No YAML files needed for common use cases:

| Policy | What it allows |
|---|---|
| `readonly` | read + list KV secrets |
| `readwrite` | read, write, delete KV + transit encrypt/decrypt |
| `admin` | full access to all secret engines |

## Identity Types

| Prefix | Who | How they authenticate |
|---|---|---|
| `user:<name>` | Human operator | Username + password |
| `svc:<name>` | Application / service | Ed25519 private key |
| `admin:<name>` | System administrator | Admin token (`lkat_`) |

## Important Defaults

```text
Server address:     https://localhost:8300
Dev server:         http://localhost:8300
Config path:        /etc/lockr/config.yml
Policy directory:   /etc/lockr/policies
Data directory:     /var/lib/lockr/data
Master key:         /var/lib/lockr/master.key.enc
CA certificate:     /etc/lockr/tls/ca.crt
```

## Security Notes

- Dev mode bypasses all authentication and grants `root`. Never use it in production.
- Production mode requires `LOCKR_PASSPHRASE` at startup to unlock the encrypted master key.
- Always pass `--ca /etc/lockr/tls/ca.crt` to clients. Without it, TLS verification is disabled.
- Back up `/var/lib/lockr/master.key.enc` and the passphrase separately — both are required to recover secrets.
- The admin token from `lockr init` is shown once. Store it securely and rotate it after initial setup.
- Transit routes still need stricter policy enforcement. See [Development](./development.md).
