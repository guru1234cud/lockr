# Lockr

A self-hosted secrets manager written in Go. Single binary, embedded storage, no external dependencies at runtime.

Lockr stores secrets encrypted at rest, authenticates users with passwords and services with Ed25519 challenge-response, enforces policies, and writes a full audit log of every request.

---

## Features

- **KV secrets** — JSON values stored by path, encrypted at rest, up to 5 versions retained
- **Transit encryption** — encrypt and decrypt caller data using named keys without exposing key material
- **Dynamic DB credentials** — short-lived Postgres users created on demand, automatically cleaned up
- **User auth** — username + password login, Argon2id hashing, session tokens
- **Ed25519 service auth** — challenge-response flow, private key never leaves the service
- **Built-in policies** — `readonly`, `readwrite`, and `admin` require no YAML files
- **Custom YAML policies** — path + capability rules, wildcard matching, explicit deny override
- **Audit log** — every request logged with identity, method, path, status, and duration
- **TLS 1.3** — self-signed CA generated at init, clients verify with `ca.crt`
- **Single binary** — no Postgres, no Redis, no external dependencies

---

## Quickstart (dev mode)

Dev mode uses HTTP, in-memory storage, and no auth. For local testing only.

**1. Build**

```bash
git clone https://github.com/etherance/lockr.git
cd lockr
go build -o lockr ./cmd/lockr
```

**2. Start the server**

```bash
./lockr server --dev
```

**3. Write and read a secret**

```bash
./lockr set prod/api/db '{"password":"s3cr3t"}' --addr http://localhost:8300
./lockr get prod/api/db --addr http://localhost:8300
```

---

## Production Setup

**1. Initialize** (run once)

```bash
go build -o lockr ./cmd/lockr
sudo lockr init --data-dir /var/lib/lockr
# Save the lkat_... admin token that is printed
```

Init generates the master key, TLS certificates, config, and a first admin token. You will be prompted for a passphrase.

Fix directory permissions so non-root users can read the CA cert:

```bash
sudo chmod 755 /etc/lockr && sudo chmod 755 /etc/lockr/tls
```

**2. Start the server**

```bash
LOCKR_PASSPHRASE='<passphrase>' sudo lockr server --config /etc/lockr/config.yml
```

**3. Create a user**

```bash
lockr user create --username alice --policy readonly \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

**4. Login as that user**

```bash
lockr login --username alice --ca /etc/lockr/tls/ca.crt
# prompts for password → prints lvt_... session token
export LOCKR_TOKEN=lvt_...
```

**5. Read a secret**

```bash
lockr get prod/db-password --ca /etc/lockr/tls/ca.crt
```

---

## Service Auth

Services authenticate with Ed25519 keys, no password needed.

**Enroll a service**

```bash
lockr enroll \
  --service api-server \
  --policy readwrite \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
# saves api-server.key in the current directory
```

**Use from a service**

```bash
lockr get prod/api/db \
  --identity api-server \
  --key ./api-server.key \
  --ca /etc/lockr/tls/ca.crt
```

---

## Built-in Policies

No YAML files needed for common use cases:

| Policy | What it allows |
|---|---|
| `readonly` | read + list KV secrets |
| `readwrite` | read, write, delete KV + transit encrypt/decrypt |
| `admin` | full access to KV, transit, and DB engines |

A YAML file with the same name in the policy directory overrides the built-in.

---

## Custom Policy Example

```yaml
name: api-server

rules:
  - path: "secrets/kv/prod/api/*"
    capabilities: [read]

  - path: "secrets/transit/payments-key"
    capabilities: [encrypt, decrypt]
```

Place the file in `/etc/lockr/policies/`. Available capabilities: `read`, `write`, `delete`, `list`, `encrypt`, `decrypt`.

Reload policies without restarting:

```bash
lockr policy reload --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

---

## Docker

```bash
cd deployments

# Initialize (run once — creates master key and TLS certs)
docker compose build
docker run --rm -it \
  -v deployments_lockr_data:/var/lib/lockr \
  -v "$(pwd)/tls:/etc/lockr/tls" \
  lockr:local init --data-dir /var/lib/lockr

# Start
LOCKR_PASSPHRASE=<passphrase> docker compose up -d
```

---

## Go SDK

```go
import lockr "github.com/etherance/lockr/pkg/client"

c, err := lockr.New(lockr.Options{
    Addr:        "https://localhost:8300",
    CAPath:      "/etc/lockr/tls/ca.crt",
    PrivKeyPath: "./api-server.key",
})

if err := c.Authenticate(ctx, "api-server"); err != nil {
    panic(err)
}

secret, err := c.KVGet(ctx, "prod/api/db", 0)
```

See [`examples/`](./examples) for Go, Python, and Node.js examples.

---

## Testing

Run the end-to-end test suite against a live production server:

```bash
export LOCKR_TOKEN=<admin-token>
export LOCKR_CA=/etc/lockr/tls/ca.crt
./test/e2e.sh
```

The suite covers user login, service auth, permission enforcement, policy changes, password reset, user delete, service revoke, and audit logging. All test data uses an `e2e-` prefix and is cleaned up on exit.

---

## Documentation

| Guide | Description |
|---|---|
| [Install and Build](./docs/install-and-build.md) | Build the binary, run tests, start dev server |
| [Initialize the Server](./docs/initialize-server.md) | Generate master key, TLS certs, admin token, and config |
| [Run the Server](./docs/run-server.md) | Dev mode and production mode |
| [Configuration](./docs/configuration.md) | Every config field explained |
| [Authentication](./docs/authentication.md) | User login, admin tokens, Ed25519, TOTP, sessions |
| [Policies](./docs/policies.md) | Built-in policies, custom YAML, capabilities, and path matching |
| [KV Secrets](./docs/kv-secrets.md) | Write, read, version, and delete secrets |
| [Transit Encryption](./docs/transit-encryption.md) | Named key encryption without exposing keys |
| [Dynamic DB Credentials](./docs/dynamic-db-credentials.md) | Short-lived Postgres credentials |
| [Admin and Audit](./docs/admin-and-audit.md) | Manage users, services, admin tokens, and audit log |
| [API Reference](./docs/api-reference.md) | HTTP routes, auth requirements, and policy checks |
| [Client Usage](./docs/client-usage.md) | CLI flags, Go SDK, multi-language examples |
| [Deployment](./docs/deployment.md) | Docker Compose and production filesystem layout |
| [Development](./docs/development.md) | Code layout, commands, tests, and known gaps |

---

## Identity Types

| Prefix | Who | How they authenticate |
|---|---|---|
| `user:<name>` | Human operator | Username + password |
| `svc:<name>` | Application / service | Ed25519 private key |
| `admin:<name>` | System administrator | Admin token (`lkat_`) |

---

## Security

Lockr is a secrets manager. If you find a security vulnerability, **please do not open a public issue.** See [SECURITY.md](./SECURITY.md) for responsible disclosure.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to set up the project, run tests, and submit changes.

---

## License

MIT — see [LICENSE](./LICENSE).
