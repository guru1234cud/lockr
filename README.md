# Lockr

A self-hosted secrets manager written in Go. Single binary, embedded storage, no external dependencies at runtime.

Lockr stores secrets encrypted at rest, authenticates services with Ed25519 challenge-response, enforces YAML-defined policies, and writes a full audit log of every request.

---

## Features

- **KV secrets** — JSON values stored by path, encrypted at rest, up to 5 versions retained
- **Transit encryption** — encrypt and decrypt caller data using named keys without exposing key material
- **Dynamic DB credentials** — short-lived Postgres users created on demand, automatically cleaned up
- **Ed25519 service auth** — challenge-response flow, private key never leaves the service
- **YAML policies** — path + capability rules, wildcard matching, explicit deny override
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

**3. Create an admin token**

```bash
./lockr admin create --name root --addr http://localhost:8300
# returns: lkat_...
```

**4. Write and read a secret**

```bash
./lockr set prod/api/db '{"password":"s3cr3t"}' \
  --addr http://localhost:8300 \
  --token <admin-token>

./lockr get prod/api/db \
  --addr http://localhost:8300 \
  --token <admin-token>
```

---

## Production Setup

**1. Initialize** (run once)

```bash
sudo lockr init --data-dir /var/lib/lockr
```

Generates the master key, TLS certificates, and a starter config. You will be prompted for a passphrase — keep it safe.

**2. Start the server**

```bash
LOCKR_PASSPHRASE=<passphrase> lockr server --config /etc/lockr/config.yml
```

**3. Create the first admin token**

```bash
lockr admin create --name root \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

**4. Enroll a service**

```bash
lockr enroll \
  --service api-server \
  --auth ed25519 \
  --policy api-server \
  --output ./certs \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

**5. Use from a service**

```bash
lockr get prod/api/db \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
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

## Policy Example

Policies are YAML files in the configured policy directory:

```yaml
name: api-server

rules:
  - path: "secrets/kv/prod/api/*"
    capabilities: [read]

  - path: "secrets/transit/payments-key"
    capabilities: [encrypt, decrypt]
```

Available capabilities: `read`, `write`, `delete`, `list`, `encrypt`, `decrypt`.

Policies are loaded on startup and can be reloaded without a restart:

```bash
lockr policy reload --token <admin-token>
```

---

## Go SDK

```go
import "github.com/etherance/lockr/pkg/client"

c := client.New(client.Options{
    Addr:     "https://localhost:8300",
    CAFile:   "/etc/lockr/tls/ca.crt",
    Identity: "api-server",
    KeyFile:  "./certs/api-server.key",
})

value, err := c.Get(ctx, "prod/api/db")
```

See [`examples/`](./examples) for Go, Python, and Node.js examples.

---

## Documentation

| Guide | Description |
|---|---|
| [Install and Build](./docs/install-and-build.md) | Build the binary, run tests, start dev server |
| [Initialize the Server](./docs/initialize-server.md) | Generate master key, TLS certs, and config |
| [Run the Server](./docs/run-server.md) | Dev mode and production mode |
| [Configuration](./docs/configuration.md) | Every config field explained |
| [Authentication](./docs/authentication.md) | Admin tokens, Ed25519, TOTP, sessions |
| [Policies](./docs/policies.md) | Write, assign, reload, and debug policies |
| [KV Secrets](./docs/kv-secrets.md) | Write, read, version, and delete secrets |
| [Transit Encryption](./docs/transit-encryption.md) | Named key encryption without exposing keys |
| [Dynamic DB Credentials](./docs/dynamic-db-credentials.md) | Short-lived Postgres credentials |
| [Admin and Audit](./docs/admin-and-audit.md) | Manage admins, enroll services, view audit log |
| [API Reference](./docs/api-reference.md) | HTTP routes, auth requirements, policy checks |
| [Client Usage](./docs/client-usage.md) | CLI flags, Go SDK, multi-language examples |
| [Deployment](./docs/deployment.md) | Docker Compose and production filesystem layout |
| [Development](./docs/development.md) | Code layout, commands, tests, known gaps |

---

## Security

Lockr is a secrets manager. If you find a security vulnerability, **please do not open a public issue.** See [SECURITY.md](./SECURITY.md) for responsible disclosure.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to set up the project, run tests, and submit changes.

---

## License

MIT — see [LICENSE](./LICENSE).
