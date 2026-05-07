# Lockr Documentation

Lockr is a self-hosted secrets manager written in Go. It stores secrets in embedded BadgerDB, encrypts secret values at rest, authenticates services, checks policies, and writes audit logs.

This documentation is organized by task so operators and developers can jump directly to the work they need to do.

## Task Guides

- [Install and Build](./install-and-build.md): build the binary, run tests, and start local development.
- [Initialize the Server](./initialize-server.md): generate the master key, TLS certificates, and config.
- [Run the Server](./run-server.md): start Lockr in dev mode or production mode.
- [Configuration](./configuration.md): understand every config section.
- [Authentication](./authentication.md): understand admin tokens, service auth, sessions, and dev mode.
- [Policies](./policies.md): create, assign, reload, and debug access policies.
- [KV Secrets](./kv-secrets.md): write, read, list, version, and delete KV secrets.
- [Transit Encryption](./transit-encryption.md): encrypt and decrypt data without exposing key material.
- [Dynamic DB Credentials](./dynamic-db-credentials.md): configure and request short-lived Postgres credentials.
- [Admin and Audit](./admin-and-audit.md): manage admins, enroll services, revoke access, and read audit logs.
- [API Reference](./api-reference.md): HTTP routes, auth requirements, and policy checks.
- [Client Usage](./client-usage.md): use the CLI, Go SDK, and examples.
- [Deployment](./deployment.md): Docker Compose and production layout.
- [Development](./development.md): code layout, commands, tests, and known gaps.

## Important Defaults

- Default server address: `https://localhost:8300`
- Dev server address: `http://localhost:8300`
- Default config path: `/etc/lockr/config.yml`
- Default policy directory: `/etc/lockr/policies`
- Default data directory: `/var/lib/lockr/data`
- Default master key path: `/var/lib/lockr/master.key.enc`

## Security Notes

- Dev mode bypasses authentication and grants the `root` policy. Use it only for local testing.
- Production mode requires `LOCKR_PASSPHRASE` to unlock the encrypted master key.
- Clients should pass `--ca /etc/lockr/tls/ca.crt` in production-style runs.
- Policy rules are stored on the server filesystem, not in the client and not in BadgerDB.
- Some sensitive DB and transit routes still need stricter policy enforcement. See [Development](./development.md).
