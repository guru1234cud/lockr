# Configuration

Lockr reads YAML configuration from:

```text
/etc/lockr/config.yml
```

You can pass a different path:

```bash
lockr server --config ./config.yml
```

Use `config.example.yml` as the reference.

## Server

```yaml
server:
  addr: "0.0.0.0:8300"
  tls_cert: "/etc/lockr/tls/server.crt"
  tls_key: "/etc/lockr/tls/server.key"
  tls_ca: "/etc/lockr/tls/ca.crt"
```

- `addr`: host and port the server listens on.
- `tls_cert`: server certificate path.
- `tls_key`: server private key path.
- `tls_ca`: CA certificate distributed to clients.

Production mode requires TLS certificate and key files.

## Storage

```yaml
storage:
  data_dir: "/var/lib/lockr/data"
  master_key_path: "/var/lib/lockr/master.key.enc"
```

- `data_dir`: BadgerDB directory.
- `master_key_path`: encrypted master key file.

The server unlocks the master key using `LOCKR_PASSPHRASE`.

## Audit

```yaml
audit:
  log_file: "/var/lib/lockr/audit.log"
```

The audit logger writes request information such as identity, auth method, path, source IP, request ID, status, and duration.

## Policy

```yaml
policy:
  dir: "/etc/lockr/policies"
```

This directory contains YAML policy files. Policies are loaded into memory on startup and reload.

## Dynamic Secrets

```yaml
dynamic_secrets:
  credential_janitor_interval: "5m"
```

This controls how often Lockr checks and cleans expired dynamic database credential leases.

## Session

```yaml
session:
  ttl: "1h"
  max_ttl: "24h"
```

- `ttl`: default session token lifetime.
- `max_ttl`: maximum intended session lifetime.

## Log Level

```yaml
log_level: "info"
```

Supported values are intended to be:

```text
debug
info
warn
error
```
