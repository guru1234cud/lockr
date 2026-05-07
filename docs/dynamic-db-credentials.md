# Dynamic DB Credentials

Dynamic database credentials are short-lived Postgres users created from stored admin connection config.

Use this when applications should receive temporary database credentials instead of a long-lived database password.

## Configure a DB Role

CLI support currently reads config:

```bash
lockr db config postgres-main \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

HTTP supports writing config:

```text
PUT /v1/secrets/db/<name>/config
```

Required policy capability for the route:

```text
write on secrets/db/<name>
```

The config type is implemented in `internal/secrets/db.go`.

## Read a DB Config Safely

```text
GET /v1/secrets/db/<name>/config
```

Required policy capability:

```text
read on secrets/db/<name>
```

The safe config response should avoid exposing sensitive connection secrets.

## Request Credentials

```bash
lockr db creds postgres-main \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
read on secrets/db/<name>
```

The response contains a temporary username/password lease.

## Revoke a Lease

HTTP route:

```text
DELETE /v1/secrets/db/<name>/creds/<lease-id>
```

Current gap: lease revocation currently exists but does not yet enforce a policy capability.

## Test a DB Config

HTTP route:

```text
POST /v1/secrets/db/<name>/test
```

Current gap: config test currently exists but does not yet enforce a policy capability.

## List Leases

HTTP route:

```text
GET /v1/secrets/db/<name>/creds
```

Current gap: lease listing currently exists but does not yet enforce a policy capability.

## Cleanup

In production mode, the server starts background cleanup work:

- A janitor periodically removes expired credentials.
- Startup reconciliation tries to clean orphaned Postgres users from previous downtime.
