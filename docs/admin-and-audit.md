# Admin and Audit

Admin operations are for operators and automation. They require an admin token except for the first admin bootstrap.

## Create the First Admin

When no admin exists yet:

```bash
lockr admin create --name root \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Save the returned `lkat_...` token.

## Create Another Admin

```bash
lockr admin create --name ops \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <root-admin-token>
```

## Revoke an Admin

```bash
lockr admin revoke --name ops \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <root-admin-token>
```

## Enroll a Service

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

This creates a service auth record and attaches a policy name to the service.

## Revoke a Service

```bash
lockr revoke \
  --service api-server \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

## View Audit Logs

```bash
lockr audit \
  --since 24h \
  --limit 100 \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

Optional filters:

```bash
--service <identity>
--path <path-prefix>
--since 24h
--limit 100
```

## Audit Entry Fields

Audit entries include:

```text
timestamp
identity
auth_method
operation
path
source_ip
request_id
status
duration_ms
```

Status is recorded as `allowed` unless the HTTP response is `401 Unauthorized` or `403 Forbidden`.

## Check Identity

```bash
lockr debug \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

This returns the current identity, auth method, and policy.
