# KV Secrets

KV secrets store JSON values at paths.

The server encrypts secret records before writing them to BadgerDB. KV secrets keep up to ten retained versions.

## Write a Secret

```bash
lockr set prod/api/db '{"username":"api","password":"secret"}' \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
write on secrets/kv/prod/api/db
```

## Read a Secret

```bash
lockr get prod/api/db \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
read on secrets/kv/prod/api/db
```

## Read One Field

```bash
lockr get prod/api/db --field password \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

## Read a Specific Version

```bash
lockr get prod/api/db --version 2 \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Version `0` means latest.

## List Secrets

```bash
lockr list prod/api \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
list on secrets/kv/prod/api/
```

## Delete a Secret

```bash
lockr delete prod/api/db \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
delete on secrets/kv/prod/api/db
```

Delete is currently a soft delete in metadata. Restore and purge APIs are not implemented.

## List All Versions

```bash
lockr versions prod/api/db \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Output:

```
VERSION    CREATED AT
------------------------------------------
1          2026-05-10T09:00:00Z
2          2026-05-16T14:30:00Z   ← current
```

## Roll Back to an Old Version

Promotes an old version as a new write — it becomes the new current version. History is never deleted.

```bash
lockr rollback prod/api/db --to 1 \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
write on secrets/kv/prod/api/db
```

## HTTP Routes

```text
GET    /v1/secrets/kv/<path>
PUT    /v1/secrets/kv/<path>
DELETE /v1/secrets/kv/<path>
GET    /v1/secrets/kv/<path>/
GET    /v1/secrets/kv/<path>/versions
POST   /v1/secrets/kv/<path>/rollback    body: {"version": N}
```
