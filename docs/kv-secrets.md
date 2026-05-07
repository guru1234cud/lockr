# KV Secrets

KV secrets store JSON values at paths.

The server encrypts secret records before writing them to BadgerDB. KV secrets keep up to five retained versions.

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

## HTTP Routes

```text
GET    /v1/secrets/kv/<path>
PUT    /v1/secrets/kv/<path>
DELETE /v1/secrets/kv/<path>
GET    /v1/secrets/kv/<path>/
GET    /v1/secrets/kv/<path>/versions
```
