# Transit Encryption

Transit encryption lets callers encrypt and decrypt data using a named server-side key. The key material is not returned to the caller.

Use transit when an application needs encryption as a service but should not own the encryption key.

## Create a Transit Key

HTTP route:

```text
POST /v1/secrets/transit/<keyname>/create
```

The current CLI exposes encrypt, decrypt, and rotate commands. Key creation is available through the API handler.

Current gap: the create route does not yet enforce a policy capability.

## Encrypt Data

```bash
lockr transit encrypt payments-key \
  --plaintext "card-token-123" \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
encrypt on secrets/transit/payments-key
```

## Decrypt Data

```bash
lockr transit decrypt payments-key \
  --ciphertext <ciphertext> \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Required policy capability:

```text
decrypt on secrets/transit/payments-key
```

## Rotate a Transit Key

```bash
lockr transit rotate payments-key \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Current gap: rotate currently exists but does not yet enforce a policy capability.

## Inspect Key Info

HTTP route:

```text
POST /v1/secrets/transit/<keyname>/info
```

Current gap: info currently exists but does not yet enforce a policy capability.

## HTTP Routes

```text
POST /v1/secrets/transit/<keyname>/create
POST /v1/secrets/transit/<keyname>/encrypt
POST /v1/secrets/transit/<keyname>/decrypt
POST /v1/secrets/transit/<keyname>/rotate
POST /v1/secrets/transit/<keyname>/info
```
