# Security Policy

## Reporting a Vulnerability

Lockr is a secrets manager. Security issues are taken seriously.

**Please do not report security vulnerabilities through public GitHub issues.**

Report vulnerabilities privately by emailing:

**neuxdemorphous@gmail.com**

Include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- The version or commit hash you tested against
- Any proof-of-concept code or output (if safe to share)

You will receive an acknowledgement within **48 hours** and a more detailed response within **7 days** describing next steps.

Please give us reasonable time to investigate and release a fix before any public disclosure. We will credit you in the release notes unless you prefer to remain anonymous.

---

## Scope

The following are in scope for security reports:

- Authentication bypass or token forgery
- Policy enforcement bypass (access to secrets without the required capability)
- Plaintext secrets leaking through logs, API responses, or error messages
- Master key or session token exposure
- Cryptographic weaknesses in storage encryption or key derivation
- SSRF or network probing through DB credential endpoints
- Privilege escalation from service token to admin-level access

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report those upstream)
- Issues requiring physical access to the server
- Denial of service without a significant security impact
- Issues already documented as known gaps in [PRODUCT.md](./PRODUCT.md)

---

## Known Limitations

The following are documented gaps in the current implementation. They are not eligible for a bounty but patches are welcome:

- CLI TLS verification is silently skipped when `--ca` is not provided (a warning is printed)
- Mutual TLS client certificate authentication is not implemented
- KV restore and purge after soft-delete are not implemented
- Master key canary verification is not implemented
- Test coverage is limited in API handlers and secret engines

See [docs/development.md](./docs/development.md) for the full list.

---

## Security Model Summary

| Layer | Mechanism |
|---|---|
| Transport | TLS 1.3, self-signed CA generated at init |
| Encryption at rest | AES-256-GCM, per-record keys derived via HKDF-SHA256 |
| Master key protection | Argon2id key derivation from passphrase, AES-256-GCM encrypted on disk |
| Service authentication | Ed25519 challenge-response, one-time-use challenges |
| Session tokens | 32-byte random, Argon2id hashed before storage, TTL enforced |
| Admin tokens | 32-byte random, Argon2id hashed before storage |
| Authorization | YAML policies, deny-by-default, explicit deny overrides allow |
| Audit | Every authenticated request logged with identity, path, status, and duration |

For the full security model see [PRODUCT.md](./PRODUCT.md).
