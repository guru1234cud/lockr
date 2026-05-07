# Initialize the Server

Use this guide for first-time production-style setup.

## What Initialization Creates

`lockr init` creates:

- An encrypted master key at `master.key.enc`.
- A BadgerDB data directory.
- TLS certificate files under `/etc/lockr/tls`.
- A starter config file at `/etc/lockr/config.yml` when one does not already exist.
- A policy directory at `/etc/lockr/policies`.

## Run Initialization

```bash
lockr init --data-dir /var/lib/lockr
```

The command asks for a passphrase. That passphrase protects the master key.

## Files Created

Typical paths:

```text
/var/lib/lockr/master.key.enc
/var/lib/lockr/data/
/etc/lockr/config.yml
/etc/lockr/tls/ca.crt
/etc/lockr/tls/ca.key
/etc/lockr/tls/server.crt
/etc/lockr/tls/server.key
/etc/lockr/policies/
```

## Master Key Behavior

Lockr encrypts secrets with keys derived from the master key. The master key is encrypted on disk and unlocked at server startup using:

```bash
LOCKR_PASSPHRASE=<passphrase>
```

Do not commit `master.key.enc`, private keys, or TLS private keys.

## TLS Behavior

The generated CA signs the server certificate. Clients should use the CA certificate to verify the server:

```bash
--ca /etc/lockr/tls/ca.crt
```

The current implementation does not use mutual TLS client certificates.
