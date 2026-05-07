# Client Usage

Lockr can be used through:

- The `lockr` CLI.
- The Go SDK in `pkg/client`.
- Example clients in `examples/`.

## CLI Global Flags

Common flags:

```text
--addr      Lockr server address
--ca        CA certificate path
--token     admin token or direct bearer token
--identity  service identity for Ed25519 auth
--key       service private key path
--output    text or json
```

Environment variables:

```text
LOCKR_ADDR
LOCKR_CA
LOCKR_TOKEN
LOCKR_SERVICE
LOCKR_KEY
```

## Admin CLI Usage

Admin commands use `--token`:

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

## Service CLI Usage

Service commands can use Ed25519 auth:

```bash
lockr get prod/api/db \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

Or they can use an existing bearer/admin token:

```bash
lockr get prod/api/db \
  --token <token> \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

## JSON Output

```bash
lockr get prod/api/db --output json \
  --identity api-server \
  --key ./certs/api-server.key
```

## Go SDK

Basic shape:

```go
package main

import (
	"context"
	"fmt"

	lockr "github.com/etherance/lockr/pkg/client"
)

func main() {
	ctx := context.Background()

	c, err := lockr.New(lockr.Options{
		Addr:        "https://localhost:8300",
		PrivKeyPath: "./certs/api-server.key",
		CAPath:      "/etc/lockr/tls/ca.crt",
	})
	if err != nil {
		panic(err)
	}

	if err := c.Authenticate(ctx, "api-server"); err != nil {
		panic(err)
	}

	secret, err := c.KVGet(ctx, "prod/api/db", 0)
	if err != nil {
		panic(err)
	}

	fmt.Println(secret)
}
```

See:

```text
examples/go/main.go
examples/nodejs/lockr_example.js
examples/python/lockr_example.py
```

## TLS Note

For production-style usage, always provide `--ca` or `CAPath`. The current CLI falls back to insecure verification when no CA path is provided.
