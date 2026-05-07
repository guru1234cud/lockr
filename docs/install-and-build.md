# Install and Build

Use this guide when you want to build Lockr, run tests, or start local development.

## Requirements

- Go installed locally.
- The repository checked out on the machine where you want to build.

Lockr is a Go application with a CLI entrypoint in `cmd/lockr`.

## Build Everything

```bash
go build ./...
```

This checks that all packages compile.

## Build the CLI Binary

```bash
go build -o lockr ./cmd/lockr
```

This creates a local `./lockr` binary.

The Makefile has the same shortcut:

```bash
make build
```

## Run Tests

```bash
go test ./...
```

If the Go build cache is not writable in your environment, use a cache under `/tmp`:

```bash
GOCACHE=/tmp/lockr-gocache go test ./...
```

## Run Static Checks

```bash
go vet ./...
```

If `golangci-lint` is installed:

```bash
make lint
```

## Start Local Dev Server

```bash
make dev
```

or:

```bash
./lockr server --dev
```

Dev mode uses HTTP, in-memory storage, no TLS, no auth enforcement, and the `root` policy.
