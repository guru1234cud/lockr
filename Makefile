BINARY  := lockr
PKG     := github.com/etherance/lockr/cmd/lockr

.PHONY: build test vet lint clean dev

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY)

dev: build
	./$(BINARY) server --dev
