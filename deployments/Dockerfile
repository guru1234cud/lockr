FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /lockr ./cmd/lockr

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
	&& addgroup -S -g 10001 lockr \
	&& adduser -S -D -H -u 10001 -h /var/lib/lockr -s /sbin/nologin -G lockr lockr \
	&& mkdir -p /var/lib/lockr/data /etc/lockr/policies /etc/lockr/tls \
	&& chown -R lockr:lockr /var/lib/lockr /etc/lockr
COPY --from=builder /lockr /usr/local/bin/lockr
USER lockr
EXPOSE 8300
ENTRYPOINT ["lockr"]
CMD ["server", "--config", "/etc/lockr/config.yml"]
