FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /lockr ./cmd/lockr

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /lockr /usr/local/bin/lockr
EXPOSE 8300
ENTRYPOINT ["lockr"]
CMD ["server"]
