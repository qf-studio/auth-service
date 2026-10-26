# Multi-stage Dockerfile for auth-service
# Stage 1: Build with Go toolchain
# Stage 2: Minimal Alpine runtime

# ---------- builder ----------
# golang:1.26.10-alpine (multi-arch index digest); bump tag and digest together
FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /bin/auth-service ./cmd/server
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /bin/auth-migrate ./cmd/migrate

# ---------- runtime ----------
# alpine:3.21 (multi-arch index digest); bump tag and digest together
FROM alpine:3.21@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 appuser \
    && adduser -u 1000 -G appuser -D -h /home/appuser appuser

COPY --from=builder /bin/auth-service /auth-service
COPY --from=builder --chown=appuser:appuser /bin/auth-migrate /auth-migrate

# Public API + Admin API
EXPOSE 4000 4001

USER appuser:appuser

ENTRYPOINT ["/auth-service"]
