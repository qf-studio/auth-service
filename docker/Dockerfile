# Multi-stage Dockerfile for auth-service
# Stage 1: Build with Go toolchain
# Stage 2: Minimal Alpine runtime

# ---------- builder ----------
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
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 appuser \
    && adduser -u 1000 -G appuser -D -h /home/appuser appuser

COPY --from=builder /bin/auth-service /auth-service
COPY --from=builder --chown=appuser:appuser /bin/auth-migrate /auth-migrate

# Public API + Admin API
EXPOSE 4000 4001

USER appuser:appuser

ENTRYPOINT ["/auth-service"]
