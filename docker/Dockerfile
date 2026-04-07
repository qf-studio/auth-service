# Multi-stage Dockerfile for auth-service
# Stage 1: Build with Go toolchain
# Stage 2: Minimal Alpine runtime

# ---------- builder ----------
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /bin/auth-service ./cmd/server

# ---------- runtime ----------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 appuser \
    && adduser -u 1000 -G appuser -D -h /home/appuser appuser

COPY --from=builder /bin/auth-service /auth-service

# Public API + Admin API
EXPOSE 4000 4001

USER appuser:appuser

ENTRYPOINT ["/auth-service"]
