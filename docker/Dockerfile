# Multi-stage Dockerfile for auth-service
# Stage 1: Build with Go toolchain
# Stage 2: Minimal distroless runtime

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
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /bin/auth-service /auth-service

# Public API + Admin API
EXPOSE 4000 4001

USER nonroot:nonroot

ENTRYPOINT ["/auth-service"]
