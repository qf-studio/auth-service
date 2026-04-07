# Auth Service

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![NIST SP 800-63-4](https://img.shields.io/badge/NIST-AAL2-blue)](https://pages.nist.gov/800-63-4/)

Authentication and authorization service for the **QuantFlow Studio** ecosystem. Serves two client types: **Users** (humans) and **Systems** (services + AI agents).

## Features

- **OAuth 2.1** with mandatory PKCE — no implicit or ROPC grants
- **JWT signing** with ES256 or EdDSA (asymmetric only)
- **Dual-port architecture** — public (`:4000`) and admin (`:4001`) with network-level isolation
- **Argon2id password hashing** (19 MiB memory, 2 iterations, HMAC pepper)
- **NIST SP 800-63-4 AAL2** password policy (15-char min, breached-password blocklist, no composition rules)
- **Token security** — prefixed tokens (`qf_at_`, `qf_rt_`, `qf_ac_`, `qf_ak_`), only signatures stored in DB
- **Rate limiting** with progressive delay and account lockout
- **DPoP** (Demonstrating Proof-of-Possession) token binding
- **MFA** — TOTP, WebAuthn, backup codes
- **Social login** — Google, GitHub, Apple via OAuth providers
- **OIDC provider** — OpenID Connect discovery and ID tokens
- **SAML SSO** — Service Provider integration
- **Multi-tenancy** — subdomain, header, or combined resolution
- **gRPC** admin interface (port `:4002`)

## Quick Start

```bash
# Start dependencies
docker-compose up -d postgres redis

# Run migrations
go run cmd/migrate/main.go up

# Start the service
source .env && go run cmd/server/main.go
```

The public API is available at `http://localhost:4000` and the admin API at `http://localhost:4001`.

## API Surface

OpenAPI specifications are in the [`api/`](./api/) directory:

| Spec | Description |
|------|-------------|
| [`public.openapi.yaml`](./api/public.openapi.yaml) | Public-facing auth endpoints (login, register, token, JWKS) |
| [`admin.openapi.yaml`](./api/admin.openapi.yaml) | Admin endpoints (user management, client management, audit) |

## Architecture

```
cmd/
├── server/main.go          # Bootstrap, DI, dual-port server
└── migrate/main.go         # Migration runner

internal/
├── config/                 # Env-based configuration
├── domain/                 # Core types: User, Client, Token, Role, Errors
├── auth/                   # Login, register, password hashing, reset
├── token/                  # JWT creation, validation, revocation, JWKS
├── middleware/             # Auth, rate limit, CORS, security headers
├── storage/               # PostgreSQL + Redis repositories
└── ...                    # See .agent/system/ for full architecture docs
```

Detailed architecture documentation is in [`.agent/system/`](./.agent/system/), including diagrams, security profile, and tech decisions.

## Configuration

All configuration is via environment variables. See [`internal/config/config.go`](./internal/config/config.go) for the full definition.

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | *(required)* | `development`, `staging`, or `production` |
| `PUBLIC_PORT` | `4000` | Public API port |
| `ADMIN_PORT` | `4001` | Admin API port |
| `GRPC_PORT` | `4002` | gRPC port |
| `LOG_LEVEL` | `info` | Log level |

### PostgreSQL

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | *(required)* | Database host |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_DB` | *(required)* | Database name |
| `POSTGRES_USER` | *(required)* | Database user |
| `POSTGRES_PASSWORD` | *(required)* | Database password |
| `POSTGRES_SSLMODE` | `disable` | SSL mode |
| `POSTGRES_MAX_CONNS` | `10` | Max connections |

### Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | *(required)* | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | *(empty)* | Redis password |
| `REDIS_DB` | `0` | Redis database number |

### JWT

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_PRIVATE_KEY_PATH` | *(required)* | Path to signing key |
| `JWT_ALGORITHM` | `ES256` | `ES256` or `EdDSA` |
| `ACCESS_TOKEN_TTL` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_TTL` | `7d` | Refresh token lifetime |
| `SYSTEM_SECRETS` | *(required)* | Comma-separated secrets (newest first) |

### Password Hashing (Argon2id)

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSWORD_PEPPER` | *(required)* | HMAC pepper |
| `ARGON2_MEMORY` | `19456` | Memory in KiB (19 MiB) |
| `ARGON2_TIME` | `2` | Iterations |
| `ARGON2_PARALLELISM` | `1` | Parallelism |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_RPS` | `50` | Requests per second |
| `RATE_LIMIT_BURST` | `100` | Burst size |
| `RATE_LIMIT_PROGRESSIVE_DELAY_AFTER` | `5` | Failed attempts before delay |
| `RATE_LIMIT_MAX_FAILED_ATTEMPTS` | `10` | Failed attempts before lockout |
| `RATE_LIMIT_LOCKOUT_DURATION` | `15m` | Lockout duration |

### TLS / CORS / Request Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_ENABLED` | `false` | Enable TLS |
| `CORS_ALLOWED_ORIGINS` | *(required)* | Comma-separated origins |
| `CORS_ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,OPTIONS` | Allowed HTTP methods |
| `CORS_ALLOWED_HEADERS` | `Authorization,Content-Type,X-Request-ID` | Allowed headers |
| `CORS_EXPOSE_HEADERS` | `X-Request-ID` | Exposed headers |
| `CORS_ALLOW_CREDENTIALS` | `false` | Allow credentials |
| `CORS_MAX_AGE` | `12h` | Preflight cache duration |
| `REQUEST_MAX_BODY_SIZE` | `1048576` | Max body size in bytes (1 MiB) |
| `REQUEST_TIMEOUT` | `30s` | Request timeout |

### Email

| Variable | Default | Description |
|----------|---------|-------------|
| `EMAIL_SERVICE_URL` | *(empty)* | Email service base URL |
| `EMAIL_API_KEY` | *(empty)* | Email service API key |
| `EMAIL_SENDER_ADDRESS` | *(empty)* | From address |
| `EMAIL_ENABLED` | `false` | Enable email delivery |

### DPoP

| Variable | Default | Description |
|----------|---------|-------------|
| `DPOP_ENABLED` | `false` | Enable DPoP binding |
| `DPOP_NONCE_TTL` | `5m` | Nonce lifetime |
| `DPOP_JTI_WINDOW` | `1m` | Replay detection window |

### MFA

| Variable | Default | Description |
|----------|---------|-------------|
| `MFA_ISSUER` | `QuantFlow Studio` | Authenticator app issuer |
| `MFA_DIGITS` | `6` | TOTP digits (6 or 8) |
| `MFA_PERIOD` | `30` | TOTP period in seconds |
| `MFA_BACKUP_CODE_COUNT` | `10` | Backup codes to generate |

### OAuth Providers

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_<PROVIDER>_ENABLED` | `false` | Enable provider (GOOGLE, GITHUB, APPLE) |
| `OAUTH_<PROVIDER>_CLIENT_ID` | *(required if enabled)* | OAuth client ID |
| `OAUTH_<PROVIDER>_CLIENT_SECRET` | *(required if enabled)* | OAuth client secret |
| `OAUTH_<PROVIDER>_REDIRECT_URI` | *(required if enabled)* | Redirect URI |
| `OAUTH_STATE_SECRET` | *(required if any enabled)* | HMAC key for state params |

### OIDC

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ISSUER_URL` | `http://localhost:4000` | Issuer identifier |
| `OIDC_ID_TOKEN_TTL` | `1h` | ID token lifetime |
| `OIDC_SUPPORTED_SCOPES` | `openid,profile,email,offline_access` | Supported scopes |

### SAML

| Variable | Default | Description |
|----------|---------|-------------|
| `SAML_ENABLED` | `false` | Enable SAML SSO |
| `SAML_ENTITY_ID` | *(required if enabled)* | SP entity ID |
| `SAML_ACS_URL` | *(required if enabled)* | Assertion Consumer Service URL |
| `SAML_KEY_PATH` | *(required if enabled)* | SP private key path |
| `SAML_CERT_PATH` | *(required if enabled)* | SP certificate path |

### Multi-Tenancy

| Variable | Default | Description |
|----------|---------|-------------|
| `TENANT_DEFAULT_ID` | *(empty)* | Fallback tenant ID |
| `TENANT_RESOLUTION_MODE` | `both` | `subdomain`, `header`, or `both` |
| `TENANT_BASE_DOMAIN` | *(empty)* | Base domain for subdomain parsing |
| `TENANT_CACHE_TTL` | `5m` | Tenant lookup cache TTL |

## Development

```bash
# Run all tests with race detection
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Lint
golangci-lint run

# Build
go build -o bin/auth-service cmd/server/main.go
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.24+ |
| HTTP Framework | Gin |
| Database | PostgreSQL (pgx/v5) |
| Cache | Redis (go-redis/v9) |
| JWT | ES256 / EdDSA |
| Password Hashing | Argon2id |
| Logging | zap |
| Containerization | Docker (Alpine, multi-stage) |

## Project Status

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 — MVP | Scaffold, auth, tokens, RBAC, middleware, integration | In Progress |
| Phase 2 — Production | MFA, WebAuthn, social login, DPoP, gRPC, audit | Planned |
| Phase 3 — Enterprise | Multi-tenancy, SAML, webhooks, GDPR | Planned |

## Built with Pilot

This project is developed with [Pilot](https://github.com/qf-studio/pilot), an autonomous execution agent that implements GitHub issues end-to-end.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, code style, and PR guidelines.

## License

[MIT](./LICENSE) — Copyright (c) 2026 QuantFlow Studio
