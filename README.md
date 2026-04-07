# Auth Service

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Security: NIST AAL2](https://img.shields.io/badge/Security-NIST%20AAL2-green)](https://pages.nist.gov/800-63-4/)

## About

Authentication and authorization service for the [QuantFlow Studio](https://quantflow.studio) ecosystem. Serves two client types: **Users** (humans) and **Systems** (services and AI agents). Built for internal-first use with a path to third-party OAuth2/OIDC in Phase 2.

## Features

- **OAuth 2.1** — Mandatory PKCE, no implicit or ROPC grants
- **JWT signing** — ES256 and EdDSA (asymmetric only)
- **Token security** — Prefixed tokens (`qf_at_`, `qf_rt_`, `qf_ac_`, `qf_ak_`), store only signatures in DB
- **Password hashing** — Argon2id (19 MiB / 2 iterations / 1 thread), HMAC pepper, 128-bit salt
- **NIST password policy** — 15-char minimum, no composition rules, no forced rotation, breached-password blocklist
- **Dual-port architecture** — Public (4000) + Admin (4001) with network-level isolation
- **Rate limiting** — Per-endpoint with progressive delay and account lockout
- **DPoP** — Demonstrating Proof-of-Possession token binding
- **MFA** — TOTP, WebAuthn, backup codes (Phase 2)
- **Social login** — Google, GitHub, Apple via OAuth (Phase 2)
- **OIDC provider** — OpenID Connect discovery and ID tokens (Phase 2)
- **SAML SSO** — Service Provider mode (Phase 3)
- **Multi-tenancy** — Subdomain and header-based tenant resolution (Phase 3)
- **RBAC** — Role-based access control with Casbin integration (Phase 2)

## Quick Start

```bash
# Prerequisites: Go 1.24+, Docker, Docker Compose

# Start dependencies
docker-compose up -d postgres redis

# Configure environment
cp .env.example .env   # edit with your values

# Run migrations
go run cmd/migrate/main.go up

# Start the service
source .env && go run cmd/server/main.go
```

The public API is available at `http://localhost:4000` and the admin API at `http://localhost:4001`.

## API Surface

| Endpoint Group | Port | Description |
|---|---|---|
| `POST /auth/register` | 4000 | User registration |
| `POST /auth/login` | 4000 | User login |
| `POST /auth/token` | 4000 | OAuth2 token exchange |
| `POST /auth/token/refresh` | 4000 | Refresh token rotation |
| `POST /auth/token/revoke` | 4000 | Token revocation |
| `GET /.well-known/jwks.json` | 4000 | JWKS public keys |
| `GET /.well-known/openid-configuration` | 4000 | OIDC discovery |
| `POST /admin/clients` | 4001 | Client management |
| `GET /admin/users` | 4001 | User management |
| `GET /health` | 4000 | Health check |

Full API documentation is available in [`api/`](./api/).

## Architecture

```
┌─────────────┐     ┌─────────────┐
│  Public :4000│     │  Admin :4001│
└──────┬──────┘     └──────┬──────┘
       │                   │
       └────────┬──────────┘
                │
        ┌───────┴───────┐
        │   Middleware   │
        │ (auth, rate,  │
        │  CORS, TLS)   │
        └───────┬───────┘
                │
     ┌──────────┼──────────┐
     │          │          │
 ┌───┴───┐ ┌───┴───┐ ┌───┴───┐
 │ Auth  │ │ Token │ │ User  │
 │Service│ │Service│ │Service│
 └───┬───┘ └───┬───┘ └───┬───┘
     │         │         │
     └────┬────┘─────────┘
          │
   ┌──────┴──────┐
   │  PostgreSQL  │──── Persistent storage
   │    Redis     │──── Sessions, rate limits, caches
   └─────────────┘
```

For detailed architecture diagrams, see [`.agent/system/architecture-diagrams.md`](./.agent/system/architecture-diagrams.md).

## Configuration

All configuration is via environment variables. See [`internal/config/config.go`](./internal/config/config.go) for the full source.

### Required Variables

| Variable | Description |
|---|---|
| `APP_ENV` | Environment: `development`, `staging`, or `production` |
| `POSTGRES_HOST` | PostgreSQL host |
| `POSTGRES_DB` | PostgreSQL database name |
| `POSTGRES_USER` | PostgreSQL user |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `REDIS_HOST` | Redis host |
| `JWT_PRIVATE_KEY_PATH` | Path to JWT signing key (ES256 or EdDSA) |
| `SYSTEM_SECRETS` | Comma-separated secrets for system token signing (newest first) |
| `PASSWORD_PEPPER` | HMAC pepper for password hashing |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed origins |

### Optional Variables

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_PORT` | `4000` | Public API port |
| `ADMIN_PORT` | `4001` | Admin API port |
| `GRPC_PORT` | `4002` | gRPC port |
| `LOG_LEVEL` | `info` | Log level |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_SSLMODE` | `disable` | PostgreSQL SSL mode |
| `POSTGRES_MAX_CONNS` | `10` | Max database connections |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | _(empty)_ | Redis password |
| `REDIS_DB` | `0` | Redis database number |
| `JWT_ALGORITHM` | `ES256` | JWT algorithm (`ES256` or `EdDSA`) |
| `ACCESS_TOKEN_TTL` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_TTL` | `7d` | Refresh token lifetime |
| `ARGON2_MEMORY` | `19456` | Argon2 memory in KiB |
| `ARGON2_TIME` | `2` | Argon2 iterations |
| `ARGON2_PARALLELISM` | `1` | Argon2 parallelism |
| `RATE_LIMIT_RPS` | `50` | Requests per second |
| `RATE_LIMIT_BURST` | `100` | Burst allowance |
| `RATE_LIMIT_PROGRESSIVE_DELAY_AFTER` | `5` | Failed attempts before progressive delay |
| `RATE_LIMIT_MAX_FAILED_ATTEMPTS` | `10` | Failed attempts before lockout |
| `RATE_LIMIT_LOCKOUT_DURATION` | `15m` | Lockout duration |
| `TLS_ENABLED` | `false` | Enable TLS |
| `REQUEST_MAX_BODY_SIZE` | `1048576` | Max request body (bytes) |
| `REQUEST_TIMEOUT` | `30s` | Request timeout |
| `EMAIL_ENABLED` | `false` | Enable email delivery |
| `EMAIL_SERVICE_URL` | _(empty)_ | Email service base URL |
| `EMAIL_API_KEY` | _(empty)_ | Email service API key |
| `EMAIL_SENDER_ADDRESS` | _(empty)_ | From address |
| `DPOP_ENABLED` | `false` | Enable DPoP |
| `DPOP_NONCE_TTL` | `5m` | DPoP nonce lifetime |
| `DPOP_JTI_WINDOW` | `1m` | DPoP replay window |
| `MFA_ISSUER` | `QuantFlow Studio` | TOTP issuer label |
| `MFA_DIGITS` | `6` | TOTP digits (6 or 8) |
| `MFA_PERIOD` | `30` | TOTP period in seconds |
| `MFA_BACKUP_CODE_COUNT` | `10` | Backup codes to generate |
| `OIDC_ISSUER_URL` | `http://localhost:4000` | OIDC issuer URL |
| `OIDC_ID_TOKEN_TTL` | `1h` | ID token lifetime |
| `OIDC_SUPPORTED_SCOPES` | `openid,profile,email,offline_access` | Supported OIDC scopes |
| `TENANT_DEFAULT_ID` | _(empty)_ | Default tenant ID |
| `TENANT_RESOLUTION_MODE` | `both` | `subdomain`, `header`, or `both` |
| `TENANT_BASE_DOMAIN` | _(empty)_ | Base domain for subdomain resolution |
| `TENANT_CACHE_TTL` | `5m` | Tenant lookup cache TTL |

## Development

```bash
# Run all tests
go test ./...

# Tests with race detection and coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Lint
golangci-lint run

# Build
go build -o bin/auth-service cmd/server/main.go
```

## Tech Stack

| Component | Technology |
|---|---|
| Language | Go 1.24+ |
| HTTP framework | Gin |
| Database | PostgreSQL (pgx/v5) |
| Cache / sessions | Redis (go-redis/v9) |
| JWT signing | ES256 / EdDSA |
| Password hashing | Argon2id |
| Logging | zap |
| Containerization | Docker (multi-stage, Alpine) |

## Project Status

**Phase 1 (MVP)** — Core authentication, token management, user/client CRUD, RBAC basics

**Phase 2 (Production)** — MFA, WebAuthn, social login, DPoP, gRPC, OIDC provider, audit logging

**Phase 3 (Enterprise)** — Multi-tenancy, SAML SSO, webhooks, GDPR compliance

## Built with Pilot

This project is developed with [Pilot](https://github.com/qf-studio/pilot) — an autonomous AI execution bot that implements GitHub issues, writes code, and opens pull requests.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, code style, commit format, and PR guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
