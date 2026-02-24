# Project Architecture

**Updated**: 2026-02-24

## Tech Stack

| Component | Choice | Version |
|---|---|---|
| Language | Go | 1.24+ |
| HTTP Framework | Gin | latest |
| Database | PostgreSQL | 16+ |
| DB Driver | pgx/v5 | latest |
| Cache / Sessions | Redis | 7.x |
| Redis Client | go-redis/v9 | latest |
| JWT | golang-jwt/jwt/v5 | latest |
| Password Hashing | Argon2id | golang.org/x/crypto/argon2 |
| Logging | zap | go.uber.org/zap |
| Migrations | golang-migrate | latest |
| Validation | go-playground/validator/v10 | latest |
| Rate Limiting | golang.org/x/time/rate + Redis | latest |

## Architecture Principles

### From Email-Service (Proven Patterns)
- **Clean Architecture**: `cmd/` + `internal/` separation
- **Interface-driven**: All major components behind interfaces
- **Factory pattern**: For pluggable implementations
- **Env-based config**: No config files, env vars only
- **Middleware stack**: security → metrics → validation → handlers
- **Structured logging**: zap singleton, environment-aware
- **Multi-stage Docker**: Alpine, non-root user, ca-certificates

### From Ory Hydra (Adopted Patterns)
- **Dual-port API**: Public (4000) + Admin (4001) on separate ports
- **Token signatures only**: Store `key.signature` in DB, not full tokens
- **Token prefixes**: `qf_at_` (access), `qf_rt_` (refresh), `qf_ac_` (auth code)
- **System secret array**: Zero-downtime rotation (newest first, try older for verification)
- **Per-client config**: Token lifetimes, auth method configurable per client
- **Challenge/verifier**: Encrypted flow state for OAuth2 redirects (Phase 2)

### Design Decisions
- **Single service**: Not Hydra's multi-service model. Identity + token issuance in one deployable.
- **Redis for ephemeral**: Sessions, token blocklist, rate limits, OTP codes. PostgreSQL for durable state.
- **Stateless access, stateful refresh**: Access tokens verified by signature. Refresh tokens checked against Redis.
- **Asymmetric JWT (ES256/EdDSA)**: Other services verify via JWKS without calling auth service.
- **Separate migration process**: Runtime DB user has no ALTER TABLE privileges.

## Entry Point Pattern

```go
// cmd/server/main.go - Bootstrap sequence
1. Logger init (environment-aware)
2. Config load from env vars
3. Database connection + migration check
4. Redis connection
5. Repository initialization (storage layer)
6. Service initialization (business logic)
7. Middleware setup
8. Router setup (public + admin)
9. Dual-port server start (blocking)
10. Graceful shutdown on SIGTERM/SIGINT
```

## Dependency Flow

```
cmd/server/main.go
    → internal/config       (env vars → Config struct)
    → internal/logger       (zap singleton)
    → internal/storage      (pgx pool + redis client → repositories)
    → internal/domain       (core types, no dependencies)
    → internal/auth         (uses storage, domain, token)
    → internal/token        (JWT ops, JWKS, revocation)
    → internal/user         (user CRUD via storage)
    → internal/client       (OAuth2 client management)
    → internal/rbac         (role enforcement)
    → internal/middleware    (auth, rate limit, CORS, headers)
    → HTTP routers          (public port + admin port)
```

## API Surface

### Public API (Port 4000) — Internet-facing
- `POST /auth/register` — User registration
- `POST /auth/login` — User login → JWT pair
- `POST /auth/token` — Token exchange / refresh
- `POST /auth/revoke` — Token revocation
- `POST /auth/password/reset` — Request password reset
- `POST /auth/password/reset/confirm` — Confirm password reset
- `GET /.well-known/jwks.json` — Public keys
- `GET /health` — Health check
- `GET /liveness` — Liveness probe
- `GET /readiness` — Readiness probe

### Admin API (Port 4001) — Internal only
- `GET/POST/PUT/DELETE /admin/users/{id}` — User management
- `GET/POST/PUT/DELETE /admin/clients/{id}` — Client management
- `POST /admin/token/introspect` — Token introspection
- `GET /admin/metrics` — Prometheus metrics
- `GET /admin/metrics/prometheus` — Prometheus text format

## Error Response Format

```json
{
  "error": "Human-readable message",
  "code": "VALIDATION_ERROR",
  "details": { "field": "email", "reason": "invalid format" }
}
```

Error codes: `VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `RATE_LIMIT_EXCEEDED`, `INTERNAL_ERROR`, `BAD_REQUEST`

## Testing Strategy

- **Table-driven tests** with testify (assert + require)
- **Mock interfaces** for all external dependencies
- **Gin TestMode** for HTTP handler tests
- **Benchmarks** for hot paths (token validation, password hashing)
- **Coverage target**: 90%+
