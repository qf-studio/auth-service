# Technology Decisions

**Updated**: 2026-02-24

## Decisions Log

### Go 1.24+ (not 1.23)
**Reason**: Native FIPS 140-3 support (`GODEBUG=fips140=on`), post-quantum TLS (ML-KEM), `crypto/hkdf`, SHA-3. No third-party cgo wrappers needed for compliance.

### Gin (not Chi, not stdlib)
**Reason**: Matches email-service patterns. Minimal, fast, middleware-friendly. Team familiarity. Chi is a valid alternative but we standardize on Gin across the ecosystem.

### PostgreSQL + pgx/v5 (not GORM, not sqlx)
**Reason**: pgx is the fastest Go PostgreSQL driver. Direct SQL, no ORM overhead. Supports connection pooling, prepared statements, COPY protocol. Row-level security for future multi-tenancy.

### Redis go-redis/v9 (not Rueidis)
**Reason**: Mature, well-documented, matches email-service. Used for: sessions, token blocklist (jti), rate limit counters, OTP codes. All ephemeral state with TTL-based expiry.

### ES256/EdDSA for JWT (not RS256)
**Reason**: NIST 128-bit security strength. ES256: widest library support. EdDSA: faster, simpler (no nonce pitfalls). RS256 deprecated for new services (larger keys, slower). Asymmetric = other services verify via JWKS without shared secret.

### Argon2id (not bcrypt)
**Reason**: OWASP 2025 + NIST recommended. Memory-hard (resists GPU attacks). Params: m=19MiB, t=2, p=1. bcrypt only as legacy fallback. If strict FIPS required: PBKDF2-HMAC-SHA-512 at 600k iterations.

### golang-migrate (not goose)
**Reason**: Supports embedded migrations, CLI + library usage, PostgreSQL native. Separate migration process from runtime (NIST security practice — runtime DB user has no DDL privileges).

### Dual-Port Architecture (not path-based separation)
**Reason**: Hydra pattern. Public API (port 4000) internet-facing, Admin API (port 4001) internal-only. Network-level isolation is the security boundary. Avoids complex RBAC on the auth server itself.

### Token = key.signature (not full token storage)
**Reason**: Hydra pattern. Only HMAC signatures stored in DB. Database compromise does not yield usable tokens without the system secret. Reduces storage and blast radius.

### Token Prefixes (qf_at_, qf_rt_, etc.)
**Reason**: Enables automated secret scanning in CI/CD, logs, and code repositories. Immediate identification of leaked token type.

### OAuth 2.1 Baseline (not OAuth 2.0)
**Reason**: Mandatory PKCE, no implicit grant, no ROPC, exact redirect URI matching, sender-constrained refresh tokens. Security best practices baked into the protocol.

### No External DI Container
**Reason**: Manual wiring in main(). Email-service pattern. Go philosophy — explicit over magic. DI containers add complexity without proportional benefit in a service this size.

### Separate Migration Process
**Reason**: NIST security practice. Runtime database user should not have ALTER TABLE privileges. Migrations run via CLI before deployment, not at startup.

## Dependencies (Phase 1)

```
golang-jwt/jwt/v5           # JWT operations
golang.org/x/crypto/argon2  # Password hashing
jackc/pgx/v5                # PostgreSQL driver
redis/go-redis/v9           # Redis client
gin-gonic/gin               # HTTP router
golang-migrate/migrate      # DB migrations
go-playground/validator/v10  # Struct validation
go.uber.org/zap             # Structured logging
golang.org/x/time/rate      # Rate limiting
google.golang.org/grpc      # gRPC (Phase 2)
```

## Rejected Alternatives

| Rejected | Reason |
|---|---|
| Ory Hydra (as dependency) | Too complex operationally (3+ services). We adopt patterns, not the software. |
| GORM | ORM overhead, magic. Direct SQL with pgx is faster and more predictable. |
| Keycloak | Java, heavy, not Go ecosystem. |
| Firebase Auth | Vendor lock-in, no self-hosted control. |
| Casbin in Phase 1 | Over-engineering for MVP. Simple role-in-claims is sufficient. Casbin added in Phase 2. |
| Redis for primary state | PostgreSQL for durable state. Redis only for ephemeral (sessions, blocklist, rate limits). |
