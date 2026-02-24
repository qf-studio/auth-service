# TASK-00: Research and Architecture Plan

**Status**: ✅ Completed
**Created**: 2026-02-24
**Completed**: 2026-02-24

---

## What Was Done

Comprehensive research and planning phase for the auth-service. Extracted patterns from email-service, analyzed Ory Hydra architecture, mapped NIST SP 800-63-4 requirements, and researched AI agent authentication patterns.

---

## Research 1: Email-Service Pattern Extraction

**Source**: `/Users/aleks.petrov/Projects/startups/email-service/`

### Adopted Patterns
- **Project structure**: `cmd/server/` + `internal/` clean architecture
- **Config**: Env-var only, `Load() (*Config, error)`, never panics
- **Logger**: zap singleton, `Init(environment)`, JSON prod / console dev
- **Protocols layer**: Interface-driven with factory pattern (`internal/protocols/`)
- **Middleware stack order**: security → metrics → validation → handlers
- **Security**: Token bucket rate limiting (`golang.org/x/time/rate`), API key auth, security headers
- **Monitoring**: Health/liveness/readiness probes, Prometheus metrics, MetricsCollector with sliding window
- **Queue pattern**: Redis BLPop, worker goroutine pool, graceful shutdown via channel, exponential backoff
- **Docker**: Multi-stage (Go 1.23-alpine → alpine:3.21), non-root user, ca-certificates
- **Testing**: Table-driven with testify, mock interfaces, gin.TestMode, benchmarks
- **Validation**: Middleware-based, validated request in context (`c.Set("validated_request", req)`)
- **Error responses**: `{error, code, details}` JSON format

### Key Email-Service Dependencies
- Go 1.23+ (we use 1.24+), Gin, zap, go-redis/v8 (we use v9), testify, golang.org/x/time

### Email-Service Tech Stack
- Gin for REST, Redis for async queue, SMTP/SES/Mailgun transports
- 5-stage GitLab CI/CD pipeline
- Docker Compose with Redis + MailHog

---

## Research 2: Ory Hydra Architecture Analysis

**Source**: github.com/ory/hydra

### Hydra Overview
- OpenID Certified OAuth 2.0 + OIDC provider in Go
- Built on `fosite` (extensible OAuth2 SDK)
- Defining decision: **delegated authentication** — Hydra handles token issuance, delegates login/consent to external apps

### Architecture Components
- **Handler layer**: oauth2.Handler, consent.Handler, client.Handler, jwk.Handler
- **Business logic**: fosite.OAuth2Provider, consent.DefaultStrategy, flow.Flow state machine
- **Persistence**: sql.BasePersister with NID-based multi-tenant isolation
- **Service registry**: driver.RegistrySQL with lazy init (sync.Once)
- **Dual-port**: Public (4444) internet-facing + Admin (4445) internal-only

### Patterns We Adopted

| Pattern | Details |
|---|---|
| **Dual-port API** | Public (4000) + Admin (4001), network-level isolation for admin |
| **Token = key.signature** | Only HMAC signatures stored in DB, full token never persisted |
| **Token prefixes** | `qf_at_`, `qf_rt_`, `qf_ac_`, `qf_ak_` for automated leak detection |
| **System secret array** | Newest first for signing, try all for verification (zero-downtime rotation) |
| **Per-client config** | Token lifetimes, auth method configurable per client |
| **Encrypted flow state** | Challenge/verifier with XChaCha20Poly1305 (Phase 2 consent flows) |
| **Separate migrations** | Runtime DB user has no DDL privileges |
| **NID multi-tenancy** | tenant_id on all tables, auto-scoped queries (Phase 3) |
| **Graceful refresh rotation** | Grace period for network unreliability (strict in Phase 1, graceful Phase 2) |
| **Key-set-per-purpose** | Separate key sets for ID tokens vs access tokens |

### Patterns We Rejected

| Rejected | Reason |
|---|---|
| Multi-service model (Hydra + Kratos + login app) | Too complex operationally for our use case |
| Database-only state (no Redis) | We need Redis for ephemeral state (sessions, blocklist, rate limits) |
| No built-in identity management | We include user management in the same service |
| Zero-auth admin API | We keep it for Phase 1 but consider optional mTLS later |
| PBKDF2 for client secrets (over bcrypt) | We use Argon2id consistently for all hashing |

### Hydra OAuth2 Flows Supported
- Authorization Code + PKCE, Client Credentials, Refresh Token, Device Authorization
- Implicit and ROPC (deprecated, we don't implement)

### Hydra Token Management
- Opaque tokens: `<key>.<signature>` with HMAC-SHA256, prefixed (`ory_at_`, etc.)
- JWT mode: optional, with stateless flag for high-performance
- Introspection: database lookup for opaque, signature verification for JWT
- Client secrets: PBKDF2 (20k-50k iterations) or bcrypt

### Hydra Consent Flow (Phase 2 Reference)
```
Client → /oauth2/auth → 302 to Login App (login_challenge)
Login App → Admin API accept → 302 to Consent App (consent_challenge)
Consent App → Admin API accept → 302 back to Client (authorization code)
Client → /oauth2/token → tokens
```
- Challenges: XChaCha20Poly1305 encrypted, contain flow IDs
- Verifiers: single-use, prevent replay
- State machine: LoginInitialized → LoginUsed → ConsentInitialized → ConsentUsed

### Hydra Performance
- ~800-1090 logins/sec sustained (single PostgreSQL)
- v3.0: 6x more flows than v2.1 via reduced DB roundtrips
- Scaling: stateless processes, all state in RDBMS, horizontal scale = more pods

### Common Criticisms of Hydra
- Operational complexity (3+ services for what Auth0 does in one)
- Token cleanup janitor can degrade PostgreSQL performance
- Documentation gaps for self-hosted
- No admin UI (API/CLI only)
- Cold start consent overhead (multiple HTTP redirects)

---

## Research 3: NIST SP 800-63-4 Compliance

**Document**: SP 800-63-4 (final, July 2025) — supersedes SP 800-63-3 (2017)

### Target: AAL2 (Authenticator Assurance Level 2)

**What AAL2 requires**:
- Multi-factor authentication (two distinct factors)
- At least one replay-resistant factor (TOTP, WebAuthn)
- Must offer phishing-resistant option (WebAuthn/FIDO2)
- Authentication intent demonstration
- Session timeouts: 24h overall, 1h inactivity
- FIPS 140 Level 1 for federal authenticators/verifiers

### Password Policy (NIST Rev 4 — Mandatory)

| Requirement | Value |
|---|---|
| Min length (single-factor) | **15 characters** |
| Min length (MFA component) | **8 characters** |
| Max length | At least **64 characters** |
| Character types | All Unicode, ASCII, space |
| Composition rules | **NONE** (no "must have uppercase") |
| Periodic rotation | **FORBIDDEN** (only on compromise) |
| Breached password check | **REQUIRED** (HaveIBeenPwned k-anonymity) |
| Security questions | **FORBIDDEN** |
| Password hints | **FORBIDDEN** (to unauthenticated) |
| Truncation | **FORBIDDEN** (verify entire password) |
| Paste support | Permitted |

### Cryptographic Requirements

| Component | Algorithm | Parameters |
|---|---|---|
| Password hashing | Argon2id | m=19456 (19 MiB), t=2, p=1 |
| Password hashing (FIPS) | PBKDF2-HMAC-SHA-512 | 600,000 iterations |
| Password salt | crypto/rand | 128-bit |
| Pepper | HMAC-SHA-256 | 256-bit key |
| JWT signing | ES256 (ECDSA P-256) or EdDSA | 128-bit security |
| Session tokens | crypto/rand | 256-bit |
| TLS | TLS 1.3 | AES-256-GCM, CHACHA20-POLY1305 |

### Session Management (AAL2)
- 24h max overall, 1h inactivity
- After inactivity: single-factor reauth OK (before overall timeout)
- After overall timeout: full MFA required
- Cookies: Secure, HttpOnly, SameSite=Strict, `__Host-` prefix
- CSRF on all state-changing endpoints
- No HTML5 localStorage for session storage

### Rate Limiting
- Max 100 failed attempts per account before lockout
- Progressive delays: 30s increments
- Biometric: 5 consecutive failures
- Success resets counter

### Federation (FAL Levels)
- FAL1: Signed assertions (JWT ID Tokens with RS256/ES256)
- FAL2: Encrypted assertions (JWE), audience restricted to single RP
- FAL3: Holder-of-key (DPoP or mTLS binding)

### Audit Logging (SP 800-53 AU-2/AU-3)
Required events: auth attempts, password changes, lockouts, session ops, MFA enrollment, admin actions, rate limit triggers
Record fields: event_type, timestamp (UTC), source, IP, user_agent, outcome, subject_id, correlation_id

### NIST on M2M / AI Agents
- SP 800-63-4 **explicitly excludes** M2M authentication
- Applicable guidance: SP 800-207 (Zero Trust), SP 800-53 Rev 5 (IA controls)
- NIST AI Agent Standards Initiative launched Feb 2026 (no final standard yet)
- Practical: treat agents as service accounts with short-lived tokens, unique identity, full audit

---

## Research 4: AI Agent Authentication Patterns

### OAuth2 Client Credentials for Agents
- Standard M2M flow: client_id + client_secret → access token
- Emerging: `requested_actor` + `actor_token` parameters for delegated agent access
- OpenID Foundation whitepaper on Identity Management for Agentic AI

### Brokered Credentials Pattern
```
[LLM Agent] → [Credential Broker/Proxy] → [Target API]
                     |
              [Token Vault] (stores real credentials)
```
- Agent never sees real credentials
- Broker retrieves from vault, makes API call, returns results
- Neutralizes prompt injection credential exfiltration
- Implementations: HashiCorp Vault, Auth0 Token Vault, Scalekit Agent Connect

### Token Lifetime Recommendations for Agents
- Access tokens: 5-15 min TTL
- Refresh tokens: sender-constrained or one-time-use
- Centralized revocation with sub-second propagation

### Two-Tier Client Model

| Aspect | Users (Humans) | Systems (Services/Agents) |
|---|---|---|
| Auth flow | Authorization Code + PKCE | Client Credentials |
| Token lifetime | 15min access, 14d refresh | 5-15min access, no refresh |
| MFA | TOTP + WebAuthn | DPoP / mTLS |
| Session | Interactive, idle timeout | Stateless, per-request |
| Rate limits | Per-user, moderate | Per-client, higher throughput |
| Audit | user_id + IP + device | client_id + service + delegation chain |

### Emerging Standards
- **OAuth 2.1**: Mandatory PKCE, no implicit, no ROPC, exact redirect URI matching
- **DPoP (RFC 9449)**: Cryptographic token binding to client key pair
- **RAR (RFC 9396)**: Structured, action-specific permissions
- **Token Exchange (RFC 8693)**: Service chain delegation with nested `act` claims
- **GNAP**: Potential OAuth successor (IETF draft, not production-ready)
- **MCP Authorization**: Mandates OAuth 2.1 for Model Context Protocol
- **NIST AI Agent Standards Initiative**: Feb 2026, request for input phase
- **CSA Agentic AI IAM Framework**: DIDs + Verifiable Credentials + Zero Trust
- **Microsoft Entra Agent ID**: Agent identities as first-class citizens (preview)

### Agent-Specific Security
- Unique identity per agent instance (never shared)
- Short-lived tokens (5-15 min max)
- Kill switch: local cache invalidation → mesh broadcast → token revocation → cert revocation
- Full audit trail with delegation chain
- DPoP prevents token theft (stolen token useless without private key)

---

## Key Decisions Made

1. **Single service** (not Hydra's multi-service model)
2. **Internal ecosystem only** for Phase 1 (third-party OAuth2 in Phase 2)
3. **ES256/EdDSA asymmetric JWT** (verify via JWKS, no shared secret)
4. **Argon2id** for all password hashing (NIST + OWASP recommended)
5. **Redis for ephemeral, PostgreSQL for durable** state
6. **Dual-port architecture** (4000 public, 4001 admin)
7. **Token signatures only** stored in DB (Hydra pattern)
8. **OAuth 2.1 baseline** (mandatory PKCE, no implicit/ROPC)
9. **NIST AAL2** as security target
10. **Pilot executes issues** — Navigator creates, Pilot implements

---

## Gaps Identified (Post-Planning)

| Gap | Priority | Notes |
|---|---|---|
| CI/CD pipeline (GitHub Actions) | High | Email-service uses GitLab CI, we need GitHub Actions |
| OpenAPI spec | Medium | API documentation for consumers |
| golangci-lint config | Medium | Linting rules and configuration |
| Integration test infra | Medium | Testcontainers for PostgreSQL + Redis in tests |
| Load testing strategy | Low | Benchmarking auth endpoints under load |
| Deployment strategy | Medium | DigitalOcean? AWS? K8s? Same as email-service? |
| Pre-commit hooks | Low | Formatting, linting before commit |
| Go SDK documentation | Low | pkg/authclient usage docs |
| Secrets management | Medium | Vault integration for production keys/pepper |

These can be addressed as follow-up issues or during Phase 1 implementation.

---

**Completed**: 2026-02-24
**Research Duration**: ~1 session
