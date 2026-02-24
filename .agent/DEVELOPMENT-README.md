# Auth Service - Development Navigator

**Project**: Authentication service for QuantFlow Studio ecosystem
**Tech Stack**: Go 1.24+, Gin, PostgreSQL (pgx/v5), Redis (go-redis/v9), JWT (ES256/EdDSA)
**Repo**: github.com/qf-studio/auth-service
**Updated**: 2026-02-24

---

## Quick Start

### New to This Project?
1. [Project Architecture](./system/project-architecture.md) - Tech stack, structure, patterns
2. [Security Profile](./system/security-profile.md) - NIST SP 800-63-4, AAL2, crypto requirements
3. [Client Model](./system/client-model.md) - Users vs Systems (incl. AI agents)

### Starting a Feature?
1. Check [`tasks/`](#implementation-plans) for existing plans
2. Read relevant system docs from [`system/`](#system-architecture)
3. Check SOPs in [`sops/`](#standard-operating-procedures)
4. Create GitHub issue for Pilot execution

### Execution Model
- **Navigator** (this workspace): Research, planning, issue creation
- **Pilot**: Executes GitHub issues labeled `pilot`, opens PRs
- Issues must have clear title + description + acceptance criteria

---

## Documentation Structure

```
.agent/
├── DEVELOPMENT-README.md     <- You are here (navigator)
├── tasks/                    <- Implementation plans from tickets
├── system/                   <- Architecture & design docs
│   ├── project-architecture.md
│   ├── security-profile.md
│   ├── client-model.md
│   └── tech-decisions.md
└── sops/                     <- Standard Operating Procedures
    ├── integrations/
    ├── debugging/
    ├── development/
    └── deployment/
```

---

## Current Focus

### Active Phase
**Phase 1 — MVP**: First-party ecosystem authentication

### GitHub Issues (35 total)

**Phase 1 — MVP** (20 issues, label: `phase-1`):
| # | Title | Depends On |
|---|---|---|
| #1 | Project scaffold: Go module, Docker, docker-compose | — |
| #2 | Config management and structured logging | #1 |
| #3 | Database layer: PostgreSQL, migrations, repositories | #1, #2 |
| #4 | Domain types: User, Client, Token, Role | #1 |
| #5 | JWT token system: creation, validation, JWKS | #2, #4 |
| #6 | User registration with Argon2id password hashing | #3, #4 |
| #7 | User login and token pair generation | #5, #6 |
| #8 | Client credentials flow for systems and AI agents | #3, #4, #5 |
| #9 | Basic RBAC middleware | #4, #5 |
| #10 | Security middleware: rate limiting, headers, CORS | #2 |
| #11 | Observability: health checks, metrics, correlation IDs | #2, #3 |
| #12 | Public REST API: routes, validation, error responses | #5-#11 |
| #13 | Admin API: separate port, management, introspection | #3, #5, #6, #8 |
| #14 | Password reset flow | #2, #3, #6 |
| #15 | Main server bootstrap and integration | #1-#14 |
| #36 | CI/CD pipeline: GitHub Actions | #1, #3 |
| #37 | golangci-lint configuration | #1 |
| #38 | Integration test infrastructure: testcontainers | #1, #3 |
| #39 | OpenAPI specification and API documentation | #12, #13 |
| #40 | Deployment strategy and infrastructure | #1, #36 |

**Phase 2 — Production** (13 issues, label: `phase-2`):
| # | Title |
|---|---|
| #16 | MFA: TOTP enrollment and verification |
| #17 | WebAuthn / Passkeys support |
| #18 | OAuth2 social login: Google, GitHub, Apple |
| #19 | DPoP: demonstration of proof-of-possession |
| #20 | Token exchange: RFC 8693 delegation chains |
| #21 | Casbin RBAC: policy engine with PostgreSQL |
| #22 | API key management |
| #23 | Audit logging: NIST SP 800-53 compliant |
| #24 | Session management |
| #25 | gRPC internal API |
| #26 | Email service integration |
| #27 | OAuth2/OIDC provider: consent flows and discovery |
| #41 | Load testing and benchmarking |

**Phase 3 — Enterprise** (8 issues, label: `phase-3`):
| # | Title |
|---|---|
| #28 | Multi-tenancy: NID-based isolation |
| #29 | RAR: rich authorization requests (RFC 9396) |
| #30 | SAML SSO: enterprise IdP integration |
| #31 | Webhooks: auth event notifications |
| #32 | Admin dashboard API |
| #33 | GDPR compliance: data export, deletion, consent |
| #34 | Agent credential broker |
| #35 | Advanced password policies |

### Completed Research
- email-service pattern extraction
- Ory Hydra architecture analysis
- NIST SP 800-63-4 requirements mapping
- AI agent authentication patterns

---

## Project Structure (Target)

```
auth-service/
├── cmd/server/main.go           # Bootstrap, DI, dual-port server
├── internal/
│   ├── config/                  # Env-based config
│   ├── domain/                  # Core types: User, Client, Token, Role
│   ├── auth/                    # Login, register, token ops, password policy
│   ├── user/                    # User CRUD, profile
│   ├── client/                  # OAuth2 client management (human + system)
│   ├── token/                   # JWT creation, validation, revocation, JWKS
│   ├── rbac/                    # Role enforcement
│   ├── middleware/              # Auth, rate limit, CORS, security headers
│   ├── storage/                 # PostgreSQL + Redis repositories
│   └── logger/                  # zap singleton
├── pkg/authclient/              # Go SDK for service token verification
├── migrations/                  # SQL migrations (separate from runtime)
├── docker/Dockerfile            # Multi-stage, non-root, Alpine
├── docker-compose.yml           # PostgreSQL + Redis + service
├── .agent/                      # Navigator docs
└── go.mod
```

---

## When to Read What

| Scenario | Load |
|---|---|
| Starting new feature | Task doc + `project-architecture.md` |
| Security question | `security-profile.md` |
| Client type design | `client-model.md` |
| Tech choice rationale | `tech-decisions.md` |
| Debugging | `sops/debugging/` |
| Deploying | `sops/deployment/` |

---

## Token Optimization

- Navigator: ~2k tokens (always)
- Current task: ~3k tokens (as needed)
- System docs: ~5k tokens (when relevant)
- SOPs: ~2k tokens (if required)
- **Total**: ~12k vs ~150k loading everything

---

**Last Updated**: 2026-02-24
**Powered By**: Navigator 6.2.1
