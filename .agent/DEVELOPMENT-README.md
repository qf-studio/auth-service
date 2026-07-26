# Auth Service - Development Navigator

**Project**: Authentication service for QuantFlow Studio ecosystem
**Tech Stack**: Go 1.24+, Gin, PostgreSQL (pgx/v5), Redis (go-redis/v9), JWT (ES256/EdDSA)
**Repo**: github.com/qf-studio/auth-service
**Updated**: 2026-02-24

---

## Quick Start

### New to This Project?
1. [Architecture Diagrams](./system/architecture-diagrams.md) - Visual system overview, flows, DB schema
2. [Project Architecture](./system/project-architecture.md) - Tech stack, structure, patterns
3. [Security Profile](./system/security-profile.md) - NIST SP 800-63-4, AAL2, crypto requirements
4. [Client Model](./system/client-model.md) - Users vs Systems (incl. AI agents)
5. [Tech Decisions](./system/tech-decisions.md) - Technology choices with rationale

### Starting a Feature?
1. Check [`tasks/`](#task-documentation) for existing plans
2. Read relevant system docs from [`system/`](#system-documentation)
3. Check SOPs in [`sops/`](#standard-operating-procedures)
4. Pick a GitHub issue or create one for Pilot execution

### Execution Model
- **Navigator** (ClaudeCode): Research, planning, issue creation
- **Pilot**: Executes GitHub issues labeled `pilot`, opens PRs
- Issues use nav-task template (Context, Implementation Plan, Technical Decisions, Dependencies, Verify, Done)

---

## Documentation Structure

```
.agent/
├── DEVELOPMENT-README.md          <- You are here (navigator)
│
├── tasks/                         <- Implementation plans
│   └── TASK-00-research-and-plan.md   # Full research & architecture plan
│
├── system/                        <- Architecture & design docs
│   ├── architecture-diagrams.md       # 8 visual diagrams (overview, flows, schema)
│   ├── project-architecture.md        # Tech stack, patterns, API surface
│   ├── security-profile.md            # NIST AAL2, crypto, session, audit
│   ├── client-model.md               # Users vs Systems, Go types, comparison
│   └── tech-decisions.md             # All choices with rationale + rejected alts
│
├── sops/                          <- Standard Operating Procedures
│   ├── integrations/
│   ├── debugging/
│   ├── development/
│   └── deployment/
│
└── grafana/                       <- Navigator metrics dashboards
```

---

## Current Focus

### Active Phase
**Phase 1 — MVP**: First-party ecosystem authentication

### GitHub Issues (41 total)

**Phase 1 — MVP** (20 issues, label: `phase-1`):

Core:
| # | Title | Depends On |
|---|---|---|
| #1 | Project scaffold: Go module, Docker, docker-compose | — |
| #2 | Config management and structured logging | #1 |
| #3 | Database layer: PostgreSQL, migrations, repositories | #1, #2 |
| #4 | Domain types: User, Client, Token, Role | #1 |
| #5 | JWT token system: creation, validation, JWKS | #2, #4 |

Auth flows:
| # | Title | Depends On |
|---|---|---|
| #6 | User registration with Argon2id password hashing | #3, #4 |
| #7 | User login and token pair generation | #5, #6 |
| #8 | Client credentials flow for systems and AI agents | #3, #4, #5 |
| #14 | Password reset flow | #2, #3, #6 |

Middleware & API:
| # | Title | Depends On |
|---|---|---|
| #9 | Basic RBAC middleware | #4, #5 |
| #10 | Security middleware: rate limiting, headers, CORS | #2 |
| #11 | Observability: health checks, metrics, correlation IDs | #2, #3 |
| #12 | Public REST API: routes, validation, error responses | #5-#11 |
| #13 | Admin API: separate port, management, introspection | #3, #5, #6, #8 |
| #15 | Main server bootstrap and integration | #1-#14 |

Infrastructure:
| # | Title | Depends On |
|---|---|---|
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
- Email-service pattern extraction (see TASK-00)
- Ory Hydra architecture analysis (see TASK-00)
- NIST SP 800-63-4 requirements mapping (see TASK-00)
- AI agent authentication patterns (see TASK-00)

---

## Task Documentation

| Task | Description | Status |
|---|---|---|
| [TASK-00](./tasks/TASK-00-research-and-plan.md) | Research & architecture plan (Hydra, NIST, agent auth) | ✅ Complete |

---

## System Documentation

| Document | Purpose | When to Read |
|---|---|---|
| [Architecture Diagrams](./system/architecture-diagrams.md) | 8 visual diagrams: overview, auth flows, DB schema, deployment | Starting work, onboarding |
| [Project Architecture](./system/project-architecture.md) | Tech stack, patterns, API surface, testing strategy | Implementing features |
| [Security Profile](./system/security-profile.md) | NIST AAL2, crypto params, session rules, audit requirements | Any security-related work |
| [Client Model](./system/client-model.md) | Users vs Systems, Go types, token policies, agent considerations | Client/auth design work |
| [Tech Decisions](./system/tech-decisions.md) | All tech choices with rationale, deps list, rejected alternatives | Understanding "why" |

---

## Standard Operating Procedures

No SOPs created yet. Will be added as patterns emerge during implementation.

---

## Project Structure (Target)

```
auth-service/
├── cmd/
│   ├── server/main.go            # Bootstrap, DI, dual-port server
│   └── migrate/main.go           # Migration runner
├── internal/
│   ├── config/                   # Env-based config
│   ├── domain/                   # Core types: User, Client, Token, Role, Errors
│   ├── auth/                     # Login, register, password hashing, password reset
│   ├── user/                     # User CRUD
│   ├── client/                   # OAuth2 client management (service + agent)
│   ├── token/                    # JWT creation, validation, revocation, JWKS, DPoP
│   ├── rbac/                     # Role enforcement (Phase 1), Casbin (Phase 2)
│   ├── mfa/                      # TOTP, WebAuthn, backup codes (Phase 2)
│   ├── oauth/                    # Social login, OIDC provider (Phase 2)
│   ├── audit/                    # Audit logging (Phase 2)
│   ├── session/                  # Session management (Phase 2)
│   ├── middleware/               # Auth, rate limit, CORS, security headers, metrics
│   ├── storage/                  # PostgreSQL + Redis repositories
│   ├── testutil/                 # Test containers, fixtures, helpers
│   └── logger/                   # zap singleton
├── pkg/authclient/               # Go SDK for service token verification
├── proto/                        # gRPC protobuf definitions (Phase 2)
├── migrations/                   # SQL migrations (separate from runtime)
├── api/                          # OpenAPI specs
├── tests/load/                   # Load testing scripts
├── scripts/                      # Deploy, key generation, pre-deploy validation
├── deployments/                  # Docker Compose for staging/production
├── docker/Dockerfile             # Multi-stage, non-root, Alpine
├── docker-compose.yml            # Dev environment (PostgreSQL + Redis)
├── .github/workflows/            # CI/CD pipelines
├── .golangci.yml                 # Linter configuration
├── Makefile                      # Build automation
├── .agent/                       # Navigator docs
└── go.mod
```

---

## When to Read What

| Scenario | Load |
|---|---|
| Starting work / onboarding | This file + `architecture-diagrams.md` |
| Implementing a feature | Task doc + `project-architecture.md` |
| Security question | `security-profile.md` |
| Client type / auth flow design | `client-model.md` |
| "Why did we choose X?" | `tech-decisions.md` |
| Full research context | `tasks/TASK-00-research-and-plan.md` |
| Debugging | `sops/debugging/` (when available) |
| Deploying | `sops/deployment/` (when available) |

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
