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

### Phase Overview
```
Phase 1 (MVP) — First-party ecosystem
├── Users: register, login, JWT, refresh, password reset
├── Systems: client credentials, API keys, DPoP-ready
├── RBAC: roles in claims, middleware enforcement
├── Security: NIST AAL2 baseline, rate limiting, audit
├── Infra: dual-port API, PostgreSQL, Redis, Docker
└── All clients are trusted (skip consent)

Phase 2 (Production) — Security depth + third-party
├── MFA: TOTP + WebAuthn
├── OAuth2/OIDC provider: consent flows, client registration
├── Token Exchange (RFC 8693) for service chains
├── DPoP, Casbin RBAC, API key management
├── gRPC internal API, email integration
└── Full audit logging

Phase 3 (Enterprise) — Scale + compliance
├── Multi-tenancy (NID-based), SAML SSO
├── RAR (RFC 9396), agent credential broker
├── Webhooks, admin dashboard
└── GDPR compliance
```

### Completed Tasks
- Research: email-service pattern extraction
- Research: Ory Hydra architecture analysis
- Research: NIST SP 800-63-4 requirements
- Research: AI agent authentication patterns

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
