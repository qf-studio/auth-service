# Auth Service - Development Navigator

**Project**: Authentication service for QuantFlow Studio ecosystem
**Tech Stack**: Go 1.24+, Gin, PostgreSQL (pgx/v5), Redis (go-redis/v9), JWT (ES256/EdDSA)
**Repo**: github.com/qf-studio/auth-service
**Updated**: 2026-07-26

---

## Quick Start

### New to This Project?
1. [Architecture Diagrams](./system/architecture-diagrams.md) - Visual system overview, flows, DB schema
2. [Project Architecture](./system/project-architecture.md) - Tech stack, structure, patterns
3. [Security Profile](./system/security-profile.md) - NIST SP 800-63-4, AAL2, crypto requirements
4. [Client Model](./system/client-model.md) - Users vs Systems (incl. AI agents), public/PKCE clients
5. [Tech Decisions](./system/tech-decisions.md) - Technology choices with rationale

### Starting a Feature?
1. Check [`tasks/`](#task-documentation) for existing plans
2. Read relevant system docs from [`system/`](#system-documentation)
3. Pick a GitHub issue or create one for Pilot execution

### Execution Model
- **Navigator** (ClaudeCode): Research, planning, issue creation
- **Pilot**: Executes GitHub issues labeled `pilot`, opens PRs. May decompose large issues into children (watch for post-PR state loss — see gh-436.md note)
- Issues use nav-task template (Context, Implementation Plan, Technical Decisions, Dependencies, Verify, Done)
- **Downstream consumer**: Pointer (getpointer.app) deploys pinned release tags to its own AWS env — see Deployment below

---

## Documentation Structure

```
.agent/
├── DEVELOPMENT-README.md          <- You are here (navigator)
├── tasks/                         <- Implementation plans
│   ├── TASK-00-research-and-plan.md   # Original research & architecture plan
│   ├── gh-NN.md                       # Per-issue specs (nav-task format)
│   └── archive/                       # Completed task docs
├── system/                        <- Architecture & design docs
│   ├── architecture-diagrams.md       # 8 visual diagrams (overview, flows, schema)
│   ├── project-architecture.md        # Tech stack, patterns, API surface
│   ├── security-profile.md            # NIST AAL2, crypto, session, audit
│   ├── client-model.md                # Users vs Systems, public clients, token policies
│   └── tech-decisions.md              # All choices with rationale + rejected alts
└── grafana/                       <- Navigator metrics dashboards
```

(No `sops/` yet — create on first SOP.)

---

## Current Focus

### Status (2026-07-26)
The original 3-phase plan (41 issues) is **fully delivered** — all phase-1/2/3 issues closed. The service is at **v0.69.0**, deployed and consumed by Pointer (auth.getpointer.app). Work is issue-driven: gaps found by consumers become `pilot`-labeled issues with `tasks/gh-NN.md` specs.

**Recently landed** (v0.69.0, 2026-07-26):
- GH-436: public/PKCE client type (`client_type=public`, `redirect_uris`, migrations 000016/000017) + `aud` claim via `JWT_AUDIENCE`
- GH-435: migrate tool shipped in the image (`/auth-migrate`: up|down|version|force), `TARGETARCH` fix (arm64 images were shipping amd64 binaries), release dry-run gate now actually runs migrations from the shipped image (was a file-existence check before)
- GH-444 (v0.68.1): fresh-install migration fix (UUID/TEXT FK mismatch)

**Open issues**:
| # | Title | Notes |
|---|---|---|
| #431 | OIDC provider implementation | Specced (`tasks/gh-431.md`), in Pilot queue. Scaffolding exists since GH-274 (`08ead94`) — handlers/DTOs/routes complete, services are nil placeholders in main.go. Implement to the existing contract; Hydra-style external login/consent UI |
| #447 | Move Pointer AWS deploy workflow to private infra repo | Security: self-hosted runner on public repo; needs infra-repo + org-admin access |
| #465 | Pointer consumer actions for v0.69.0 | On Pointer's side: deploy, enable aud validation, re-register SPA as public client, drop vendored migrations. NOT pilot-labeled |

**Pilot operational notes** (two bookkeeping bugs observed 2026-07-25/26):
1. Post-PR state loss: worker can die after opening a PR without closing the child issue → repick loop → `pilot-blocked` with all work actually done in open PRs. Check `gh pr list` before re-arming.
2. False completion: a merged PR whose *title* mentions "GH-NN" (e.g. a specs/docs PR) can get an unrelated open issue labeled `pilot-done`. Verify branches/PRs exist before trusting `pilot-done`.

### Deployment
- **Own strategy** (issue #40): Docker Compose on VPS, Caddy auto-TLS, `scripts/deploy.sh` / `rollback.sh`, manual `deploy-production.yml` (SSH). Staging disabled until infra exists (GH-416).
- **Release**: push to main / `v*` tag → GHCR image (multi-arch, version tags) + **migration dry-run gate** on fresh Postgres 16. Never break this gate.
- **Consumers** (Pointer): pin a `vX.Y.Z` tag, run `migrations/` from that same tag, deploy the image. `deploy-pointer-aws.yml` does this (temporarily in this repo — #447).
- Migrations run via CLI before deploy, never at startup (runtime DB user has no ALTER).

---

## Task Documentation

| Task | Description | Status |
|---|---|---|
| [TASK-00](./tasks/TASK-00-research-and-plan.md) | Research & architecture plan (Hydra, NIST, agent auth) | ✅ Complete |
| [gh-436](./tasks/gh-436.md) | Public/PKCE client type + `aud` claim | ✅ Complete (v0.69.0) |
| [gh-435](./tasks/gh-435.md) | Migrate tool in image + multi-arch fix + real CI gate | ✅ Complete (v0.69.0) |
| [gh-431](./tasks/gh-431.md) | OIDC provider services implementation | 🚀 Dispatched to Pilot |
| `tasks/gh-NN.md` | Per-issue specs; active ones match open `pilot`-labeled issues | Various |

---

## System Documentation

| Document | Purpose | When to Read |
|---|---|---|
| [Architecture Diagrams](./system/architecture-diagrams.md) | 8 visual diagrams: overview, auth flows, DB schema, deployment | Starting work, onboarding |
| [Project Architecture](./system/project-architecture.md) | Tech stack, patterns, API surface, testing strategy | Implementing features |
| [Security Profile](./system/security-profile.md) | NIST AAL2, crypto params, session rules, audit requirements | Any security-related work |
| [Client Model](./system/client-model.md) | Users vs Systems, public clients, token policies, agent considerations | Client/auth design work |
| [Tech Decisions](./system/tech-decisions.md) | All tech choices with rationale, deps list, rejected alternatives | Understanding "why" |

---

## Project Structure (Actual)

```
auth-service/
├── cmd/
│   ├── server/main.go     # Bootstrap, DI, dual-port server (4000 public / 4001 admin)
│   └── migrate/main.go    # Migration runner (DATABASE_URL or POSTGRES_* env)
├── internal/
│   ├── config/            # Env-based config (JWTConfig, OIDCConfig, ...)
│   ├── domain/            # Core types: User, Client (service|agent|public), Token, Role, Claims
│   ├── auth/              # Login, register, password hashing, reset
│   ├── admin/             # Admin services incl. client management (NOT internal/client)
│   ├── api/               # Routers + handlers, public & admin; request DTOs + validation
│   ├── token/             # JWT creation/validation, JWKS, refresh; aud via JWT_AUDIENCE
│   ├── oauth/             # Social login (outbound PKCE helpers in pkce.go)
│   ├── mfa/ rbac/ session/ audit/ dpop/ webhook/ email/ grpc/
│   ├── middleware/ metrics/ health/ httpserver/ logger/ password/ hibp/
│   ├── storage/           # PostgreSQL + Redis repositories
│   └── testutil/          # Test containers, fixtures
├── pkg/authclient/        # Go SDK for token verification
├── migrations/            # SQL (embedded); highest: 000017. FKs to users.id are TEXT
├── api/                   # OpenAPI specs
├── deployments/           # Compose staging/production, Caddyfile, README
├── scripts/               # deploy.sh, rollback.sh, key generation
└── .github/workflows/     # test, release, spectral, deploy-{staging,production,pointer-aws}
```

⚠️ Known trap: `internal/domain/admin.go` has a **dead** `CreateClientRequest`/validator path; the live one is `internal/api/admin_services.go` (see gh-436.md).
⚠️ Issuer discrepancy: hardcoded `https://auth.qf.studio` in `token/service.go` vs unused `OIDC_ISSUER_URL` config — do not "fix" casually, downstream verifiers pin `iss`.

---

## When to Read What

| Scenario | Load |
|---|---|
| Starting work / onboarding | This file + `architecture-diagrams.md` |
| Implementing a feature | Task doc + `project-architecture.md` |
| Security question | `security-profile.md` |
| Client type / auth flow design | `client-model.md` |
| "Why did we choose X?" | `tech-decisions.md` |
| Deploying / releases | Deployment section above + `deployments/README.md` |
| Full research context | `tasks/TASK-00-research-and-plan.md` |

---

**Last Updated**: 2026-07-26 (v0.69.0)
**Powered By**: Navigator 6.2.1
