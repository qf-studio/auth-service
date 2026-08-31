# Auth Service - Development Navigator

**Project**: Authentication service for QuantFlow Studio ecosystem
**Tech Stack**: Go 1.24+, Gin, PostgreSQL (pgx/v5), Redis (go-redis/v9), JWT (ES256/EdDSA)
**Repo**: github.com/qf-studio/auth-service
**Updated**: 2026-08-31

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

### Status (2026-08-31)
The original 3-phase plan (41 issues) is **fully delivered**. Latest release: **v0.71.0** (email wiring GH-477/478, gRPC port GH-483); **v0.72.0 expected 2026-08-31 ~14:00 UTC** via Pilot autopilot's release train (daily 16:00 Europe/Berlin — releases are cut by the train, not manually, since 2026-08-03). Work is issue-driven: gaps found by consumers become `pilot`-labeled issues with `tasks/gh-NN.md` specs.

**Recently landed** (on main 2026-08-30, review-003 wave 1 — external feature-inventory audit, verified 0/39 claims wrong; specs `tasks/gh-485..488.md`):
- GH-485 (PR #489): migration 000019 `api_keys` (table never existed!) + API-key hashing switched Argon2id→SHA-256 digest so indexed lookup works (validation previously always 401'd)
- GH-486 (PR #492): refresh-token introspection fixed — `domain.RefreshTokenSignature` helper, login stores signature-only with configured TTL, rotation revokes-old/inserts-new in Postgres, logout takes optional `refresh_token` body field
- GH-487 (PR #490): `deploy.sh` migrations now actually run (`compose run --rm --entrypoint /auth-migrate auth-service up`), hard-fail before restart
- GH-488 (PR #491): post-MFA tokens carry roles (UserLookup injected), MFA status check fails closed (AAL2), TOTP digits validated at startup + honored in verify; `mfa.NewService` now returns error
- Full suite green locally with `-race` incl. testcontainers (2026-08-31)
- Review-003 confirmed-unissued backlog (wave 2 candidates): in-memory sessions, audit_logs never written, HIBP never called, no auth on :4001, RLS unarmed, webhook Dispatch uncalled, scope allow-list on dead DTO, Casbin vs tenant_id, retention
- **E2E & canary strategy planned** — see [`tasks/TASK-01-e2e-canary-strategy.md`](./tasks/TASK-01-e2e-canary-strategy.md): 3 layers (PR-gated E2E booting the Docker image / 6h canary repo vs published artifacts / staging re-point), issues A–D awaiting approval. Wave-2 fixes should land after issue B so each flips a skipped acceptance test.

**Open issues**:
| # | Title | Notes |
|---|---|---|
| #447 | Move Pointer AWS deploy workflow to private infra repo | Security: self-hosted runner on public repo; needs infra-repo + org-admin access |
| #465 | Pointer consumer actions (now targets v0.70.0) | Consolidated checklist in comments: deploy v0.70.0 directly (skip v0.69.0), aud two-step, SPA as public client, OIDC_LOGIN_UI_URL, iss warning. Live instance predates v0.69.0; Nelya pinged in Slack #pointer 2026-07-27 |

**Pilot operational notes** (instance at v2.271.2 as of 2026-08-30):
0. Base-presence check (new, observed 2026-08-30): specs referencing a file path that doesn't exist on main verbatim get silently held ~2h then labeled `pilot-needs-human` with NO issue comment. Use full repo-relative paths in specs. Recovery: fix path, `gh issue edit NN --body-file <doc> --remove-label pilot-needs-human`, wait out repick backoff (~8-15 min).
1. Post-PR state loss: worker can die after opening a PR without closing the child issue → repick loop → `pilot-blocked` with all work actually done in open PRs. Check `gh pr list` before re-arming. Unverified against v2.246.1.
2. ~~False completion via merged-PR title scan~~ **RESOLVED**: the title-based completion scan was removed in Pilot v2.237.0 (pilot PRs #4178/#4192); running instance is v2.246.1, so this can no longer occur. Historical remediation (needed only on pre-v2.237 instances): retitle merged PRs matching `"GH-NN" in:title`, then remove the bogus `pilot-done` once.
3. Stale worker file state: PR branches can carry (a) reverts of files fixed on main after the branch was cut — #475 silently reverted a reviewed bugfix from #474 — and (b) polluted meta files (`.claude/settings.json` worker hook paths, stale `.agent/` doc restores). Before merging a Pilot PR: `git diff origin/main <branch>` (not the GitHub compare, which can show a stale merge base) and `git checkout origin/main -- <file>` the regressions on the branch. Unverified against v2.246.1 — keep checking.

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
| [gh-431](./tasks/gh-431.md) | OIDC provider services implementation (children gh-467→470) | ✅ Complete (v0.70.0) |
| [gh-473](./tasks/gh-473.md) | Token-type hardening: gRPC qf_at_ gate + client_type claim gate | ✅ Complete (v0.70.0, PR #476) |
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
│   ├── token/             # JWT creation/validation, JWKS, refresh; aud via JWT_AUDIENCE; IssueIDToken
│   ├── oauth/             # Social login (outbound PKCE helpers in pkce.go)
│   ├── oidc/              # OIDC provider: Redis challenge/code stores, provider/consent/approval services
│   ├── mfa/ rbac/ session/ audit/ dpop/ webhook/ email/ grpc/
│   ├── middleware/ metrics/ health/ httpserver/ logger/ password/ hibp/
│   ├── storage/           # PostgreSQL + Redis repositories
│   └── testutil/          # Test containers, fixtures
├── pkg/authclient/        # Go SDK for token verification
├── migrations/            # SQL (embedded); highest: 000018. FKs to users.id are TEXT
├── api/                   # OpenAPI specs
├── deployments/           # Compose staging/production, Caddyfile, README
├── scripts/               # deploy.sh, rollback.sh, key generation
└── .github/workflows/     # test, release, spectral, deploy-{staging,production,pointer-aws}
```

⚠️ Known trap: `internal/domain/admin.go` has a **dead** `CreateClientRequest`/validator path; the live one is `internal/api/admin_services.go` (see gh-436.md).
⚠️ `OIDC_ISSUER_URL` now actually sets `iss` on issued tokens (GH-468; previously hardcoded). Consumers that pin `iss` break when a deployment first overrides it — see deployments/README.md.
⚠️ `migrations/consent_grants_migration_test.go` asserts head schema version == 18; the next migration must bump that assertion.

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

**Last Updated**: 2026-07-27 (v0.70.0 released: OIDC provider + token-type hardening)
**Powered By**: Navigator 6.2.1
