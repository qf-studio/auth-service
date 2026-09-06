# Auth Service - Development Navigator

**Project**: Authentication service for QuantFlow Studio ecosystem
**Tech Stack**: Go 1.24+, Gin, PostgreSQL (pgx/v5), Redis (go-redis/v9), JWT (ES256/EdDSA)
**Repo**: github.com/qf-studio/auth-service
**Updated**: 2026-09-06

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

### Status (2026-09-06)
**The service is LIVE at `auth.quantflow.studio`** (AWS ECS `quantflow-svc-auth-service` behind a TLS-terminating ALB, deployed via the new "Deploy QuantFlow AWS" workflow — see Deployment). Latest release: **v0.72.0** (train 2026-09-01: E2E issue B #504 + smoke image #505). Before that: v0.71.2 (manual cut: E2E A1-A4 + MFA-enrollment fix), v0.71.1 (review-003 wave 1 fixes, PRs #489-492). Releases: train daily 16:00 Berlin; manual `v*` tag cuts are safe (train skips already-tagged content — verified 09-01).

**Recently landed** (2026-09-06, driven by the live AWS deployment):
- GH-506 (PR #509): per-application `aud` — `Client.Audience` overrides global `JWT_AUDIENCE`; opt-in `JWT_AUDIENCE_ENFORCE`
- GH-507 (PR #510): `TLS_ENABLED` no-op resolved (deprecation WARN; drop in v0.74 — #513)
- GH-508 (PR #514): **review-003's DPoP `htu` proxy bug fixed for real** — `TRUSTED_PROXY_CIDRS` gates `X-Forwarded-Proto` trust (was breaking SSL at auth.quantflow.studio)
- GH-512 (PR #515, in flight): refresh preserves per-client `aud` (`SetClientLookup` + client_id persisted in the Redis refresh value, legacy fallback)
- E2E layers L1 complete: harness A1-A4 (PRs #500-503, v0.71.2) + wiring assertions/wave-2 skips/negatives B (#504) + smoke image C (#505) in v0.72.0. E2E already caught 1 prod bug (MFA enrollment 500). Next: canary D (#496, Navigator-executed — unblocked now that the smoke image ships)
- Review-003 wave-2 backlog unchanged (in-memory sessions, audit_logs, HIBP, :4001 auth, RLS, webhooks, scopes DTO, Casbin, retention) — acceptance tests already written as `t.Skip("review-003: ...")` in `e2e/` via #504; each fix flips its skip

**Open issues**:
| # | Title | Notes |
|---|---|---|
| #512 | refresh drops per-client aud | PR #515 rebased+validated by Navigator 2026-09-06 |
| #513 | drop TLS_ENABLED deprecation WARN | scheduled for one release after v0.73 |
| #496 | canary repo (TASK-01 issue D) | Navigator-executed; smoke image now available |
| #465 | Pointer consumer actions | STALE: predates AWS cutover — Pointer's auth copy is frozen until it switches to `auth.quantflow.studio` (see fa896d2); checklist needs a rewrite for the shared-instance model |
| #447 | Pointer deploy workflow relocation | Largely OBE: `deploy-pointer-aws.yml` removed from this repo (fa896d2); close or repurpose |

**Pilot operational notes** (instance at v2.271.2 as of 2026-08-30):
0. Base-presence check (new, observed 2026-08-30): specs referencing a file path that doesn't exist on main verbatim get silently held ~2h then labeled `pilot-needs-human` with NO issue comment. Use full repo-relative paths in specs. Recovery: fix path, `gh issue edit NN --body-file <doc> --remove-label pilot-needs-human`, wait out repick backoff (~8-15 min).
1. Post-PR state loss: worker can die after opening a PR without closing the child issue → repick loop → `pilot-blocked` with all work actually done in open PRs. Check `gh pr list` before re-arming. Unverified against v2.246.1.
2. ~~False completion via merged-PR title scan~~ **RESOLVED**: the title-based completion scan was removed in Pilot v2.237.0 (pilot PRs #4178/#4192); running instance is v2.246.1, so this can no longer occur. Historical remediation (needed only on pre-v2.237 instances): retitle merged PRs matching `"GH-NN" in:title`, then remove the bogus `pilot-done` once.
3. Stale worker file state: PR branches can carry (a) reverts of files fixed on main after the branch was cut — #475 silently reverted a reviewed bugfix from #474 — and (b) polluted meta files (`.claude/settings.json` worker hook paths, stale `.agent/` doc restores). Before merging a Pilot PR: `git diff origin/main <branch>` (not the GitHub compare, which can show a stale merge base) and `git checkout origin/main -- <file>` the regressions on the branch. Unverified against v2.246.1 — keep checking.

### Deployment (rewritten 2026-09-06 — AWS cutover)
- **Production**: `auth.quantflow.studio` — AWS ECS service `quantflow-svc-auth-service` behind a TLS-terminating ALB. Deployed by `.github/workflows/deploy-quantflow-aws.yml` ("Deploy QuantFlow AWS"): after a successful `v*` Release (or manual dispatch with an image tag) → mirror GHCR→ECR `quantflow/auth-service` → deploy stack → run `/auth-migrate` in-VPC via the `quantflow-auth-service-migrate` task definition → verify. One deploy at a time (concurrency group); first-create path uses DesiredCount=0 → migrate → scale to 2.
- Because the ALB terminates TLS, `TRUSTED_PROXY_CIDRS` must be set (VPC CIDRs) or DPoP `htu` validation fails (GH-508).
- Old SSH deploy paths (`deploy-production.yml`/`deploy-staging.yml`) and `deploy-pointer-aws.yml` REMOVED 2026-09-06 (b3870b2, fa896d2). `scripts/deploy.sh` remains for local/VPS compose use only.
- **Release**: push to main / `v*` tag → GHCR image (multi-arch) + **migration dry-run gate** on fresh Postgres 16 (never break this gate) + `auth-service-smoke:<tag>` image (#505) — run it against any live deployment: `docker run --rm -e SMOKE_BASE_URL=https://auth.quantflow.studio ghcr.io/qf-studio/auth-service-smoke:<tag>`.
- **Consumers** (Pointer): its self-hosted auth copy is frozen; plan is to consume the shared `auth.quantflow.studio` instance (#465 checklist needs rewriting for that model).
- Migrations run via CLI before scale-up, never at startup (runtime DB user has no ALTER).

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
