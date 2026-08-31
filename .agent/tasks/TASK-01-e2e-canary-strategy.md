# TASK-01: E2E & Canary Test Strategy

**Created:** 2026-08-31
**Status:** 🚀 In flight — A=#493 (dispatched to Pilot), B=#494, C=#495 (label `pilot` after #493 merges), D=#496 (Navigator-executed; repo qf-studio/auth-service-canary created 2026-08-31)
**Origin:** Review-003 post-mortem — 25 of 39 verified findings were "built but never wired in `main()`" defects that unit tests structurally cannot see (they bypass `main()` and hand-wire mocks). `cmd/server` has zero test files today; nothing boots the real binary.

## Goal

Three layers, delivered in order. Each layer catches a failure class the previous one can't:

| Layer | What it boots | Catches | Runs |
|---|---|---|---|
| **L1 — in-repo E2E** | The Docker image (built from the PR) + testcontainers Postgres/Redis | main() wiring gaps, Dockerfile breaks, migration drift, route/authz regressions | Every PR (CI gate) |
| **L2 — canary repo** | The *published* GHCR release image + `pkg/authclient` from go.mod | Broken release-train output, bad published image, SDK/image drift — fails the way a consumer (Pointer) would | Cron every 6h |
| **L3 — staging canary** | Same L2 scenarios, `BASE_URL` re-pointed at real staging | Infra/config/TLS-proxy-class bugs (e.g. the DPoP `htu` scheme bug) | When staging exists (GH-416) |

## Tooling (decided)

- **testcontainers-go** (postgres + redis modules, already in go.mod); SUT booted as `GenericContainer` from the locally built image — exercises `docker/Dockerfile`, `/auth-migrate`, env wiring, all 3 ports
- **stdlib net/http + testify** for HTTP assertions (no httpexpect — keep deps lean)
- **`pkg/authclient`** for gRPC assertions (dogfoods the SDK; consumer-breaking changes fail E2E)
- **Fake externals** modeled on `pilot/e2e/mocks/github.go` (`httptest.NewServer` + stateful map + assertion hooks): `HIBPMock`, `WebhookReceiverMock`, `EmailSinkMock`; later an OIDC login-UI stub
- **Fake secrets** as obviously-fake constants (pilot `internal/testutil/tokens.go` convention — avoids push-protection false positives)
- **Gating**: `testing.Short()` everywhere — ONE mechanism, no build tags. Also retrofit the existing `internal/oidc` testcontainers tests with the same guard (fixes the known no-skip-on-missing-Docker nit)

## Pilot lessons applied (from nav-research of pilot repo, 2026-08-31)

1. **CI-wiring pitfall**: pilot's `make test-integration`/`test-chaos` never run in CI — silently local-only. Our E2E CI job lands in the SAME PR as the suite, non-optional.
2. **Zero in-daemon canary code** (pilot TASK-379/403 hard constraint): the canary must exercise the service exactly as a real consumer — scenarios live in GitHub Actions YAML + scripts, not in the service.
3. **Port, nearly verbatim**: `pilot/scripts/canary-report.py` (single mutating tracker issue per scenario, JSON state blob, green-streak auto-close — no comment spam) and the idempotency-guard + reusable-scenario-workflow shape from `pilot/.github/workflows/pilot-canary*.yml`.
4. **Metrics-isolation pitfall**: pilot needed 5+ fixes to exclude canary rows from metrics (each write path needs its own stamp). We AVOID the problem in L2 by using ephemeral envs (nothing persists); defer the canary-tenant flag to L3.
5. **Spec hygiene**: full repo-relative paths only in issue specs (Pilot base-presence check holds tasks 2h over shorthand paths — see nav note #0).

## Coverage

**P0 golden paths** (issue A) — each crosses the real network boundary:
1. register → verify-email (EmailSinkMock) → login → `/me` → refresh → admin introspect `active:true` → logout → introspect `active:false` *(would have caught GH-486)*
2. MFA: setup → confirm → login challenge → verify → **parse JWT, assert roles claim** *(GH-488)*
3. Admin: client CRUD → rotate secret (grace) → API key create → validate → rotate → revoke *(GH-485 ×2)*
4. OIDC: discovery → JWKS → authorize → admin PUT login/consent → code → token → userinfo
5. gRPC via authclient: ValidateToken / IntrospectToken / GetUser
6. Password reset via EmailSinkMock

**P0 wiring assertions** (issue B):
- Golden route list: every expected `(method, path)` on :4000/:4001 answers non-404 (~70 endpoints)
- `audit_logs` row growth after admin actions
- Migration head version after `/auth-migrate up`
- **Wave-2 acceptance tests, written now as `t.Skip("GH-NN: ...")`**: audit_logs empty, arbitrary scopes accepted, `X-Tenant-ID` ignored, RBAC unenforced, HIBP never called. Each wave-2 fix flips its skip → the E2E suite is the acceptance harness for the review-003 backlog.

**P1 negatives** (issue B): revoked-token reuse, expired tokens (short-TTL env), rate-limit 429, health/readiness semantics, Prometheus scrape parses.

**P2 — later, separate issue**: fault injection (stop Redis mid-flight → assert fail-closed), TLS-terminating proxy container (DPoP `htu`), restart-persistence (documents in-memory-sessions gap). Pilot's `internal/chaos` may have portable patterns — unresearched.

## Canary (L2) design — issue D

- New repo **`qf-studio/auth-service-canary`** (mirrors `pilot-canary-sandbox` role): cron `0 */6 * * *` + `workflow_dispatch`
- Each run: pull `ghcr.io/qf-studio/auth-service:<latest release tag>` → compose up postgres/redis/service in the runner → run the **smoke subset** of L1 flows via published `pkg/authclient` (consumed through go.mod like a real consumer, NOT a local replace)
- Smoke subset = non-destructive-by-construction here (env is ephemeral), so the full golden paths run
- Reporting: ported `canary-report.py` → `[canary:auth-flows]` tracker issue on auth-service repo, green-streak auto-close
- Idempotency guard + per-scenario timeout, per pilot pattern
- L3 = same workflow with `BASE_URL` env override pointing at staging + disposable-tenant flows only (destructive subset off) + the canary-tenant metrics flag (accept the pilot pitfall cost then, not now)

## Delivery

| Issue | Content | Depends on | Size |
|---|---|---|---|
| **A** | `e2e/` harness (image boot, containers, mocks, fake-secrets), P0 golden paths 1–6, CI job (`-timeout 20m`, pilot's 2× headroom lesson), `-short` retrofit for oidc tests | — | L |
| **B** | Golden route list, audit/migration wiring assertions, skipped wave-2 acceptance tests, P1 negatives | A | M |
| **C** | Publish `auth-service-smoke` image per release (compiled `go test -c ./e2e` + smoke flag) — the artifact D consumes; also runnable manually against any URL (Pointer post-deploy verification, #465 pain) | A | S |
| **D** | `auth-service-canary` repo: cron workflow, scenario shape, ported reporter, tracker issue | C | M |

Wave-2 review-003 fixes should land AFTER B exists, so each fix flips a skipped acceptance test.

## Open decisions (2)

1. **Canary cadence/cost**: 6h mirrors pilot; each run is a few minutes of Actions time + image pull. Cheaper alternative: daily + on-release trigger. Default: on-release + daily cron.
2. **Issue C/D merge**: could ship as one issue if Pilot handles multi-repo tasks poorly (D creates a new repo — likely needs manual repo creation by Aleks first, then a pilot issue for content).

## Refs

- Review-003 verification (this session, 2026-08-30/31): `tasks/gh-485..488.md`, wave-2 backlog in DEVELOPMENT-README Current Focus
- Pilot patterns: `pilot/.github/workflows/pilot-canary.yml`, `pilot-canary-scenario.yml`, `pilot/scripts/canary-poll.sh`, `pilot/scripts/canary-report.py`, `pilot/e2e/` (harness + mocks), `pilot/.agent/tasks/archive/TASK-379-runtime-self-verification.md`, `TASK-403-canary-lifecycle-scenarios.md`
- Existing partial coverage: `internal/oidc/oidc_flow_integration_test.go` (testcontainers, self-wired), `internal/storage/repository_integration_test.go`, `migrations/consent_grants_migration_test.go`
