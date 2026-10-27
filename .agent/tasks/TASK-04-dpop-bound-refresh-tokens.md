# TASK-04: fix(dpop): keep refresh tokens bound to the DPoP key they were issued with

**Created:** 2026-10-26
**Status:** ✅ Merged as #548 (reviewed 2026-10-26: clean; shipped in v0.76.1)
**Last Updated:** 2026-10-27

## Context

`POST /auth/token` with `grant_type=refresh_token` (`internal/api/token_handlers.go` ~lines 44-50) calls `RefreshWithDPoP` when a `DPoP` header is present and plain `Refresh` otherwise. The refresh-token record in Redis (`refreshTokenData`, `internal/token/service.go` ~line 659) stores `sub`, `cid` and `iat`, but no key binding. So a refresh token that was issued together with a DPoP-bound access token (`cnf.jkt`) can later be refreshed without any proof, and the result is an unbound Bearer pair.

Rotation, reuse detection and revocation live in `internal/token/refresh_lifecycle.go` (`lookupRefreshToken`, `consumeRefreshToken`, `checkRefreshReuse`); `refreshInternal` in `internal/token/service.go` is the single entry point for `Refresh` and `RefreshWithDPoP`.

`DPOP_ENABLED` defaults to false (`internal/config/config.go`), so this has no effect on deployments that do not enable DPoP.

## Implementation Plan

1. Add `JKT string \`json:"jkt,omitempty"\`` to `refreshTokenData`. Thread an optional jkt through `issueRefreshToken` / `issueTokenPair` so a pair issued with a DPoP thumbprint stores it on the refresh record.
2. In `refreshInternal`: after `lookupRefreshToken` and BEFORE `consumeRefreshToken`, if `record.JKT != ""` require that the caller's proof thumbprint equals `record.JKT`; otherwise return `ErrUnauthorized` and do not consume the token (a failed attempt must not burn the legitimate client's token).
3. On rotation, carry `record.JKT` to the new refresh record and issue the new access token with the same `cnf.jkt`. A record with an empty `JKT` keeps today's behaviour (Bearer or DPoP both allowed; with DPoP the new pair becomes bound).
4. Never take the binding from the request alone: the stored `JKT` is the source of truth.

## Technical Decisions

- Redis is authoritative for refresh tokens; no Postgres schema change.
- Records written before this change have no `JKT` and stay unbound, so existing clients are not affected.
- Mismatch or missing proof returns the same error as an invalid refresh token (no detail about the binding).

## Dependencies

None. Touches `internal/token/` and its tests only (no `cmd/server/main.go` or config changes), so it can run in parallel with the open hardening issues.

## Verify

- Table-driven tests in `internal/token/` (extend the existing refresh lifecycle tests):
  - bound record + matching proof thumbprint → new pair, new refresh record keeps `JKT`, access token has `cnf.jkt`;
  - bound record + no proof → error, and the refresh token is still valid afterwards (not consumed);
  - bound record + different thumbprint → error, token not consumed;
  - unbound record + no proof → works as before;
  - unbound record + proof → new pair is bound.
- Existing reuse-detection and revoke-all tests still pass.

## Done

- All Verify items pass; `go build ./...`, `go vet ./...`, `go test -race ./internal/...` and the e2e job are green.
- One PR, conventional-commit title equal to the issue title.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/539
- Hardening batch 2026-10-26 (follow-up to #524–#535).
