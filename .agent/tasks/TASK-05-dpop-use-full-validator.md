# TASK-05: fix(dpop): validate DPoP proofs with the full dpop.Validator (ath, alg allow-list, one-shot nonces)

**Created:** 2026-10-26
**Status:** 📋 Filed as #540 without the `pilot` label — add it after #530 merges (#524 and #525 merged 2026-10-27)
**Last Updated:** 2026-10-27

## Context

`internal/dpop/` contains two validators:

- `dpop.Validator` (`internal/dpop/dpop.go`, `NewValidator` ~line 126, `ValidateProof` ~line 147): checks `typ`, an algorithm allow-list (ES256, EdDSA), signature, `jti` replay (Redis `SetNX`), `iat` window, `htu` (scheme, host, path), `ath` against the access token, and one-shot server nonces (`handleNonce` ~line 306). It is fully unit-tested (`internal/dpop/dpop_test.go`) but only constructed in tests.
- `dpop.Service` (`internal/dpop/service.go`, `ValidateProof` ~line 71): the one wired in `cmd/server/main.go` (~line 158) through `internal/dpop/middleware_adapter.go` and `internal/dpop/api_adapter.go`. It does not check `ath`, rejects only `none`/`HS*` algorithms, checks a client-supplied nonce with `Exists` without consuming it, and keeps `jti` for `DPOP_JTI_WINDOW` (1m) while accepting `iat` up to 5m old.

`internal/middleware/dpop.go` (`DPoPMiddleware`) runs only for tokens with `cnf.jkt` and does not pass the access token to the validator, so `ath` cannot be checked.

`DPOP_ENABLED` defaults to false (`internal/config/config.go` ~line 659).

## Implementation Plan

1. Make both adapters (`internal/dpop/middleware_adapter.go`, `internal/dpop/api_adapter.go`) call `dpop.Validator.ValidateProof`. Construct the `Validator` in `cmd/server/main.go` from `cfg.DPoP` when `cfg.DPoP.Enabled`.
2. `internal/middleware/dpop.go`: pass the raw access token so the validator checks `ath`. On `POST /auth/token` (no access token yet) pass an empty token, as the validator already supports.
3. Make the `jti` replay window cover the full accepted `iat` window (max age + clock skew), so a proof cannot be replayed after its `jti` key expires.
4. New config in `internal/config/config.go` (documented in `deployments/README.md`):
   - `DPOP_NONCE_REQUIRED` (default `false`);
   - `DPOP_ATH_MODE` = `warn` | `enforce` (default `warn`: log a missing/wrong `ath` and allow; `enforce`: reject).
   - The allowed algorithms stay ES256 and EdDSA (the validator default).
5. When `DPOP_NONCE_REQUIRED=true` and the proof has no valid nonce: respond `401` with a `DPoP-Nonce` header and error `use_dpop_nonce` (RFC 9449 §8). Nonces are consumed on use.
6. Remove `dpop.Service` and `internal/dpop/service_test.go` once nothing references them, or keep `Service` only for `IssueNonce` if the nonce endpoint needs it. Do not delete tests without equivalent `Validator` coverage.

## Technical Decisions

- `ath` starts in `warn` mode so clients that omit it keep working for one release; flip to `enforce` later by config.
- Nonce stays optional by default; enabling it is a config change, not a code change.
- Behaviour with `DPOP_ENABLED=false` is unchanged.

## Dependencies

Touches `cmd/server/main.go` and `internal/config/config.go`, like #524, #525 and #530. Start after those merge to avoid conflicts. Independent of #539 (refresh binding), which may land first.

## Verify

- Unit tests for both adapters with real proofs (reuse the proof builders in `internal/dpop/dpop_test.go`):
  - valid ES256 and EdDSA proofs accepted; RS256 and `none` rejected;
  - `ath` missing → accepted with a warning log in `warn`, rejected in `enforce`; wrong `ath` → same;
  - replayed `jti` within the full `iat` window → rejected;
  - `DPOP_NONCE_REQUIRED=true`: no nonce → 401 + `DPoP-Nonce` header + `use_dpop_nonce`; reused nonce → rejected.
- `internal/middleware/dpop_test.go` and `internal/api/dpop_integration_test.go` updated and green.
- With `DPOP_ENABLED=false` nothing changes (existing tests green).

## Done

- All Verify items pass; `go build ./...`, `go vet ./...`, `go test -race ./...` and the e2e job are green.
- `deployments/README.md` documents the new env vars.
- One PR, conventional-commit title equal to the issue title.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/540
- Hardening batch 2026-10-26 (follow-up to #524–#535).
