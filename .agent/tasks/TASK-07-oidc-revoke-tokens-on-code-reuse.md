# TASK-07: fix(oidc): revoke tokens issued from an authorization code when the code is redeemed again

**Created:** 2026-10-26
**Status:** ✅ Merged as #572 (reviewed 2026-10-27: clean)
**Last Updated:** 2026-10-27

## Context

Authorization codes are single-use: `RedisStore.ConsumeAuthorizationCode` (`internal/oidc/redis_store.go` ~line 197) does a GETDEL, and a second redemption in `ProviderService.ExchangeCode` (`internal/oidc/provider_service.go` ~line 207) returns "invalid or expired authorization code". The tokens issued by the first redemption stay valid. RFC 6749 §4.1.2 and OAuth 2.1 §4.1.3 say the server SHOULD revoke all tokens previously issued from a code that is used twice.

Available primitives (`internal/token/`):
- access tokens: jti denylist `revoked:<jti>` written by `Service.Revoke` (`internal/token/service.go` ~line 359) and checked by `IsRevoked` (~line 467) in `internal/middleware/auth.go`;
- refresh tokens: Redis records (`refreshTokenData`, `internal/token/service.go` ~line 659) with rotation, reuse detection and a per-subject epoch in `internal/token/refresh_lifecycle.go`. There is no token family: after one rotation the original refresh key is gone and its successors cannot be found from the code.

## Implementation Plan

1. **Refresh token family.** Add `FamilyID string \`json:"fid,omitempty"\`` to `refreshTokenData`. A new pair gets a fresh random family id; rotation copies it to the new record. Add `RevokeRefreshFamily(ctx, familyID, ttl)` that sets `rt_fam_revoked:<familyID>` (TTL = refresh-token TTL), and make `lookupRefreshToken` reject a record whose family is revoked (mirror the existing epoch check).
2. **Access token by jti.** Add `RevokeJTI(ctx, jti string, exp time.Time)` that writes the existing `revoked:<jti>` key with the remaining lifetime. Expose the access token jti from the issue path (return it, or parse it from the minted JWT); never store the raw token.
3. **Used-code record.** Replace the plain GETDEL with one atomic Redis operation (Lua script) that reads and deletes the code and writes a used-code marker keyed by SHA-256 of the code (`oidc_code_used:<hex>`, TTL ≥ access-token TTL, at least 15 min). After issuance, store `{jti, exp, family_id}` in that marker.
4. **Replay handling in `ExchangeCode`.** When the code is not found but the used-code marker exists: revoke the recorded jti and refresh family, log an audit/warn event (`oidc_code_reuse`, client_id, no code value), and return the same `invalid_grant`-style error as today. If the marker exists without issuance details yet (race with the first redemption), set a `replayed` flag on it; the first redemption checks the flag after it writes the details and revokes its own tokens if set.

## Technical Decisions

- Revocation is scoped to the tokens from that one code (family + jti). `RevokeAllRefreshTokens` (per subject) is too broad: it would end the user's other sessions.
- Store only the SHA-256 of the code and token identifiers (jti, family id), never raw tokens.
- The error response for a reused code does not change.

## Dependencies

Start after #541 merges (same `ExchangeCode` code path and tests), and after #533.

## Verify

- `internal/token/` tests: family id set on issue and kept on rotation; `RevokeRefreshFamily` makes every token of the family fail (including rotated successors) and leaves other families of the same user working; `RevokeJTI` makes `IsRevoked` return true.
- `internal/oidc/provider_service_test.go` (and `internal/oidc/fakes_test.go`): second redemption → error AND the access token jti and refresh family from the first redemption are revoked; unrelated tokens of the same user stay valid.
- Race test (or a store-level unit test with miniredis): replay flag set before issuance details are stored → the first redemption revokes its own tokens.
- `e2e/oidc_flow_test.go`: redeem the same code twice → second call fails, and the access token from the first call now gets 401 on `/auth/me`.

## Done

- All Verify items pass; `go build ./...`, `go vet ./...`, `go test -race ./...` and the e2e job are green.
- One PR, conventional-commit title equal to the issue title. If the work does not fit one Pilot run, split it: (a) token family + `RevokeJTI` in `internal/token/`, (b) the OIDC used-code record and replay handling.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/542
- Hardening batch 2026-10-26 (follow-up to #524–#535).
