# TASK-06: fix(oidc): issue a refresh token from the authorization-code grant only when offline_access is granted

**Created:** 2026-10-26
**Status:** ✅ Merged as #550 (reviewed 2026-10-26: clean; shipped in v0.76.1)
**Last Updated:** 2026-10-27

## Context

`ProviderService.ExchangeCode` (`internal/oidc/provider_service.go`, ~line 246) always calls `tokens.IssueTokenPairForClient`, so every successful code exchange returns a refresh token, for confidential and public (PKCE) clients alike. `offline_access` appears only as a default entry of `OIDC_SUPPORTED_SCOPES` (`internal/config/config.go` ~line 775) and is echoed in discovery; no code checks it.

`code.Scopes` holds the scopes granted at login/consent (`internal/oidc/consent_service.go`). `OIDCTokenResponse.RefreshToken` (`internal/api/services.go` ~line 198) is already `omitempty`.

OpenID Connect Core §11: refresh tokens for offline access are issued only when `offline_access` is requested and granted.

## Implementation Plan

1. Add a token method that mints an access token with no refresh token for a client (for example `IssueAccessTokenForClient(ctx, subject, roles, scopes, clientType, clientID, audience...)` in `internal/token/service.go`), and add it to the `TokenIssuer` interface in `internal/oidc/deps.go`.
2. In `ExchangeCode`: if `containsScope(code.Scopes, "offline_access")` call `IssueTokenPairForClient` (as today); otherwise call the new access-only method. The response then omits `refresh_token`.
3. Keep `offline_access` in `OIDC_SUPPORTED_SCOPES` and keep `refresh_token` in discovery `grant_types_supported`.
4. README and `deployments/README.md`: one sentence stating that OIDC clients must request `offline_access` (and have it in their client scopes) to receive a refresh token.

## Technical Decisions

- The decision uses the granted `code.Scopes`, never the raw request.
- No change to `/auth/login`, `/auth/token` or `/auth/refresh` (first-party flows keep their refresh tokens).

## Dependencies

Start after #533 merges: both change `internal/oidc/provider_service.go`, `internal/oidc/fakes_test.go` and `e2e/oidc_flow_test.go`. #542 builds on this issue.

## Verify

- `internal/oidc/provider_service_test.go`:
  - code with `openid offline_access` → response has `refresh_token`;
  - code with `openid` only → no `refresh_token`, access token and ID token present;
  - update the existing assertions that expect `resp.RefreshToken == "rt"` (seed `offline_access` where the test needs a refresh token), including the `PersistsClientIDForRefresh` test.
- `e2e/oidc_flow_test.go`: the flow without `offline_access` returns no `refresh_token`; with `offline_access` it returns one and `POST /auth/refresh` (or the refresh grant) works with it.

## Done

- All Verify items pass; `go build ./...`, `go vet ./...`, `go test -race ./...` and the e2e job are green.
- One PR, conventional-commit title equal to the issue title.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/541
- Hardening batch 2026-10-26 (follow-up to #524–#535).
