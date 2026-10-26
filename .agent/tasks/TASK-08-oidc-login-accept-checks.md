# TASK-08: fix(oidc): check subject and client state when the login challenge is accepted, and audit the decision

**Created:** 2026-10-26
**Status:** 🚀 Dispatched to Pilot (label `pilot` added 2026-10-26 after #533 merged as #544)
**Last Updated:** 2026-10-26

## Context

The login UI accepts a login challenge with `PUT /admin/oauth/auth/requests/login?login_challenge=…&accept=true` (`internal/api/admin_router.go` ~line 206, `internal/api/admin_consent_handlers.go` ~lines 40-82). `ConsentService.AcceptLogin` (`internal/oidc/consent_service.go` ~line 84):

- consumes the challenge and loads the client, but does not check `client.IsActive()`;
- does not look up `req.Subject` (`AcceptLoginRequest`, `internal/api/services.go` ~line 237): an unknown, locked or deleted user id still gets an authorization code;
- emits no audit event (accept/reject login and reject consent are not audited).

`ConsentService` has no `UserLookup` (the interface exists in `internal/oidc/deps.go`; `ProviderService` already receives the user repository in `cmd/server/main.go`). At code exchange, `ProviderService.ExchangeCode` (`internal/oidc/provider_service.go` ~line 233) checks that the user exists but not that the user is active.

## Implementation Plan

1. Add a `UserLookup` argument to `NewConsentService` and pass the user repository in `cmd/server/main.go` (same instance `ProviderService` gets). Update `newTestConsentService` in `internal/oidc/consent_service_test.go`.
2. In `AcceptLogin`, after the client lookup:
   - reject if `!client.IsActive()`;
   - look up the subject in the tenant; reject if not found or not active (locked, suspended, deleted) — `api.ErrNotFound` for unknown, `api.ErrForbidden` for inactive.
3. In `ExchangeCode`, after the user lookup: reject with the existing `ErrUnauthorized` if the user is not active.
4. Audit: add event constants in `internal/audit/audit.go` (e.g. `EventOIDCLoginAccept`, `EventOIDCLoginReject`, `EventOIDCConsentReject`) and log them from `AcceptLogin`, `RejectLogin` and `RejectConsent` with subject, client_id, whether consent was skipped, and the first 8 hex chars of SHA-256(challenge). Never log the challenge itself. `ConsentService` already has an `audit.EventLogger`.

## Technical Decisions

- No change to the login UI contract (request and response bodies stay the same); only invalid subjects/clients now get an error.
- Browser binding of the challenge (Hydra-style `login_csrf` cookie) is out of scope: the accept call is server-to-server from the login UI, so it needs a login UI change. Admin API authentication is #524.
- `req.Remember` stays a no-op (documented in the code).

## Dependencies

Start after #533 merges (both change `internal/oidc/consent_service.go` and its tests; different functions). Independent of #524; if #524 lands first, add the admin caller identity to the audit event.

## Verify

- `internal/oidc/consent_service_test.go`: accept login with unknown subject → not found; locked subject → forbidden; inactive client → error; valid subject → code issued as before; audit event emitted with subject and client_id and without the challenge.
- `internal/oidc/provider_service_test.go`: exchange for a user locked after the code was issued → unauthorized.
- `e2e/oidc_flow_test.go` still passes unchanged.

## Done

- All Verify items pass; `go build ./...`, `go vet ./...`, `go test -race ./...` and the e2e job are green.
- One PR, conventional-commit title equal to the issue title.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/543
- Hardening batch 2026-10-26 (follow-up to #524–#535).
