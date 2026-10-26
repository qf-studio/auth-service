# TASK-10: ops(deploy): provision the production secrets and settings for hardening waves 2 and 3

**Created:** 2026-10-26
**Status:** 📋 Issue #568, assigned to Nelya (human ops task, no `pilot` label)
**Last Updated:** 2026-10-26

## Context

Hardening waves 2 and 3 add new configuration. Every release deploys to production automatically after the `aws-quantflow` approval, so the values must exist before the operator flips the strict switches. None of these changes takes production down when the value is missing; each one degrades to a WARN or a disabled endpoint:

| Variable | Issue | Kind | Behaviour when unset |
|---|---|---|---|
| `ADMIN_API_TOKENS` | #524 | secret, comma-separated, each ≥ 32 bytes | `/admin/*` returns 503 `admin_api_disabled`, one ERROR at startup |
| `GRPC_CLIENT_TOKENS` | #525 | secret, comma-separated, each ≥ 32 bytes | gRPC callers are not authenticated |
| `GRPC_AUTH_MODE` | #525 | plain env: `off` / `warn` / `enforce` | default `warn`: unauthenticated calls pass and log a WARN |
| `REDIS_PASSWORD` | #530 | secret | WARN at startup (`CONFIG_STRICT=false`) |
| `REDIS_TLS` | #530 | plain env, `true` | WARN at startup |
| `DATA_ENCRYPTION_KEY` | #531 | secret, 32 bytes, base64 | TOTP and webhook secrets stay plaintext, WARN at startup |
| `CONFIG_STRICT` | #530/#531 | plain env, `true` | default `false`: production rules only log WARN lines |

Where production configuration lives:

- Secrets are SSM Parameter Store SecureString parameters under `/quantflow/auth/<NAME>` (same as the existing `SYSTEM_SECRETS`, `PASSWORD_PEPPER`, `JWT_PRIVATE_KEY`).
- The ECS task definitions come from the CloudFormation template that the deploy workflow downloads from `$TEMPLATE_BASE/auth-service.yml` (`.github/workflows/deploy-quantflow-aws.yml`). The template is not in this repo. It registers two task definitions, `TaskDefinition` and `MigrationTaskDefinition`; both carry the same `Environment` and `Secrets` lists.
- The admin API port 4001 is deliberately not mapped in production. gRPC port 4002 is served through the internal NLB.

## Implementation Plan

1. **Template access.** Get read/write access to the stack template object (it is KMS-encrypted; the `aleks` IAM user gets `kms:Decrypt` AccessDenied), or find the pipeline that uploads it. Record the template's source of truth in the TASK-10 notes below.
2. **Execution role.** Confirm the ECS task execution role can read new parameters under `/quantflow/auth/` (wildcard or per-parameter grant). Extend it if not.
3. **Before #524 deploys:** create `/quantflow/auth/ADMIN_API_TOKENS` (`openssl rand -hex 32`). Add it to `Secrets` in both task definitions. Hand the token to the login UI owner only when :4001 gets a caller.
4. **Before #525 deploys:** create `/quantflow/auth/GRPC_CLIENT_TOKENS` with one token per gRPC caller. Add it to `Secrets`. Add `GRPC_AUTH_MODE=warn` to `Environment`. Give each caller its token. Set `enforce` only after the WARN lines stop.
5. **Before #530 deploys:** check whether the ElastiCache cluster supports AUTH and in-transit encryption without replacement. Plan the change window if it needs a new cluster. Then create `/quantflow/auth/REDIS_PASSWORD` and set `REDIS_TLS=true`.
6. **Before #531 deploys:** create `/quantflow/auth/DATA_ENCRYPTION_KEY` (`openssl rand -base64 32`). Back the key up outside SSM: losing it makes encrypted TOTP secrets unreadable.
7. **Last:** after a deploy shows no config WARN lines in `/quantflow/auth-service` logs, set `CONFIG_STRICT=true`.

## Technical Decisions

- Never put secret values in GitHub issues, PRs, Slack or this repo (the repo is public). Share tokens with callers through a secret manager.
- Plain settings (`GRPC_AUTH_MODE`, `REDIS_TLS`, `CONFIG_STRICT`) go in `Environment`, not in SSM.
- Each strict switch is flipped in its own deploy, so a failure points to one change.

## Dependencies

- Steps 3–6 each must finish before the matching release deploys. The deploy waits for the `aws-quantflow` approval, so the operator can hold a release until its secret exists.
- Wave 3 (#528–#531) is not labeled for Pilot yet.

## Verify

- `aws ecs describe-task-definition` for the service and migrate families lists the new names under `secrets` (names only; do not print values).
- After #524 deploys: `/admin/*` returns 401 without a bearer and not 503.
- After #525 deploys with `warn`: the gRPC WARN count drops to zero once callers send tokens; then `enforce`.
- After `CONFIG_STRICT=true`: the service starts and `/health` returns 200.

## Done

- All seven variables are set in production, `CONFIG_STRICT=true` and `GRPC_AUTH_MODE=enforce` are live, and the template source of truth is recorded.

## Notes

- Template source of truth: _(fill in)_

## Refs

- Issue: https://github.com/qf-studio/auth-service/issues/568
- Hardening batch 2026-10-26: #524, #525, #530, #531.
