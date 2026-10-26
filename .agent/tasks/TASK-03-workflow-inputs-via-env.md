# TASK-03: ci(deploy): pass tag names and dispatch inputs to shell through env and validate them

**Created:** 2026-10-26
**Status:** ✅ Merged as #549 (reviewed 2026-10-26: clean)
**Last Updated:** 2026-10-26

## Context

Two workflows expand `${{ … }}` expressions that carry ref names or `workflow_dispatch` inputs directly inside `run:` scripts. The shell then parses those values as code, not as data.

- `.github/workflows/deploy-quantflow-aws.yml`
  - ~line 64: `SRC_TAG="${{ inputs.image_tag || github.event.workflow_run.head_branch }}"` (mirror job).
  - ~line 71: `-u "${{ github.actor }}"`.
  - ~lines 125 and 178: `ImageTag="${{ needs.mirror.outputs.tag }}"` (derived from `SRC_TAG`).
  - ~lines 157-158: `${{ inputs.force_version }}` inside an `if` test and inside the escaped JSON passed to `aws ecs run-task --overrides`; `$1` is also expanded unquoted in `run_migrate` (~line 148).
  - The only gate on the `workflow_run` path is the `if:` at ~line 48 (`startsWith(head_branch, 'v')`).
- `.github/workflows/release.yml`
  - ~line 200 (`trigger-canary` job): `-F 'client_payload[tag]=${{ github.ref_name }}'`.
  - ~line 164: `"${{ steps.version.outputs.version }}"` (computed by us; move for consistency).

All three `workflow_dispatch` inputs of the deploy workflow are `type: string` with no format check. `image_tag` is meant to be `vX.Y.Z`; `force_version` is a golang-migrate schema version (integer) used by `/auth-migrate force <N>`.

All 94 existing tags match `^v[0-9]+\.[0-9]+\.[0-9]+$` (checked 2026-10-26).

## Implementation Plan

1. `.github/workflows/deploy-quantflow-aws.yml`, mirror job: add a first step "Validate tag" that reads the tag from `env:` (`SRC_TAG: ${{ inputs.image_tag || github.event.workflow_run.head_branch }}`) and fails unless it matches `^v[0-9]+\.[0-9]+\.[0-9]+$`. Use `SRC_TAG` from `env:` in every later step instead of the inline expression.
2. Same file: pass `github.actor`, `needs.mirror.outputs.tag` and `github.run_id` through `env:` wherever they appear in `run:` bodies.
3. Same file, migrate job: pass `inputs.force_version` through `env:` (`FORCE_VERSION`); when non-empty, fail unless it matches `^[0-9]+$`. Build the `--overrides` JSON with `jq -n --arg` (or `printf` with the validated integer), not by string concatenation. Quote `"$1"` in `run_migrate`.
4. `.github/workflows/release.yml`: pass `github.ref_name` (line ~200) and `steps.version.outputs.version` (line ~164) through `env:` and reference them as `"$VAR"`.
5. Add an actionlint config (a new actionlint YAML config in the `.github` directory) that declares the custom runner label `aws-quantflow-deployer`, so `actionlint` runs without label noise. Optionally add an `actionlint` step to `.github/workflows/test.yml` (GitHub-hosted runner, pinned by commit SHA).

## Technical Decisions

- **Do not rename or move `.github/workflows/deploy-quantflow-aws.yml`, and keep `name: Deploy QuantFlow AWS`.** The self-hosted runner group accepts only this workflow file at `refs/heads/main`; a renamed file gets no runner.
- Keep `concurrency: group: deploy-auth-service`, the `environment: aws-quantflow` on the deploy job, all `runs-on` labels and job names unchanged.
- Strict tag regex without a pre-release suffix: no tag in the repo uses one.
- Behaviour for valid inputs must not change. This is a pure input-handling change.

## Dependencies

None. Independent of the Go code issues (#524–#535); touches only `.github/`.

## Verify

- `actionlint` over every workflow file reports no new errors (shellcheck warnings that existed before may remain; do not add new ones).
- A grep over every workflow file for `${{ inputs.`, `${{ github.event.`, `${{ github.ref_name`, `${{ github.head_ref` and `${{ github.actor` shows matches only in `env:`, `if:` or `with:` lines, never inside a `run:` body.
- Offline check of the validation snippet (a small shell test or the PR description shows it): `v0.76.0` accepted; `v$(id)`, `v1;x`, `main` rejected; `force_version` `5` accepted, `5"]};x` rejected.
- Do not trigger a real deploy to test.

## Done

- All Verify items pass; existing CI (`.github/workflows/test.yml`, `.github/workflows/spectral.yml`) is green.
- One PR, conventional-commit title equal to the issue title.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/538
- Hardening batch 2026-10-26 (follow-up to #524–#535).
