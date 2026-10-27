# TASK-09: ci: pin the Go toolchain, add a govulncheck gate, and pin actions and base images

**Created:** 2026-10-26
**Status:** ✅ Merged as #553 (not reviewed by Navigator)
**Last Updated:** 2026-10-27

## Context

#532 planned four changes. Only the module bumps reached main (PR #547). These items are still open:

1. **Toolchain.** `go.mod` declares `go 1.26.0` and has no `toolchain` line. CI installs Go from it (`actions/setup-go` with `go-version-file: go.mod` in `.github/workflows/test.yml`, lines ~21 and ~36), so tests run on go1.26.0. `govulncheck ./...` with go1.26.0 reports 37 reachable standard-library vulnerabilities; with go1.26.10 it reports 0 (checked 2026-10-26). The release image already builds with go1.26.10, because `docker/Dockerfile` uses the floating tag `golang:1.26-alpine`.
2. **No govulncheck gate.** No workflow runs `govulncheck`.
3. **Actions pinned by tag.** 18 `uses:` lines in `.github/workflows/release.yml`, `.github/workflows/test.yml` and `.github/workflows/spectral.yml` use a tag (`@v4`, `@v5`, `@v6`, `@v3`) or `@latest` (`stoplightio/spectral-action@latest`).
4. **Base images pinned by tag.** `docker/Dockerfile` (lines 6, 27) and `docker/Dockerfile.smoke` (lines 23, 45) use `golang:1.26-alpine` and `alpine:3.21`.

## Implementation Plan

1. `go.mod`: add `toolchain go1.26.10` below the `go` line. Do NOT raise the `go` line: it is the minimum Go version for consumers of `pkg/authclient`, and `toolchain` does not affect them.
2. `.github/workflows/test.yml`: add a job `govulncheck` on `ubuntu-latest` that fails on any reachable vulnerability:
   ```yaml
   govulncheck:
     name: govulncheck
     runs-on: ubuntu-latest
     steps:
       - uses: golang/govulncheck-action@032d45514ae346b1db93c04b0c90b841c370344f # v1.1.0
         with:
           go-version-file: go.mod
           go-package: ./...
   ```
3. Pin every `uses:` in `.github/workflows/release.yml`, `.github/workflows/test.yml` and `.github/workflows/spectral.yml` to these commit SHAs (resolved from the release tags on 2026-10-26), keeping the tag as a comment:
   - `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`
   - `actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5.6.0`
   - `docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130 # v3.7.0`
   - `docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f # v3.12.0`
   - `docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9 # v3.7.0`
   - `docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051 # v5.10.0`
   - `docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8 # v6.19.2`
   - `stoplightio/spectral-action@6416fd018ae38e60136775066eb3e98172143141 # v0.8.13`
4. Pin the base images in `docker/Dockerfile` and `docker/Dockerfile.smoke` by multi-arch index digest, keeping the tag:
   - `golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba`
   - `alpine:3.21@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd`
5. Add a Dependabot version-updates config (new file in the `.github` directory) with weekly updates for `github-actions` (directory `/`), `docker` (directory `/docker`) and `gomod` (directory `/`). Without it, the digest pins freeze the base images and Go patch updates stop.

## Technical Decisions

- Pins replace floating tags, so the build is reproducible; Dependabot keeps them current.
- `toolchain` instead of a higher `go` line: no new minimum for SDK consumers.
- Do not change `.github/workflows/deploy-quantflow-aws.yml`: it has no `uses:` lines, and #538 owns that file.
- Keep job names `test` and `e2e` unchanged (branch protection or required checks may refer to them).

## Dependencies

Start after #538 merges: both change `.github/workflows/release.yml` and `.github/workflows/test.yml`.

## Verify

- The CI log of the `test` job shows `go version go1.26.10`.
- The new `govulncheck` job passes on the PR (0 reachable vulnerabilities).
- A grep over all workflow files for `uses:` lines that end with `@v<digit>`, `@main` or `@latest` returns nothing.
- `docker build -f docker/Dockerfile .` and `docker build -f docker/Dockerfile.smoke .` succeed; the `e2e` job is green.
- `actionlint` over every workflow file reports no new errors.

## Done

- All Verify items pass; existing CI (`test`, `e2e`, spectral) is green.
- One PR, conventional-commit title equal to the issue title.

## Refs

- Pilot issue: https://github.com/qf-studio/auth-service/issues/552
- Remaining scope of #532 (only the module bumps merged, in #547).
- Hardening batch 2026-10-26.
