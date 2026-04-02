#!/usr/bin/env bash
# pre-deploy.sh — Pre-deployment validation gate
#
# Usage:
#   ./scripts/pre-deploy.sh <staging|production>
#
# Runs test suite, linting, and build verification.
# Exits non-zero on any failure, blocking deployment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    echo "PRE-DEPLOY FAILED: $*" >&2
    exit 1
}

info() {
    echo "[pre-deploy] $*"
}

ENV="${1:-}"
if [[ -z "$ENV" ]] || [[ "$ENV" != "staging" && "$ENV" != "production" ]]; then
    echo "Usage: $0 <staging|production>" >&2
    exit 1
fi

ENV_FILE="$PROJECT_ROOT/.env.$ENV"
if [[ ! -f "$ENV_FILE" ]]; then
    die "Environment file not found: $ENV_FILE"
fi

info "Running pre-deploy checks for $ENV environment..."

# Source environment for any env-dependent build tags
set -a
source "$ENV_FILE"
set +a

cd "$PROJECT_ROOT"

# Step 1: Build verification
info "Step 1/3: Build verification..."
if ! go build -o /dev/null ./cmd/server/main.go 2>&1; then
    die "Build failed"
fi
info "Build: OK"

# Step 2: Linting
info "Step 2/3: Running linter..."
if command -v golangci-lint >/dev/null 2>&1; then
    if ! golangci-lint run ./... 2>&1; then
        die "Linting failed"
    fi
    info "Lint: OK"
else
    info "Lint: SKIPPED (golangci-lint not found)"
fi

# Step 3: Test suite
info "Step 3/3: Running tests..."
if ! go test -race -count=1 ./... 2>&1; then
    die "Tests failed"
fi
info "Tests: OK"

info "All pre-deploy checks passed for $ENV."
