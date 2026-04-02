#!/usr/bin/env bash
# rollback.sh — Rollback auth-service to the previous deployment
#
# Usage:
#   ./scripts/rollback.sh <staging|production>
#
# Reverts to the image tag saved during the last deployment.
# Target: complete rollback within 30 seconds.
# Exits non-zero on failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"
STATE_DIR="$PROJECT_ROOT/.deploy-state"

# Health check — aggressive timing for fast rollback
HEALTH_URL="http://localhost:4000/health"
MAX_RETRIES=5
INITIAL_BACKOFF=1

die() {
    echo "ROLLBACK FAILED: $*" >&2
    exit 1
}

info() {
    echo "[rollback] $*"
}

ENV="${1:-}"
if [[ -z "$ENV" ]] || [[ "$ENV" != "staging" && "$ENV" != "production" ]]; then
    echo "Usage: $0 <staging|production>" >&2
    exit 1
fi

ENV_FILE="$PROJECT_ROOT/.env.$ENV"
COMPOSE_FILE="$DEPLOYMENTS_DIR/docker-compose.$ENV.yml"

if [[ ! -f "$ENV_FILE" ]]; then
    die "Environment file not found: $ENV_FILE"
fi
if [[ ! -f "$COMPOSE_FILE" ]]; then
    die "Compose file not found: $COMPOSE_FILE"
fi

STATE_FILE="$STATE_DIR/previous-image.$ENV"
if [[ ! -f "$STATE_FILE" ]]; then
    die "No rollback state found. Was a previous deployment made with deploy.sh?"
fi

PREVIOUS_IMAGE=$(cat "$STATE_FILE")
if [[ -z "$PREVIOUS_IMAGE" ]]; then
    die "Rollback state file is empty: $STATE_FILE"
fi

# Source environment
set -a
source "$ENV_FILE"
set +a

COMPOSE_CMD="docker compose -f $COMPOSE_FILE"

# Health check with exponential backoff (shorter timeouts for rollback speed)
health_check() {
    local retries=0
    local backoff=$INITIAL_BACKOFF

    info "Waiting for service to become healthy..."
    while [[ $retries -lt $MAX_RETRIES ]]; do
        if curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
            info "Health check passed."
            return 0
        fi

        retries=$((retries + 1))
        if [[ $retries -lt $MAX_RETRIES ]]; then
            info "Health check attempt $retries/$MAX_RETRIES failed, retrying in ${backoff}s..."
            sleep "$backoff"
            backoff=$((backoff * 2))
        fi
    done

    die "Health check failed after $MAX_RETRIES attempts"
}

info "Rolling back auth-service ($ENV) to: $PREVIOUS_IMAGE"

SECONDS=0

# Override the image and restart
if [[ "$ENV" == "production" ]]; then
    info "Reverting to previous image..."
    AUTH_SERVICE_IMAGE="$PREVIOUS_IMAGE" $COMPOSE_CMD up -d auth-service
else
    # Staging builds from source — rebuild from the previous state
    # For staging, rollback redeploys current compose config (git revert handles the code)
    info "Restarting auth-service from current compose state..."
    $COMPOSE_CMD up -d --force-recreate auth-service
fi

# Health check
health_check

ELAPSED=$SECONDS
info "Rollback completed in ${ELAPSED}s (target: <30s)."
if [[ $ELAPSED -gt 30 ]]; then
    info "WARNING: Rollback exceeded 30s target."
fi
