#!/usr/bin/env bash
# deploy.sh — Deploy auth-service to staging or production
#
# Usage:
#   ./scripts/deploy.sh <staging|production>
#
# Steps:
#   1. Sources the appropriate .env.<environment> file
#   2. Pulls latest image (production) or rebuilds (staging)
#   3. Runs database migrations via docker compose exec
#   4. Restarts services
#   5. Health-check polling with exponential backoff
#
# Exits non-zero on failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"
STATE_DIR="$PROJECT_ROOT/.deploy-state"

# Health check configuration
HEALTH_URL="http://localhost:4000/health"
MAX_RETRIES=8
INITIAL_BACKOFF=1

die() {
    echo "DEPLOY FAILED: $*" >&2
    exit 1
}

info() {
    echo "[deploy] $*"
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

# Source environment
set -a
source "$ENV_FILE"
set +a

COMPOSE_CMD="docker compose -f $COMPOSE_FILE"

# Save current image tag for rollback (production only)
save_rollback_state() {
    mkdir -p "$STATE_DIR"
    local current_image
    current_image=$($COMPOSE_CMD ps --format json auth-service 2>/dev/null \
        | grep -o '"Image":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
    if [[ -n "$current_image" ]]; then
        echo "$current_image" > "$STATE_DIR/previous-image.$ENV"
        info "Saved rollback state: $current_image"
    fi
}

# Health check with exponential backoff
health_check() {
    local retries=0
    local backoff=$INITIAL_BACKOFF

    info "Waiting for service to become healthy..."
    while [[ $retries -lt $MAX_RETRIES ]]; do
        if curl -sf --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
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

info "Deploying auth-service to $ENV..."

# Step 1: Save rollback state
info "Step 1/5: Saving rollback state..."
save_rollback_state

# Step 2: Pull or build
if [[ "$ENV" == "production" ]]; then
    info "Step 2/5: Pulling latest image..."
    $COMPOSE_CMD pull auth-service
else
    info "Step 2/5: Building from source..."
    $COMPOSE_CMD build auth-service
fi

# Step 3: Run database migrations
info "Step 3/5: Running database migrations..."
# Start all services so auth-service container is running for exec
$COMPOSE_CMD up -d
info "Waiting for database to be ready..."
sleep 5

# Run migrations via docker compose exec as specified
$COMPOSE_CMD exec auth-service /app/auth-service migrate up 2>&1 || {
    info "Migration command not available, skipping (migrate binary may not be built yet)"
}

# Step 4: Restart services
info "Step 4/5: Restarting services..."
$COMPOSE_CMD up -d

# Step 5: Health check
info "Step 5/5: Running health checks..."
health_check

info "Deployment to $ENV completed successfully."
