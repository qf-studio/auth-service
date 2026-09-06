# Auth Service — Deployment Guide

Deployment documentation for the QuantFlow Studio auth service.
Covers staging and production environments, secrets management, monitoring, rollback, and troubleshooting.

---

## Table of Contents

- [Infrastructure Requirements](#infrastructure-requirements)
- [Prerequisites](#prerequisites)
- [Secrets Management](#secrets-management)
- [Deployment Guide](#deployment-guide)
  - [Staging](#staging-deployment)
  - [Production](#production-deployment)
- [Running Migrations from the Image](#running-migrations-from-the-image)
- [Verifying a Live Deployment (Smoke Image)](#verifying-a-live-deployment-smoke-image)
- [Monitoring](#monitoring)
- [Rollback Procedures](#rollback-procedures)
- [Troubleshooting](#troubleshooting)

---

## Infrastructure Requirements

### Server Specifications

| Component | Staging | Production |
|-----------|---------|------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 20 GB SSD | 50+ GB SSD |
| OS | Linux (amd64) | Linux (amd64) |

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Docker Engine | 24+ | Container runtime |
| Docker Compose | v2+ | Service orchestration (`docker compose`, not `docker-compose`) |
| OpenSSL | 3.x | JWT key generation |
| curl | any | Health check polling |
| Go | 1.24+ | Pre-deploy checks (build, test, lint) |
| golangci-lint | latest | Linting (optional, skipped if absent) |

### Database & Cache

| Service | Version | Notes |
|---------|---------|-------|
| PostgreSQL | 16+ | `postgres:16-alpine` image. Staging: exposed on port 5432. Production: internal-only. |
| Redis | 7+ | `redis:7-alpine` image. Staging: exposed on port 6379. Production: internal-only, AOF persistence. |

### TLS Certificate

- **Staging**: no TLS termination in the compose stack; Caddy is not included in the staging stack.
- **Production**: Caddy 2 handles automatic TLS via ACME (Let's Encrypt). Requires:
  - A valid domain pointing to the server (e.g., `auth.quantflow.studio`)
  - Port 80 and 443 open for ACME challenge and HTTPS
  - `TLS_EMAIL` set for Let's Encrypt account registration

### Network Ports

| Port | Environment | Purpose |
|------|-------------|---------|
| 4000 | Both | Public API (auth endpoints) |
| 4001 | Both | Admin API (metrics, management) |
| 80 | Production | HTTP → HTTPS redirect (Caddy) |
| 443 | Production | HTTPS termination (Caddy) |
| 5432 | Staging only | PostgreSQL (not exposed in production) |
| 6379 | Staging only | Redis (not exposed in production) |

---

## Prerequisites

### 1. Generate JWT Signing Keys

The service uses ES256 (P-256 ECDSA) for JWT signing. Generate a key pair:

```bash
./scripts/generate-keys.sh --out-dir ./keys --name jwt
```

This creates:
- `keys/jwt.private.pem` — Private key (mode 600), used for signing tokens
- `keys/jwt.public.pem` — Public key (mode 644), used for verification and JWKS

The script validates the key pair by performing a sign-and-verify round trip.

Set the key path in your environment file:
```bash
JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private_key
```

### 2. Generate Secrets

Generate required secrets using the provided script:

```bash
# Password hashing pepper (hex, 32 bytes)
./scripts/generate-secret.sh --name PASSWORD_PEPPER --bytes 32 --format hex --out .env.production

# System secrets for client credential signing
./scripts/generate-secret.sh --name SYSTEM_SECRETS --bytes 32 --format hex --out .env.production
```

Options:
- `--bytes N` — Entropy size (default: 32 → 64 hex characters)
- `--format hex|base64|base64url` — Output encoding
- `--out FILE` — Append to file (replaces existing entry if present)
- `--force` — Overwrite existing entry

### 3. Prepare Environment File

Copy the appropriate example file and fill in all `CHANGE_ME` values:

```bash
# Staging
cp .env.staging.example .env.staging

# Production
cp .env.production.example .env.production
```

See [Environment Variables Reference](#environment-variables-reference) for the full list.

---

## Secrets Management

### Phase 1: Environment Variables (Current)

All secrets are stored in `.env.<environment>` files on the host:

| Secret | Description | Generation |
|--------|-------------|------------|
| `POSTGRES_PASSWORD` | Database password | Manual — use a strong random password |
| `REDIS_PASSWORD` | Cache password | Manual — use a strong random password |
| `PASSWORD_PEPPER` | Argon2id HMAC pepper | `./scripts/generate-secret.sh --name PASSWORD_PEPPER` |
| `SYSTEM_SECRETS` | Client credential secrets (comma-separated, newest first) | `./scripts/generate-secret.sh --name SYSTEM_SECRETS` |
| `JWT_PRIVATE_KEY_PATH` | Path to PEM private key | `./scripts/generate-keys.sh` |

Security practices:
- `.env.*` files are gitignored — never commit them
- Set file permissions: `chmod 600 .env.production`
- The private key file should be mode 600, owned by the service user
- Rotate `SYSTEM_SECRETS` by prepending a new value (comma-separated, newest first)

### Phase 3: HashiCorp Vault (Upgrade Path)

For production hardening, migrate to Vault for dynamic secrets:

1. **Database credentials** — Use Vault's PostgreSQL secrets engine for short-lived credentials with automatic rotation
2. **JWT keys** — Store in Vault's Transit engine or KV v2 with versioning
3. **Password pepper** — Store in KV v2; version changes require re-hashing (plan a migration)
4. **Redis password** — Use Vault's KV with a sidecar agent for injection

Migration approach:
- Deploy Vault alongside the auth service
- Use Vault Agent sidecar to inject secrets as environment variables
- No application code changes required — the service reads env vars regardless of source
- Enable Vault audit logging for secret access tracking

---

## Deployment Guide

### Staging Deployment

Staging builds from source and exposes all ports for development access.

#### Initial Setup

```bash
# 1. Prepare environment
cp .env.staging.example .env.staging
# Edit .env.staging — fill in CHANGE_ME values

# 2. Generate JWT keys
./scripts/generate-keys.sh --out-dir ./keys --name jwt

# 3. Generate secrets
./scripts/generate-secret.sh --name PASSWORD_PEPPER --bytes 32 --format hex --out .env.staging
./scripts/generate-secret.sh --name SYSTEM_SECRETS --bytes 32 --format hex --out .env.staging

# 4. Run pre-deploy checks
./scripts/pre-deploy.sh staging

# 5. Deploy
./scripts/deploy.sh staging
```

#### What `deploy.sh staging` Does

1. Validates that `.env.staging` and `deployments/docker-compose.staging.yml` exist
2. Sources the environment file
3. Saves current container image tag to `.deploy-state/previous-image.staging` (for rollback)
4. Builds the auth-service image from source (`docker compose build`)
5. Starts the postgres and redis dependencies (`docker compose up -d postgres redis`)
6. Runs database migrations (`docker compose run --rm --entrypoint /auth-migrate auth-service up`), aborting before the restart step on failure
7. Restarts all services, including auth-service (`docker compose up -d`)
8. Polls `http://localhost:4000/health` with exponential backoff (up to 8 retries, ~2 min max)
9. Exits non-zero if health check fails

#### Staging Compose Services

| Service | Image | Ports | Resources |
|---------|-------|-------|-----------|
| auth-service | Built from `docker/Dockerfile` | 4000, 4001 (all interfaces) | 1 CPU / 512 MB |
| postgres | postgres:16-alpine | 5432 | Default |
| redis | redis:7-alpine | 6379 | 128 MB maxmemory |

### Production Deployment

Production pulls a pre-built image, runs behind Caddy with TLS, and applies strict security hardening.

#### Initial Setup

```bash
# 1. Prepare environment
cp .env.production.example .env.production
# Edit .env.production — fill in ALL values (no defaults for credentials)

# 2. Generate JWT keys
./scripts/generate-keys.sh --out-dir ./keys --name jwt

# 3. Generate secrets
./scripts/generate-secret.sh --name PASSWORD_PEPPER --bytes 32 --format hex --out .env.production
./scripts/generate-secret.sh --name SYSTEM_SECRETS --bytes 32 --format hex --out .env.production

# 4. Configure DNS
# Point auth.quantflow.studio → server IP
# Point auth-admin.quantflow.studio → server IP

# 5. Run pre-deploy checks
./scripts/pre-deploy.sh production

# 6. Deploy
./scripts/deploy.sh production
```

#### What `deploy.sh production` Does

1. Validates that `.env.production` and `deployments/docker-compose.production.yml` exist
2. Sources the environment file
3. Saves current container image tag for rollback
4. Pulls the latest image (`docker compose pull auth-service`)
5. Starts all services
6. Runs database migrations
7. Health check with exponential backoff
8. Exits non-zero on failure

#### Production Compose Services

| Service | Image | Ports | Resources | Security |
|---------|-------|-------|-----------|----------|
| auth-service | `${AUTH_SERVICE_IMAGE}` | 127.0.0.1:4000, 127.0.0.1:4001 | 2 CPU / 1 GB | Read-only filesystem, no-new-privileges, 64 MB tmpfs |
| postgres | postgres:16-alpine | None (internal) | Default | Read-only filesystem, no-new-privileges |
| redis | redis:7-alpine | None (internal) | 256 MB maxmemory, AOF | Read-only filesystem, no-new-privileges |
| caddy | caddy:2-alpine | 80, 443 | Default | Depends on auth-service healthy |

#### Production Security Hardening

- **No exposed database ports** — PostgreSQL and Redis are accessible only within the Docker network
- **Read-only filesystems** — All containers use read-only root filesystems with minimal tmpfs mounts
- **No-new-privileges** — Prevents privilege escalation inside containers
- **Localhost-only API ports** — Auth service ports 4000/4001 bind to 127.0.0.1; Caddy handles external traffic
- **Admin IP allowlisting** — Caddy restricts admin API access to `ADMIN_ALLOWED_IPS` (default: RFC 1918 ranges)
- **Security headers** — HSTS (2 years + preload), X-Content-Type-Options, X-Frame-Options: DENY, restrictive CSP
- **TLS 1.3** — Caddy auto-provisions certificates via Let's Encrypt
- **PostgreSQL SSL** — `POSTGRES_SSLMODE=require` enforces encrypted DB connections

#### Running Behind an AWS ALB (TLS-terminating load balancer)

Deployments that terminate TLS in front of the service (e.g. an AWS ALB in
front of `auth.quantflow.studio`, rather than the Caddy setup above) receive
only plaintext HTTP at the container — `Request.TLS` is always nil. Without
further configuration the server reconstructs every request URL as
`http://...`, which breaks DPoP proof validation: a correct client always
signs its proof against the public `https://...` URL, so the `htu` scheme
never matches and every DPoP-bound request is rejected (GH-508).

Set `TRUSTED_PROXY_CIDRS` to the VPC CIDR(s) the ALB's target group lives in
so the server trusts the ALB's `X-Forwarded-Proto` / `X-Forwarded-Host`
headers when reconstructing the request URL. Leave it unset (the default) for
any deployment where the load balancer's peer address isn't otherwise
trusted — the headers are then ignored and the scheme falls back to
`Request.TLS`, same as before this setting existed. Do not set it to `0.0.0.0/0`
or anything broader than the actual proxy network: any peer inside a trusted
CIDR can spoof the scheme seen by DPoP validation.

---

## Running Migrations from the Image

The published image is self-contained: it ships a second binary, `/auth-migrate`, alongside `/auth-service`. `/auth-migrate` embeds the full migration SQL set at compile time, so any consumer can migrate a database using only the image and environment variables — no checkout of this repo, no vendored `migrations/*.sql`, no separate `migrate/migrate` container.

### Invocation

Override the image's default entrypoint (`/auth-service`) to run `/auth-migrate` instead:

```bash
docker run --rm --entrypoint /auth-migrate \
  -e DATABASE_URL=postgres://user:pass@host:5432/dbname?sslmode=require \
  ghcr.io/qf-studio/auth-service:<tag> up
```

### Required Environment

Provide database connectivity via either:

- `DATABASE_URL` — a full `postgres://` connection string, **or**
- The individual `POSTGRES_*` variables: `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` (optionally `POSTGRES_PORT`, default `5432`, and `POSTGRES_SSLMODE`, default `disable`)

If `DATABASE_URL` is set, it takes precedence over the individual `POSTGRES_*` variables.

### Subcommands

| Subcommand | Description |
|------------|--------------|
| `up` | Applies all pending migrations. |
| `down` | Rolls back the most recently applied migration. |
| `version` | Prints the current schema version, and whether the schema is left `dirty` from a failed migration. |
| `force <N>` | Forces `schema_migrations` to version `N` without running any SQL. Used to clear a dirty state after manual recovery — see below. |

### Dirty-State Recovery Example

If a migration fails partway through, `golang-migrate` marks `schema_migrations` as `dirty` and refuses further `up`/`down` calls until the dirty flag is cleared:

```bash
# 1. Confirm the dirty version
docker run --rm --entrypoint /auth-migrate -e DATABASE_URL="$DATABASE_URL" \
  ghcr.io/qf-studio/auth-service:<tag> version
# e.g. "5 (dirty)"

# 2. Inspect migration 000005's SQL and the actual table state, and
#    manually finish or revert the partial change directly in Postgres.

# 3. Clear the dirty flag by forcing the version (does not re-run SQL)
docker run --rm --entrypoint /auth-migrate -e DATABASE_URL="$DATABASE_URL" \
  ghcr.io/qf-studio/auth-service:<tag> force 5

# 4. Resume normal migrations
docker run --rm --entrypoint /auth-migrate -e DATABASE_URL="$DATABASE_URL" \
  ghcr.io/qf-studio/auth-service:<tag> up
```

---

## Verifying a Live Deployment (Smoke Image)

Every release also publishes `ghcr.io/qf-studio/auth-service-smoke:<tag>` — the same tag as the service image — a small, self-contained image that runs the live-safe subset of the E2E suite (`TestSmoke*` in `e2e/`: health/readiness, OIDC discovery + JWKS shape, register → login → refresh → logout with a throwaway user, gRPC `ValidateToken` via `pkg/authclient`) against an already-running deployment. It never touches the admin port destructively and only ever creates disposable identities, so it's safe to run repeatedly against production.

### Basic Usage

```bash
docker run --rm -e SMOKE_BASE_URL=http://host:4000 \
  ghcr.io/qf-studio/auth-service-smoke:<tag>
```

Exit code `0` means every smoke check passed; non-zero means at least one failed. Output is plain `go test -v` text, readable directly from CI or a terminal.

### Configuration

| Variable | Required | Purpose |
|----------|----------|---------|
| `SMOKE_BASE_URL` | Yes | Public API base URL to verify (e.g. `http://host:4000` or `https://auth.quantflow.studio`). |
| `SMOKE_ADMIN_URL` | No | Admin API base URL. When reachable, enables the token-introspection leg of the golden-path check. Omit for deployments where the admin port isn't network-reachable from wherever the smoke image runs. |
| `SMOKE_GRPC_ADDR` | No | `host:port` for the gRPC service. When set, exercises `ValidateToken` via `pkg/authclient`. Omit to skip the gRPC leg. |

### Full Example

```bash
docker run --rm \
  -e SMOKE_BASE_URL=https://auth.quantflow.studio \
  -e SMOKE_ADMIN_URL=http://127.0.0.1:4001 \
  -e SMOKE_GRPC_ADDR=auth.quantflow.studio:4002 \
  ghcr.io/qf-studio/auth-service-smoke:v0.72.0
```

This is the artifact issue D's canary cron and consumers like Pointer poll against instead of guessing deployment health from `/health` alone.

---

## Monitoring

### Health Endpoints

| Endpoint | Port | Purpose |
|----------|------|---------|
| `GET /health` | 4000 | General health check. Used by Docker healthcheck, Caddy, and deploy scripts. |
| `GET /liveness` | 4000 | Kubernetes-style liveness probe (is the process alive?) |
| `GET /readiness` | 4000 | Kubernetes-style readiness probe (can the service handle requests?) |

### Prometheus Metrics

Metrics are exposed on the admin port (4001):

| Endpoint | Format |
|----------|--------|
| `GET /admin/metrics` | JSON |
| `GET /admin/metrics/prometheus` | Prometheus text exposition format |

#### Prometheus Scrape Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'auth-service'
    scrape_interval: 15s
    metrics_path: '/admin/metrics/prometheus'
    static_configs:
      - targets: ['auth-service:4001']
        labels:
          service: 'auth-service'
          environment: 'production'
```

For staging with exposed ports:
```yaml
    static_configs:
      - targets: ['<staging-host>:4001']
        labels:
          environment: 'staging'
```

#### Recommended Alerting Rules

```yaml
groups:
  - name: auth-service
    rules:
      # Service is down
      - alert: AuthServiceDown
        expr: up{job="auth-service"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Auth service is unreachable"
          description: "Prometheus cannot scrape {{ $labels.instance }} for more than 1 minute."

      # Health check failing
      - alert: AuthServiceUnhealthy
        expr: auth_health_status != 1
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Auth service health check failing"

      # High request latency (p99 > 500ms)
      - alert: AuthHighLatency
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{job="auth-service"}[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Auth service p99 latency above 500ms"
          description: "p99 latency is {{ $value }}s on {{ $labels.instance }}"

      # High error rate (>5% of requests returning 5xx)
      - alert: AuthHighErrorRate
        expr: |
          sum(rate(http_requests_total{job="auth-service", status=~"5.."}[5m]))
          /
          sum(rate(http_requests_total{job="auth-service"}[5m]))
          > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Auth service error rate above 5%"
          description: "Error rate is {{ $value | humanizePercentage }} on {{ $labels.instance }}"

      # Database connection pool exhaustion
      - alert: AuthDBPoolExhausted
        expr: auth_db_pool_available_connections == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Auth service database connection pool exhausted"

      # Redis connection failure
      - alert: AuthRedisDown
        expr: auth_redis_connected != 1
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Auth service lost Redis connection"

      # High token generation rate (possible abuse)
      - alert: AuthTokenAbuseDetected
        expr: rate(auth_tokens_issued_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Unusually high token generation rate"
```

### Caddy Access Logs

In production, Caddy writes JSON access logs:
- Public API: `/data/logs/public-access.log`
- Admin API: `/data/logs/admin-access.log`
- Rotation: 10 MB per file, 5 rolling files

---

## Rollback Procedures

### Automatic Rollback

The `deploy.sh` script saves the previous image tag before each deployment. If a deployment fails or needs to be reverted:

```bash
./scripts/rollback.sh <staging|production>
```

#### What `rollback.sh` Does

1. Reads the previous image tag from `.deploy-state/previous-image.<env>`
2. Sources the environment file
3. **Production**: Overrides `AUTH_SERVICE_IMAGE` with the previous tag and restarts the service
4. **Staging**: Force-recreates the auth-service container (expects source code to be reverted via git)
5. Polls health check (5 retries, 1s initial backoff, 3s timeout)
6. Reports elapsed time — target: complete within 30 seconds
7. Warns if rollback exceeded the 30-second target

### Manual Rollback

If `rollback.sh` fails or rollback state is unavailable:

```bash
# 1. Check the previous image
cat .deploy-state/previous-image.<env>

# 2. Production: set image and restart
export AUTH_SERVICE_IMAGE=ghcr.io/qf-studio/auth-service:<previous-tag>
docker compose -f deployments/docker-compose.production.yml up -d auth-service

# 3. Staging: revert code and rebuild
git revert HEAD
docker compose -f deployments/docker-compose.staging.yml up -d --build auth-service

# 4. Verify health
curl -sf http://localhost:4000/health
```

### Database Rollback

If a migration caused the issue:

```bash
# Run migration rollback (down)
docker compose -f deployments/docker-compose.<env>.yml exec auth-service /auth-migrate down

# Verify database state
docker compose -f deployments/docker-compose.<env>.yml exec postgres psql -U <user> -d <db> -c '\dt'
```

> **Note**: Always review migration rollback SQL before executing. Some migrations (data migrations, column drops) may not be fully reversible.

---

## Troubleshooting

### Service Won't Start

**Check logs**:
```bash
docker compose -f deployments/docker-compose.<env>.yml logs auth-service
```

**Common causes**:
| Symptom | Cause | Fix |
|---------|-------|-----|
| `JWT_PRIVATE_KEY_PATH: file not found` | Key file missing or wrong path | Run `./scripts/generate-keys.sh` and verify path in `.env` |
| `connection refused` on postgres | Database not ready | Wait for health check or restart: `docker compose restart postgres` |
| `REDIS_PASSWORD: authentication failed` | Password mismatch | Ensure `REDIS_PASSWORD` matches in `.env` and Redis config |
| `bind: address already in use` | Port conflict | Check for existing processes: `lsof -i :4000` |
| Container exits immediately | Missing required env vars | Compare `.env` against `.env.<env>.example` — all `CHANGE_ME` values must be set |

### Health Check Failures

```bash
# Direct health check
curl -v http://localhost:4000/health

# Check if service is listening
docker compose -f deployments/docker-compose.<env>.yml exec auth-service wget -qO- http://localhost:4000/health

# Check container status
docker compose -f deployments/docker-compose.<env>.yml ps
```

**If health returns unhealthy**: Check that PostgreSQL and Redis are reachable from the auth-service container:
```bash
# Test DB connectivity
docker compose exec auth-service wget -qO- http://postgres:5432 2>&1 | head -1

# Test Redis connectivity
docker compose exec auth-service nc -zv redis 6379
```

### Database Issues

```bash
# Check PostgreSQL logs
docker compose -f deployments/docker-compose.<env>.yml logs postgres

# Connect to database
docker compose -f deployments/docker-compose.<env>.yml exec postgres psql -U <user> -d <db>

# Check connection pool usage (from metrics)
curl -s http://localhost:4001/admin/metrics | jq '.db_pool'

# Verify migrations applied
docker compose exec postgres psql -U <user> -d <db> -c 'SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 5;'
```

### Redis Issues

```bash
# Check Redis logs
docker compose -f deployments/docker-compose.<env>.yml logs redis

# Connect to Redis CLI
docker compose -f deployments/docker-compose.<env>.yml exec redis redis-cli -a $REDIS_PASSWORD

# Check memory usage
docker compose exec redis redis-cli -a $REDIS_PASSWORD INFO memory

# Check if Redis is rejecting writes (maxmemory hit)
docker compose exec redis redis-cli -a $REDIS_PASSWORD INFO stats | grep rejected
```

### TLS / Caddy Issues (Production)

```bash
# Check Caddy logs
docker compose -f deployments/docker-compose.production.yml logs caddy

# Test HTTPS
curl -vI https://auth.quantflow.studio/health

# Verify certificate
openssl s_client -connect auth.quantflow.studio:443 -servername auth.quantflow.studio </dev/null 2>/dev/null | openssl x509 -noout -dates
```

**Common TLS issues**:
| Symptom | Cause | Fix |
|---------|-------|-----|
| ACME challenge fails | Port 80 blocked or DNS not pointing to server | Open port 80 and verify DNS A record |
| Certificate not renewing | Caddy data volume lost | Ensure `caddy-data` volume persists across restarts |
| Admin API 403 | Client IP not in `ADMIN_ALLOWED_IPS` | Add the IP/CIDR to `ADMIN_ALLOWED_IPS` in `.env.production` |

### Deploy Script Failures

```bash
# Pre-deploy checks failing
./scripts/pre-deploy.sh staging 2>&1 | tail -20

# Deploy stuck on health check
# The script retries 8 times with exponential backoff (~2 min total)
# If health never passes, check service logs above

# Rollback state missing
ls -la .deploy-state/
# If empty, manual rollback is needed (see Manual Rollback section)
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Check auth-service request latency (from Prometheus)
curl -s http://localhost:4001/admin/metrics/prometheus | grep http_request_duration

# Check database slow queries
docker compose exec postgres psql -U <user> -d <db> -c 'SELECT * FROM pg_stat_activity WHERE state != $$idle$$ ORDER BY duration DESC;'
```

---

## Environment Variables Reference

Full list of configuration variables. See `.env.staging.example` and `.env.production.example` for defaults.

### Application

| Variable | Description | Staging Default | Production Default |
|----------|-------------|-----------------|-------------------|
| `APP_ENV` | Environment name | `staging` | `production` |
| `PUBLIC_PORT` | Public API port | `4000` | `4000` |
| `ADMIN_PORT` | Admin API port | `4001` | `4001` |
| `LOG_LEVEL` | Log verbosity | `debug` | `info` |

### Database

| Variable | Description | Staging Default | Production Default |
|----------|-------------|-----------------|-------------------|
| `POSTGRES_HOST` | PostgreSQL host | `postgres` | `postgres` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` | `5432` |
| `POSTGRES_DB` | Database name | `auth_staging` | `auth_production` |
| `POSTGRES_USER` | Database user | `auth_user` | *(required)* |
| `POSTGRES_PASSWORD` | Database password | *(required)* | *(required)* |
| `POSTGRES_SSLMODE` | SSL mode | `disable` | `require` |
| `POSTGRES_MAX_CONNS` | Max pool connections | `10` | `25` |

### Cache

| Variable | Description | Staging Default | Production Default |
|----------|-------------|-----------------|-------------------|
| `REDIS_HOST` | Redis host | `redis` | `redis` |
| `REDIS_PORT` | Redis port | `6379` | `6379` |
| `REDIS_PASSWORD` | Redis password | *(required)* | *(required)* |
| `REDIS_DB` | Redis database number | `0` | `0` |

### Authentication

| Variable | Description | Staging Default | Production Default |
|----------|-------------|-----------------|-------------------|
| `JWT_PRIVATE_KEY_PATH` | Path to ES256 private key PEM | `/run/secrets/jwt_private_key` | `/run/secrets/jwt_private_key` |
| `JWT_ALGORITHM` | JWT signing algorithm | `ES256` | `ES256` |
| `ACCESS_TOKEN_TTL` | Access token lifetime | `15m` | `15m` |
| `REFRESH_TOKEN_TTL` | Refresh token lifetime | `24h` | `7d` |
| `SYSTEM_SECRETS` | Client credential secrets (comma-separated) | *(required)* | *(required)* |
| `JWT_AUDIENCE` | Comma-separated list of `aud` values to set on issued access tokens. Empty/unset (default) means no `aud` claim is added. This is the service-wide default; a client can override it per-application via the `audience` field on the admin client API (GH-506) — an empty override means that client inherits this value. | *(empty)* | *(empty)* |
| `JWT_AUDIENCE_ENFORCE` | When `true`, `ValidateToken` rejects tokens whose `aud` claim does not intersect with `JWT_AUDIENCE` (GH-506). Default `false` preserves the pre-GH-506 behavior of accepting audience-less or mismatched tokens, to avoid a rotation hazard when `JWT_AUDIENCE` is first configured. Only takes effect when `JWT_AUDIENCE` is also set. | `false` | `false` |

### OIDC Provider

| Variable | Description | Staging Default | Production Default |
|----------|-------------|-----------------|-------------------|
| `OIDC_ISSUER_URL` | Sets the discovery document's `issuer` field and the `iss` claim on issued access/ID tokens. **Behavior change (GH-468):** prior to this fix, `iss` was hardcoded to `https://auth.qf.studio` and this variable had no effect on issued tokens — only on the discovery document. Deployments that already set a non-default `OIDC_ISSUER_URL` will see `iss` on newly issued tokens change to match it. | `https://auth.qf.studio` | `https://auth.qf.studio` |
| `OIDC_ID_TOKEN_TTL` | ID token lifetime | `1h` | `1h` |
| `OIDC_SUPPORTED_SCOPES` | Comma-separated list of supported OIDC scopes | `openid,profile,email,offline_access` | `openid,profile,email,offline_access` |
| `OIDC_LOGIN_UI_URL` | Base URL of the external login UI; `login_challenge` is appended as a query param. **Required** for the OIDC authorization code flow — `GET /oauth/authorize` returns an internal error if unset. | *(required)* | *(required)* |
| `OIDC_CONSENT_UI_URL` | Base URL of the external consent UI; `consent_challenge` is appended as a query param. Defaults to `OIDC_LOGIN_UI_URL` when unset. | *(defaults to `OIDC_LOGIN_UI_URL`)* | *(defaults to `OIDC_LOGIN_UI_URL`)* |

### Security

| Variable | Description | Staging Default | Production Default |
|----------|-------------|-----------------|-------------------|
| `ARGON2_MEMORY` | Argon2id memory in KiB | `19456` (19 MiB) | `19456` (19 MiB) |
| `ARGON2_TIME` | Argon2id iterations | `2` | `2` |
| `ARGON2_PARALLELISM` | Argon2id parallelism | `1` | `1` |
| `PASSWORD_PEPPER` | HMAC pepper for password hashing | *(required)* | *(required)* |
| `RATE_LIMIT_RPS` | Rate limit requests per second | `20` | `50` |
| `RATE_LIMIT_BURST` | Rate limit burst size | `40` | `100` |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins | `https://staging.quantflow.studio` | `https://quantflow.studio` |

### Production-Only (Caddy / TLS)

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_SERVICE_IMAGE` | Container image to pull | `ghcr.io/qf-studio/auth-service:latest` |
| `TLS_EMAIL` | ACME account email | `admin@quantflow.studio` |
| `AUTH_PUBLIC_DOMAIN` | Public API domain | `auth.quantflow.studio` |
| `AUTH_ADMIN_DOMAIN` | Admin API domain | `auth-admin.quantflow.studio` |
| `ADMIN_ALLOWED_IPS` | Admin API IP allowlist (CIDR) | `10.0.0.0/8` |

---

## File Reference

| File | Purpose |
|------|---------|
| `deployments/docker-compose.staging.yml` | Staging stack (auth-service + PostgreSQL + Redis) |
| `deployments/docker-compose.production.yml` | Production stack (+ Caddy for TLS) |
| `deployments/Caddyfile` | Caddy reverse proxy config with TLS and security headers |
| `.env.staging.example` | Staging environment template |
| `.env.production.example` | Production environment template |
| `scripts/deploy.sh` | Deploy orchestrator (build/pull, migrate, health check) |
| `scripts/rollback.sh` | Rollback to previous deployment (target: <30s) |
| `scripts/pre-deploy.sh` | Pre-deploy validation (build, lint, test) |
| `scripts/generate-keys.sh` | Generate ES256 JWT key pair |
| `scripts/generate-secret.sh` | Generate cryptographic secrets |
