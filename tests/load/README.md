# Load Tests

k6-based load tests for the auth service. Each scenario targets a single endpoint and runs through four concurrency tiers (10 → 50 → 100 → 500 VUs, 30 s each).

## Prerequisites

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Docker (no install)
docker run --rm -i grafana/k6 run - < tests/load/scenarios/jwks.js
```

k6 version ≥ 0.47 required (for `ramping-vus` executor and `SharedArray`).

## Running the Service

```bash
docker-compose up -d postgres redis
go run cmd/migrate/main.go up
go run cmd/server/main.go
```

The public API listens on port **4000** by default.

## Scenarios

| File | Endpoint | Description |
|------|----------|-------------|
| `scenarios/register.js` | `POST /auth/register` | User registration (Argon2id) |
| `scenarios/login.js` | `POST /auth/login` | Password login (Argon2id verify) |
| `scenarios/token-refresh.js` | `POST /auth/token` | Refresh token exchange |
| `scenarios/token-validate.js` | `GET /auth/me` | Authenticated request (JWT verify + Redis revocation check) |
| `scenarios/jwks.js` | `GET /.well-known/jwks.json` | Public key set fetch |

## Running Scenarios

```bash
# Single scenario
k6 run tests/load/scenarios/jwks.js
k6 run tests/load/scenarios/login.js

# Custom base URL (staging / CI)
k6 run -e K6_BASE_URL=https://auth.staging.example.com tests/load/scenarios/jwks.js

# Custom concurrency stages (JSON array, overrides defaults)
k6 run -e K6_STAGES='[{"duration":"30s","target":10},{"duration":"30s","target":50}]' \
  tests/load/scenarios/login.js

# Run all scenarios sequentially
for s in register login token-refresh token-validate jwks; do
  k6 run tests/load/scenarios/${s}.js
done
```

## Concurrency Stages

Default stages defined in `config.js`:

| Stage | Target VUs | Duration |
|-------|-----------|----------|
| Ramp up | 0 → 10 | 30 s |
| Sustain | 10 → 50 | 30 s |
| Sustain | 50 → 100 | 30 s |
| Sustain | 100 → 500 | 30 s |
| Ramp down | 500 → 0 | 30 s |

Override via `K6_STAGES` env var (valid JSON array of `{duration, target}` objects).

## Thresholds

Failure causes the k6 process to exit with code 99.

| Scenario | p50 | p95 | p99 | Error rate |
|----------|-----|-----|-----|------------|
| Register | < 800 ms | < 2000 ms | < 4000 ms | < 1% |
| Login | < 800 ms | < 2000 ms | < 4000 ms | < 1% |
| Token refresh | < 100 ms | < 300 ms | < 500 ms | < 1% |
| Token validate | < 50 ms | < 200 ms | < 500 ms | < 1% |
| JWKS | < 10 ms | < 50 ms | < 100 ms | < 0.1% |

Registration and login thresholds are deliberately wide because Argon2id is configured with parameters (m=19 MiB, t=2, p=1) that produce ~300–600 ms hashing time by design (NIST AAL2 requirement).

## Output and Reporting

```bash
# Write structured JSON summary for CI/CD ingestion
k6 run --out json=results.json tests/load/scenarios/jwks.js

# Stream metrics to InfluxDB + Grafana
k6 run --out influxdb=http://localhost:8086/k6 tests/load/scenarios/jwks.js
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `K6_BASE_URL` | `http://localhost:4000` | Base URL of the auth service |
| `K6_STAGES` | See table above | JSON array overriding default VU stages |

## Notes

- **Token refresh concurrency**: at high VU counts multiple VUs may attempt to refresh the same token simultaneously. The scenario treats HTTP 401/409 responses as expected (token already consumed) and excludes them from the error rate threshold.
- **Access token TTL**: the `token-validate` scenario provisions access tokens in `setup()`. If the test duration exceeds the token TTL (default 15 min), VUs will start receiving 401s. Either extend the TTL in the test environment or reduce the number of stages.
- **Rate limiting**: the service enforces rate limits. Run load tests against a dedicated staging environment with rate limits disabled or raised, not production.
