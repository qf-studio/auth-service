# Performance Baselines

Target thresholds for the auth-service. All latency targets are **p99** unless noted otherwise.

## Latency Targets (p99)

| Endpoint / Operation       | p99 Target | p95 Target | p50 Target | Notes                              |
| -------------------------- | ---------- | ---------- | ---------- | ---------------------------------- |
| Token validation           | < 50 ms    | < 25 ms    | < 10 ms    | JWT signature verify + revocation check |
| Login (password auth)      | < 500 ms   | < 300 ms   | < 200 ms   | Argon2id dominates; intentionally slow |
| Token refresh              | < 100 ms   | < 50 ms    | < 20 ms    | HMAC verify + new JWT issue        |
| JWKS endpoint (cached)     | < 10 ms    | < 5 ms     | < 2 ms     | Served from in-memory cache        |
| Registration               | < 1 s      | < 700 ms   | < 400 ms   | Argon2id hash + DB insert + HIBP check |

## Throughput Targets

| Operation           | Target (req/s) | Notes                                    |
| ------------------- | -------------- | ---------------------------------------- |
| Token validation    | > 5,000        | Most frequent operation in ecosystem     |
| JWKS fetch          | > 10,000       | Cached, read-only                        |
| Login               | > 100          | CPU-bound by Argon2id (by design)        |
| Token refresh       | > 2,000        | Moderate frequency                       |
| Registration        | > 50           | Lowest frequency, highest cost           |

## Error Rate Targets

- All endpoints: < 0.1% error rate under normal load
- Under stress (2x expected load): < 1% error rate
- Graceful degradation above capacity (no crashes, proper 503 responses)

---

## Running Benchmarks

### Go Micro-Benchmarks

Run all benchmarks with memory allocation stats:

```bash
make bench
```

Run with CPU profiling (output to `profiles/cpu.prof`):

```bash
make bench-cpu
```

Run with memory profiling (output to `profiles/mem.prof`):

```bash
make bench-mem
```

Run benchmarks for a specific package:

```bash
go test -bench=. -benchmem -run=^$ ./internal/token/...
go test -bench=. -benchmem -run=^$ ./internal/password/...
go test -bench=. -benchmem -run=^$ ./internal/middleware/...
```

### Load Tests (k6)

Requires [k6](https://k6.io/docs/get-started/installation/) and a running auth-service instance.

```bash
# Start dependencies and the service
make docker-up
make run &

# Run load tests
make load-test
```

Load test scenarios are in `tests/load/scenarios.js` and cover:
- Registration flow
- Login flow
- Token refresh
- Token validation (authenticated request)
- JWKS fetch

Configurable VU (virtual user) stages: 10 -> 50 -> 100 -> 500 VUs over 30s per stage.

---

## Interpreting Results

### Go Benchmark Output

```
BenchmarkValidateToken-8    50000    23456 ns/op    4096 B/op    12 allocs/op
```

| Field               | Meaning                              |
| ------------------- | ------------------------------------ |
| `-8`                | GOMAXPROCS (CPU cores used)          |
| `50000`             | Iterations run                       |
| `23456 ns/op`       | Nanoseconds per operation (~23 us)   |
| `4096 B/op`         | Bytes allocated per operation        |
| `12 allocs/op`      | Heap allocations per operation       |

**Key things to watch:**
- `ns/op` — primary latency metric. Convert: 1ms = 1,000,000 ns.
- `B/op` — memory pressure. High values increase GC frequency.
- `allocs/op` — allocation count. Fewer is better for GC.

### Profiling

After running `make bench-cpu` or `make bench-mem`:

```bash
# Interactive web UI
go tool pprof -http=:8080 profiles/cpu.prof

# Top functions by CPU time
go tool pprof -top profiles/cpu.prof

# Flamegraph (in web UI, navigate to "Flame Graph" view)
```

**CPU profile** — look for:
- Argon2id should dominate login/registration benchmarks (expected)
- JWT signing/verification should be the hot path for token operations
- Unexpected stdlib or serialization overhead

**Memory profile** — look for:
- Large allocations per request (potential for sync.Pool)
- Repeated small allocations (consider pre-allocation)

### k6 Load Test Output

```
http_req_duration...: avg=45ms  min=2ms  med=30ms  max=500ms  p(90)=80ms  p(95)=120ms  p(99)=200ms
```

**Key metrics:**
- `http_req_duration` p99 — compare against targets above
- `http_req_failed` — should be < 0.1%
- `iterations` — total completed requests
- `vus` — concurrent virtual users at time of measurement

**Red flags:**
- p99 > 2x target: performance regression, investigate
- Error rate > 1%: likely resource exhaustion (connections, memory)
- p99/p50 ratio > 10x: high variance, check for lock contention or GC pauses

### Comparing Benchmark Runs

Use `benchstat` to compare before/after:

```bash
# Install benchstat
go install golang.org/x/perf/cmd/benchstat@latest

# Run baseline
make bench > bench-before.txt

# Make changes, then run again
make bench > bench-after.txt

# Compare
benchstat bench-before.txt bench-after.txt
```

A statistically significant regression (p < 0.05) in a critical path should block the PR.
