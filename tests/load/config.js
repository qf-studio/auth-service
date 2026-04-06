/**
 * Shared k6 load test configuration.
 *
 * Concurrency stages: ramp through 10 → 50 → 100 → 500 VUs with 30s at each level,
 * then ramp back to 0. Override via K6_STAGES env var (JSON array of {duration, target}).
 *
 * BASE_URL defaults to http://localhost:4000 and can be overridden via K6_BASE_URL env var.
 */

export const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:4000';

// Default stages: 30s at each VU tier + 30s ramp-down.
export const defaultStages = __ENV.K6_STAGES
  ? JSON.parse(__ENV.K6_STAGES)
  : [
      { duration: '30s', target: 10 },
      { duration: '30s', target: 50 },
      { duration: '30s', target: 100 },
      { duration: '30s', target: 500 },
      { duration: '30s', target: 0 },
    ];

// --- Per-scenario thresholds ---

// Registration is slow by design (Argon2id hashing). Generous thresholds.
export const registerThresholds = {
  http_req_failed:              ['rate<0.01'],
  http_req_duration:            ['p(50)<800', 'p(95)<2000', 'p(99)<4000'],
  'http_req_duration{scenario:register}': ['p(50)<800', 'p(95)<2000', 'p(99)<4000'],
};

// Login: Argon2id verify — similar budget to register.
export const loginThresholds = {
  http_req_failed:              ['rate<0.01'],
  http_req_duration:            ['p(50)<800', 'p(95)<2000', 'p(99)<4000'],
  'http_req_duration{scenario:login}': ['p(50)<800', 'p(95)<2000', 'p(99)<4000'],
};

// Token refresh: HMAC + Redis lookup — much faster.
export const tokenRefreshThresholds = {
  http_req_failed:              ['rate<0.01'],
  http_req_duration:            ['p(50)<100', 'p(95)<300', 'p(99)<500'],
  'http_req_duration{scenario:token_refresh}': ['p(50)<100', 'p(95)<300', 'p(99)<500'],
};

// Token validation (GET /auth/me): JWT verify + DB lookup.
export const tokenValidateThresholds = {
  http_req_failed:              ['rate<0.01'],
  http_req_duration:            ['p(50)<50', 'p(95)<200', 'p(99)<500'],
  'http_req_duration{scenario:token_validate}': ['p(50)<50', 'p(95)<200', 'p(99)<500'],
};

// JWKS: static JSON from memory/cache — very fast.
export const jwksThresholds = {
  http_req_failed:              ['rate<0.001'],
  http_req_duration:            ['p(50)<10', 'p(95)<50', 'p(99)<100'],
  'http_req_duration{scenario:jwks}': ['p(50)<10', 'p(95)<50', 'p(99)<100'],
};
