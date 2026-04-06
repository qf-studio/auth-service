/**
 * k6 load test — Registration scenario
 *
 * Each VU registers a unique user on every iteration.
 * Heavy endpoint: Argon2id hashing takes ~300-600ms per call.
 * Thresholds reflect this intentional latency.
 *
 * Run:
 *   k6 run tests/load/scenarios/register.js
 *   k6 run -e K6_BASE_URL=https://auth.staging.example.com tests/load/scenarios/register.js
 */
import { check, sleep } from 'k6';
import http from 'k6/http';
import { defaultStages, registerThresholds } from '../config.js';
import { randomEmail, JSON_HEADERS, BASE_URL } from '../helpers.js';

// Minimum 15-char password per NIST SP 800-63-4. No composition rules.
const TEST_PASSWORD = 'LoadTestPass#1234';

export const options = {
  scenarios: {
    register: {
      executor:    'ramping-vus',
      startVUs:    0,
      stages:      defaultStages,
      gracefulRampDown: '10s',
    },
  },
  thresholds: registerThresholds,
};

export default function () {
  const email = randomEmail();

  const res = http.post(
    `${BASE_URL}/auth/register`,
    JSON.stringify({
      email,
      password: TEST_PASSWORD,
      name:     'Load Test User',
    }),
    { headers: JSON_HEADERS, tags: { scenario: 'register' } },
  );

  check(res, {
    'status is 201': (r) => r.status === 201,
    'has access_token': (r) => {
      try { return JSON.parse(r.body).access_token !== undefined; } catch (_) { return false; }
    },
  });

  // Brief pause to avoid hammering a single endpoint without think time.
  sleep(0.5);
}
