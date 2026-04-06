/**
 * k6 load test — Login scenario
 *
 * setup() registers a fixed pool of users (one per VU slot up to MAX_USERS).
 * Each VU logs in as a unique pool user on every iteration to avoid
 * credential conflicts while keeping the user set realistic.
 *
 * Argon2id verify is intentionally slow; thresholds reflect this.
 *
 * Run:
 *   k6 run tests/load/scenarios/login.js
 *   k6 run -e K6_BASE_URL=https://auth.staging.example.com tests/load/scenarios/login.js
 */
import { check, sleep } from 'k6';
import http from 'k6/http';
import { SharedArray } from 'k6/data';
import { defaultStages, loginThresholds } from '../config.js';
import { registerUser, JSON_HEADERS, BASE_URL } from '../helpers.js';

const TEST_PASSWORD = 'LoadTestPass#1234';
const MAX_USERS     = 500; // must be >= max VUs to avoid collisions

// Pre-create user pool once before test begins.
const users = new SharedArray('users', function () {
  const pool = [];
  for (let i = 0; i < MAX_USERS; i++) {
    pool.push(`loadtest-login-${i}-${Date.now()}@example-load.test`);
  }
  return pool;
});

export const options = {
  scenarios: {
    login: {
      executor:    'ramping-vus',
      startVUs:    0,
      stages:      defaultStages,
      gracefulRampDown: '10s',
    },
  },
  thresholds: loginThresholds,
};

export function setup() {
  // Register all pool users before the load test begins.
  // This runs once in a single goroutine, so it's sequential — acceptable for setup.
  for (const email of users) {
    registerUser(email, TEST_PASSWORD);
  }
}

export default function () {
  // Each VU picks its own slot to avoid concurrent login on the same account.
  const email = users[(__VU - 1) % users.length];

  const res = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({ email, password: TEST_PASSWORD }),
    { headers: JSON_HEADERS, tags: { scenario: 'login' } },
  );

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has access_token': (r) => {
      try { return JSON.parse(r.body).access_token !== undefined; } catch (_) { return false; }
    },
    'has refresh_token': (r) => {
      try { return JSON.parse(r.body).refresh_token !== undefined; } catch (_) { return false; }
    },
  });

  sleep(0.5);
}
