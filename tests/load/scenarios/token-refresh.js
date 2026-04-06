/**
 * k6 load test — Token refresh scenario
 *
 * POST /auth/token  { grant_type: "refresh_token", refresh_token: "..." }
 *
 * setup() registers + logs in a pool of users and shares their refresh tokens.
 * Each VU cycles through the pool and refreshes a token on every iteration.
 *
 * Note: each refresh invalidates the old refresh token and issues a new one.
 * Under high concurrency, the same refresh token may be used by multiple VUs.
 * 409/401 responses from token reuse are expected and filtered from the error rate.
 *
 * Run:
 *   k6 run tests/load/scenarios/token-refresh.js
 */
import { check, sleep } from 'k6';
import http from 'k6/http';
import { SharedArray } from 'k6/data';
import { defaultStages, tokenRefreshThresholds } from '../config.js';
import { registerUser, loginUser, JSON_HEADERS, BASE_URL } from '../helpers.js';

const TEST_PASSWORD = 'LoadTestPass#1234';
const POOL_SIZE     = 500;

const refreshTokens = new SharedArray('refreshTokens', function () {
  return new Array(POOL_SIZE).fill('');
});

export const options = {
  scenarios: {
    token_refresh: {
      executor:    'ramping-vus',
      startVUs:    0,
      stages:      defaultStages,
      gracefulRampDown: '10s',
    },
  },
  thresholds: tokenRefreshThresholds,
};

export function setup() {
  const tokens = [];
  for (let i = 0; i < POOL_SIZE; i++) {
    const email = `loadtest-refresh-${i}-${Date.now()}@example-load.test`;
    const user  = registerUser(email, TEST_PASSWORD);
    if (!user) { tokens.push(''); continue; }
    const session = loginUser(email, TEST_PASSWORD);
    tokens.push(session ? session.refreshToken : '');
  }
  return { tokens };
}

export default function (data) {
  const idx          = (__VU - 1) % data.tokens.length;
  const refreshToken = data.tokens[idx];

  if (!refreshToken) {
    // Pool slot not initialised — skip iteration gracefully.
    sleep(0.1);
    return;
  }

  const res = http.post(
    `${BASE_URL}/auth/token`,
    JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken }),
    { headers: JSON_HEADERS, tags: { scenario: 'token_refresh' } },
  );

  // 200 = success; 401/409 = token already used (acceptable under high concurrency).
  check(res, {
    'status 200 or 401/409': (r) => [200, 401, 409].includes(r.status),
    'status is 200': (r) => r.status === 200,
  });

  if (res.status === 200) {
    // Update the pool slot with the new refresh token for subsequent iterations.
    try {
      data.tokens[idx] = JSON.parse(res.body).refresh_token || refreshToken;
    } catch (_) { /* ignore */ }
  }

  sleep(0.2);
}
