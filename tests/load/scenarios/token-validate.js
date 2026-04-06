/**
 * k6 load test — Token validation scenario (authenticated request)
 *
 * GET /auth/me with Authorization: Bearer <access_token>
 *
 * This measures the full middleware chain:
 *   extract bearer token → JWT verify (ES256/EdDSA) → revocation check (Redis) → handler
 *
 * setup() provisions a pool of users with active access tokens.
 * Access tokens are short-lived (15 min typical); if the test runs longer than the
 * token TTL, VUs will start receiving 401s. Extend token TTL in the test environment
 * or reduce concurrency stages accordingly.
 *
 * Run:
 *   k6 run tests/load/scenarios/token-validate.js
 */
import { check, sleep } from 'k6';
import http from 'k6/http';
import { SharedArray } from 'k6/data';
import { defaultStages, tokenValidateThresholds } from '../config.js';
import { registerUser, loginUser, BASE_URL } from '../helpers.js';

const TEST_PASSWORD  = 'LoadTestPass#1234';
const POOL_SIZE      = 500;

const accessTokens = new SharedArray('accessTokens', function () {
  return new Array(POOL_SIZE).fill('');
});

export const options = {
  scenarios: {
    token_validate: {
      executor:    'ramping-vus',
      startVUs:    0,
      stages:      defaultStages,
      gracefulRampDown: '10s',
    },
  },
  thresholds: tokenValidateThresholds,
};

export function setup() {
  const tokens = [];
  for (let i = 0; i < POOL_SIZE; i++) {
    const email   = `loadtest-validate-${i}-${Date.now()}@example-load.test`;
    const user    = registerUser(email, TEST_PASSWORD);
    if (!user) { tokens.push(''); continue; }
    const session = loginUser(email, TEST_PASSWORD);
    tokens.push(session ? session.accessToken : '');
  }
  return { tokens };
}

export default function (data) {
  const idx         = (__VU - 1) % data.tokens.length;
  const accessToken = data.tokens[idx];

  if (!accessToken) {
    sleep(0.1);
    return;
  }

  const res = http.get(
    `${BASE_URL}/auth/me`,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type':  'application/json',
      },
      tags: { scenario: 'token_validate' },
    },
  );

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has email field': (r) => {
      try { return JSON.parse(r.body).email !== undefined; } catch (_) { return false; }
    },
  });

  sleep(0.1);
}
