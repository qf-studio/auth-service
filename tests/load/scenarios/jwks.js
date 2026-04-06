/**
 * k6 load test — JWKS fetch scenario
 *
 * GET /.well-known/jwks.json — public endpoint, no authentication required.
 *
 * This endpoint returns the public key set used for JWT signature verification.
 * It should be served from an in-memory cache after the first request.
 * Thresholds are aggressive (p99 < 100ms) to detect regressions in caching.
 *
 * Run:
 *   k6 run tests/load/scenarios/jwks.js
 */
import { check, sleep } from 'k6';
import http from 'k6/http';
import { defaultStages, jwksThresholds } from '../config.js';
import { BASE_URL } from '../helpers.js';

export const options = {
  scenarios: {
    jwks: {
      executor:    'ramping-vus',
      startVUs:    0,
      stages:      defaultStages,
      gracefulRampDown: '10s',
    },
  },
  thresholds: jwksThresholds,
};

export default function () {
  const res = http.get(
    `${BASE_URL}/.well-known/jwks.json`,
    { tags: { scenario: 'jwks' } },
  );

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has keys array': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.keys) && body.keys.length > 0;
      } catch (_) {
        return false;
      }
    },
    'content-type is json': (r) => {
      const ct = r.headers['Content-Type'] || '';
      return ct.includes('application/json');
    },
  });

  // No sleep needed — JWKS is stateless and cacheable; we want max throughput.
  sleep(0.05);
}
