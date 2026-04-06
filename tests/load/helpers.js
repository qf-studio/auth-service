/**
 * Shared k6 load test helpers.
 */
import { check } from 'k6';
import http from 'k6/http';
import { BASE_URL } from './config.js';

const JSON_HEADERS = { 'Content-Type': 'application/json' };

/**
 * Generate a unique email address safe for parallel VU use.
 * Uses __VU (virtual user ID) + Date.now() + random suffix to avoid collisions.
 */
export function randomEmail() {
  const rand = Math.floor(Math.random() * 1e9);
  return `loadtest-vu${__VU}-${Date.now()}-${rand}@example-load.test`;
}

/**
 * Register a new user and return { email, password } or null on failure.
 * Used in setup() or as a per-VU init step.
 */
export function registerUser(email, password) {
  const res = http.post(
    `${BASE_URL}/auth/register`,
    JSON.stringify({ email, password, name: 'Load Test User' }),
    { headers: JSON_HEADERS },
  );
  const ok = check(res, { 'register 201': (r) => r.status === 201 });
  if (!ok) {
    return null;
  }
  return { email, password };
}

/**
 * Log in and return { access_token, refresh_token } or null on failure.
 */
export function loginUser(email, password) {
  const res = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({ email, password }),
    { headers: JSON_HEADERS },
  );
  const ok = check(res, { 'login 200': (r) => r.status === 200 });
  if (!ok) {
    return null;
  }
  try {
    const body = JSON.parse(res.body);
    return {
      accessToken:  body.access_token,
      refreshToken: body.refresh_token,
    };
  } catch (_) {
    return null;
  }
}

/**
 * Build an Authorization: Bearer header map.
 */
export function bearerHeaders(accessToken) {
  return {
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${accessToken}`,
  };
}

export { JSON_HEADERS, BASE_URL };
