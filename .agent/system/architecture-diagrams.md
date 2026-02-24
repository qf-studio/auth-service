# Architecture Diagrams

**Updated**: 2026-02-24

---

## 1. System Overview

```
                            ┌─────────────────────────────────────────────┐
                            │              Auth Service                    │
                            │            (Single Go Binary)                │
                            │                                              │
    Internet                │   ┌──────────┐       ┌──────────┐           │
   ─────────────────────────┼──►│  Public   │       │  Admin   │◄──── Internal
    Browsers, Mobile,       │   │  API     │       │  API     │      Network
    SPAs, OAuth Clients     │   │  :4000   │       │  :4001   │      Only
                            │   └────┬─────┘       └────┬─────┘           │
                            │        │                   │                 │
                            │        ▼                   ▼                 │
                            │   ┌────────────────────────────────┐        │
                            │   │       Middleware Stack          │        │
                            │   │  ┌─────────────────────────┐   │        │
                            │   │  │ Correlation ID           │   │        │
                            │   │  │ Security Headers         │   │        │
                            │   │  │ Rate Limiting (Redis)    │   │        │
                            │   │  │ Request Size Limit       │   │        │
                            │   │  │ CORS                     │   │        │
                            │   │  │ Auth (JWT validation)    │   │        │
                            │   │  │ RBAC (role enforcement)  │   │        │
                            │   │  │ Metrics Collection       │   │        │
                            │   │  └─────────────────────────┘   │        │
                            │   └────────────┬───────────────────┘        │
                            │                │                             │
                            │                ▼                             │
                            │   ┌────────────────────────────────┐        │
                            │   │        Service Layer           │        │
                            │   │                                │        │
                            │   │  ┌──────┐ ┌───────┐ ┌──────┐  │        │
                            │   │  │ Auth │ │ Token │ │ User │  │        │
                            │   │  └──┬───┘ └───┬───┘ └──┬───┘  │        │
                            │   │     │         │        │       │        │
                            │   │  ┌──────┐ ┌───────┐ ┌──────┐  │        │
                            │   │  │Client│ │ RBAC  │ │Audit │  │        │
                            │   │  └──┬───┘ └───┬───┘ └──┬───┘  │        │
                            │   └─────┼─────────┼────────┼───────┘        │
                            │         │         │        │                 │
                            │         ▼         ▼        ▼                 │
                            │   ┌────────────────────────────────┐        │
                            │   │       Storage Layer            │        │
                            │   │                                │        │
                            │   │  ┌──────────────────────────┐  │        │
                            │   │  │  Repository Interfaces   │  │        │
                            │   │  │  UserRepo │ ClientRepo   │  │        │
                            │   │  │  TokenRepo │ AuditRepo   │  │        │
                            │   │  └──────────┬───────────────┘  │        │
                            │   └─────────────┼──────────────────┘        │
                            │          ┌──────┴──────┐                     │
                            └──────────┼─────────────┼─────────────────────┘
                                       │             │
                                       ▼             ▼
                              ┌────────────┐  ┌────────────┐
                              │ PostgreSQL │  │   Redis    │
                              │   :5432    │  │   :6379    │
                              │            │  │            │
                              │ Durable:   │  │ Ephemeral: │
                              │ • Users    │  │ • Sessions │
                              │ • Clients  │  │ • Token    │
                              │ • Refresh  │  │   blocklist│
                              │   tokens   │  │ • Rate     │
                              │   (sigs)   │  │   limits   │
                              │ • Audit    │  │ • OTP codes│
                              │   log      │  │ • Reset    │
                              │ • RBAC     │  │   tokens   │
                              │   policies │  │ • MFA      │
                              └────────────┘  │   sessions │
                                              └────────────┘
```

---

## 2. Authentication Flows

### 2a. User Login Flow

```
  Client (Browser/SPA)              Auth Service                 PostgreSQL     Redis
  ────────────────────              ────────────                 ──────────     ─────
         │                                │                          │            │
         │  POST /auth/login              │                          │            │
         │  {email, password}             │                          │            │
         │───────────────────────────────►│                          │            │
         │                                │                          │            │
         │                                │  SELECT user by email    │            │
         │                                │─────────────────────────►│            │
         │                                │◄─────────────────────────│            │
         │                                │                          │            │
         │                                │  Verify Argon2id hash    │            │
         │                                │  (password + pepper)     │            │
         │                                │                          │            │
         │                                │  Generate access token   │            │
         │                                │  (ES256 JWT, qf_at_)    │            │
         │                                │                          │            │
         │                                │  Generate refresh token  │            │
         │                                │  (qf_rt_<key>.<sig>)    │            │
         │                                │                          │            │
         │                                │  Store refresh sig       │            │
         │                                │─────────────────────────►│            │
         │                                │                          │            │
         │                                │  Update last_login_at    │            │
         │                                │─────────────────────────►│            │
         │                                │                          │            │
         │  200 {access_token,            │                          │            │
         │       refresh_token,           │                          │            │
         │       token_type: "Bearer",    │                          │            │
         │       expires_in: 900}         │                          │            │
         │◄───────────────────────────────│                          │            │
         │                                │                          │            │
```

### 2b. Token Refresh Flow

```
  Client                    Auth Service                 PostgreSQL     Redis
  ──────                    ────────────                 ──────────     ─────
    │                             │                          │            │
    │  POST /auth/token           │                          │            │
    │  grant_type=refresh_token   │                          │            │
    │  refresh_token=qf_rt_...   │                          │            │
    │────────────────────────────►│                          │            │
    │                             │                          │            │
    │                             │  Validate HMAC sig       │            │
    │                             │  (system secret)         │            │
    │                             │                          │            │
    │                             │  Lookup by signature     │            │
    │                             │─────────────────────────►│            │
    │                             │◄─────────────────────────│            │
    │                             │                          │            │
    │                             │  Check: not expired,     │            │
    │                             │  not revoked             │            │
    │                             │                          │            │
    │                             │  Revoke old refresh      │            │
    │                             │─────────────────────────►│            │
    │                             │                          │            │
    │                             │  Generate new pair       │            │
    │                             │  (rotation)              │            │
    │                             │                          │            │
    │                             │  Store new refresh sig   │            │
    │                             │─────────────────────────►│            │
    │                             │                          │            │
    │  200 {new access_token,     │                          │            │
    │       new refresh_token}    │                          │            │
    │◄────────────────────────────│                          │            │
    │                             │                          │            │
```

### 2c. Client Credentials Flow (Systems / AI Agents)

```
  Service / Agent             Auth Service                 PostgreSQL     Redis
  ───────────────             ────────────                 ──────────     ─────
       │                            │                          │            │
       │  POST /auth/token          │                          │            │
       │  grant_type=               │                          │            │
       │    client_credentials      │                          │            │
       │  client_id=...             │                          │            │
       │  client_secret=qf_cs_...   │                          │            │
       │───────────────────────────►│                          │            │
       │                            │                          │            │
       │                            │  Lookup client by ID     │            │
       │                            │─────────────────────────►│            │
       │                            │◄─────────────────────────│            │
       │                            │                          │            │
       │                            │  Verify Argon2id hash    │            │
       │                            │  (client_secret)         │            │
       │                            │                          │            │
       │                            │  Validate requested      │            │
       │                            │  scopes ⊆ allowed        │            │
       │                            │                          │            │
       │                            │  Generate access token   │            │
       │                            │  claims.client_type =    │            │
       │                            │    "service" | "agent"   │            │
       │                            │  TTL: 15m (svc) / 5m     │            │
       │                            │    (agent)               │            │
       │                            │                          │            │
       │                            │  Update last_used_at     │            │
       │                            │─────────────────────────►│            │
       │                            │                          │            │
       │  200 {access_token,        │                          │            │
       │       token_type: "Bearer",│                          │            │
       │       expires_in: 300}     │                          │            │
       │  (NO refresh token)        │                          │            │
       │◄──────────────────────────-│                          │            │
       │                            │                          │            │
```

---

## 3. Token Verification (by consuming services)

```
  Consuming Service           Auth Service JWKS          Consuming Service
  (LinearInvoices, etc.)      (fetched once, cached)     (local verification)
  ──────────────────────      ──────────────────────     ────────────────────
         │                            │                          │
         │  GET /.well-known/         │                          │
         │      jwks.json             │                          │
         │───────────────────────────►│                          │
         │                            │                          │
         │  200 {keys: [{             │                          │
         │    kty: "EC",              │                          │
         │    crv: "P-256",           │                          │
         │    kid: "...",             │                          │
         │    x: "...", y: "..."      │                          │
         │  }]}                       │                          │
         │◄───────────────────────────│                          │
         │                            │                          │
         │  Cache public key locally  │                          │
         │────────────────────────────────────────────────────►  │
         │                                                       │
         │  On each request:                                     │
         │  1. Extract qf_at_ token from Authorization header    │
         │  2. Strip prefix                                      │
         │  3. Verify ES256 signature with cached public key     │
         │  4. Check exp, iss, aud claims                        │
         │  5. Extract roles, scopes, client_type                │
         │  6. Authorize request locally                         │
         │                                                       │
         │  *** NO call back to auth service ***                 │
         │                                                       │
```

---

## 4. Internal Package Dependency Graph

```
                        ┌─────────────────┐
                        │ cmd/server/main │
                        └────────┬────────┘
                                 │ wires everything
          ┌──────────┬───────────┼────────────┬──────────────┐
          ▼          ▼           ▼            ▼              ▼
    ┌──────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────────┐
    │  config  │ │ logger │ │storage │ │protocols │ │ middleware  │
    │          │ │        │ │        │ │(routers, │ │(auth,rbac, │
    │ Load()   │ │ Init() │ │pg pool │ │handlers) │ │rate,cors,  │
    │          │ │        │ │redis   │ │          │ │security,   │
    │          │ │        │ │repos   │ │          │ │metrics)    │
    └──────────┘ └────────┘ └───┬────┘ └────┬─────┘ └─────┬──────┘
                                │           │              │
                                │     ┌─────┴──────┐       │
                                │     │  Service   │       │
                                │     │   Layer    │◄──────┘
                                │     │            │  (middleware calls
                                │     │ ┌────────┐ │   token service
                                ▼     │ │  auth  │ │   for validation)
                          ┌─────────┐ │ ├────────┤ │
                          │ domain  │◄┤ │ token  │ │
                          │         │ │ ├────────┤ │
                          │ User    │ │ │  user  │ │
                          │ Client  │ │ ├────────┤ │
                          │ Token   │ │ │ client │ │
                          │ Role    │ │ ├────────┤ │
                          │ Errors  │ │ │  rbac  │ │
                          │         │ │ ├────────┤ │
                          └─────────┘ │ │ audit  │ │
                             ▲        │ └────────┘ │
                             │        └────────────┘
                             │              │
                     Zero deps,        All services use
                     only stdlib       domain types +
                     + uuid            storage repos
```

**Dependency rules:**

- `domain` has ZERO external deps (stdlib + uuid only)
- `config`, `logger` depend on nothing internal
- `storage` depends on `domain` only
- Services (`auth`, `token`, `user`, `client`, `rbac`, `audit`) depend on `domain` + `storage`
- `middleware` depends on `token` service (for JWT validation)
- `protocols` (routers/handlers) depends on services + middleware
- `cmd/server/main.go` wires everything together (manual DI)

---

## 5. Database Schema (Phase 1)

```md
┌─────────────────────────────────────────┐
│ users │
├─────────────────────────────────────────┤
│ id UUID PK DEFAULT │
│ gen_random_uuid() │
│ email VARCHAR(255) UNIQUE │
│ password_hash TEXT NOT NULL │
│ roles TEXT[] DEFAULT '{user}' │
│ status VARCHAR(20) DEFAULT │
│ 'active' │
│ mfa_enabled BOOLEAN DEFAULT false │
│ created_at TIMESTAMPTZ │
│ updated_at TIMESTAMPTZ │
│ last_login_at TIMESTAMPTZ │
│ password_changed_at TIMESTAMPTZ │
├─────────────────────────────────────────┤
│ idx_users_email (email) │
│ idx_users_status (status) │
└──────────────────┬──────────────────────┘
│
│ user_id FK
▼
┌─────────────────────────────────────────┐
│ refresh_tokens │
├─────────────────────────────────────────┤
│ id UUID PK │
│ signature TEXT UNIQUE NOT NULL │
│ user_id UUID FK → users(id) │
│ ON DELETE CASCADE │
│ client_id UUID FK → clients(id) │
│ ON DELETE CASCADE │
│ scopes TEXT[] DEFAULT '{}' │
│ expires_at TIMESTAMPTZ NOT NULL │
│ created_at TIMESTAMPTZ │
│ revoked_at TIMESTAMPTZ │
├─────────────────────────────────────────┤
│ idx_refresh_tokens_user_id (user_id) │
│ idx_refresh_tokens_signature (signature)│
│ idx_refresh_tokens_expires (expires) │
└─────────────────────────────────────────┘
▲
│ client_id FK
│
┌─────────────────────────────────────────┐
│ clients │
├─────────────────────────────────────────┤
│ id UUID PK │
│ name VARCHAR(255) NOT NULL │
│ client_type VARCHAR(20) NOT NULL │
│ 'service' | 'agent' │
│ secret_hash TEXT NOT NULL │
│ scopes TEXT[] DEFAULT '{}' │
│ roles TEXT[] DEFAULT │
│ '{service}' │
│ owner VARCHAR(255) NOT NULL │
│ skip_consent BOOLEAN DEFAULT true │
│ access_token_ttl INTERVAL │
│ status VARCHAR(20) DEFAULT │
│ 'active' │
│ created_at TIMESTAMPTZ │
│ updated_at TIMESTAMPTZ │
│ last_used_at TIMESTAMPTZ │
├─────────────────────────────────────────┤
│ idx_clients_name (name) │
│ idx_clients_status (status) │
└─────────────────────────────────────────┘
```

---

## 6. Deployment Architecture

```
                    Internet
                       │
                       ▼
              ┌────────────────┐
              │  Caddy / Nginx │
              │  (TLS 1.3      │
              │   termination) │
              │  :443          │
              └───────┬────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
         ▼                         ▼
  ┌──────────────┐        ┌──────────────┐
  │ auth-service │        │ auth-service │
  │   :4000      │        │   :4001      │
  │  (public)    │        │  (admin)     │
  │              │        │              │
  │ Routes:      │        │ Routes:      │
  │ /auth/*      │        │ /admin/*     │
  │ /.well-known │        │ /admin/      │
  │ /health      │        │   metrics    │
  └──────┬───────┘        └──────┬───────┘
         │                       │
         │    ┌──────────────┐   │
         └───►│  PostgreSQL  │◄──┘
              │  :5432       │
              │              │
              │  Volume:     │
              │  pgdata      │
              └──────────────┘
                     │
         ┌───────────┘
         │
         │    ┌──────────────┐
         └───►│    Redis     │
              │  :6379       │
              │              │
              │  Volume:     │
              │  redisdata   │
              └──────────────┘

  ┌──────────────────────────────────────┐
  │  docker-compose.yml                   │
  │                                       │
  │  services:                            │
  │    caddy:     (reverse proxy + TLS)   │
  │    auth:      (Go binary, dual-port)  │
  │    postgres:  (16-alpine, healthcheck)│
  │    redis:     (7.4-alpine, healthcheck│
  │                                       │
  │  volumes:                             │
  │    pgdata, redisdata                  │
  └──────────────────────────────────────┘
```

---

## 7. Token Lifecycle

```md
┌─────────────────────────────────────────────────────────────────┐
│ ACCESS TOKEN (qf*at*) │
│ │
│ Created: on login / refresh / client*credentials │
│ Format: qf_at* + ES256-signed JWT │
│ TTL: 15 min (users) / 5-15 min (systems, per-client) │
│ Storage: NOT stored (verified by signature only) │
│ Revoke: jti added to Redis blocklist (TTL = token exp) │
│ Verify: any service with JWKS public key (no auth call) │
│ │
│ Claims: │
│ ┌───────────────────────────────────────────────────────┐ │
│ │ sub: "user-uuid" iss: "auth.quantflow.studio"│ │
│ │ aud: ["api.quantflow..."] exp: 1740000000 │ │
│ │ iat: 1739999100 jti: "unique-id" │ │
│ │ client_id: "client-uuid" client_type: "user|svc|agt" │ │
│ │ roles: ["admin","user"] scopes: ["read","write"] │ │
│ └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ REFRESH TOKEN (qf*rt*) │
│ │
│ Created: on login / refresh (rotation) │
│ Format: qf*rt* + <128-bit key> . <HMAC-SHA256 signature> │
│ TTL: 14 days (users only, NO refresh for systems) │
│ Storage: SIGNATURE ONLY in PostgreSQL (not full token) │
│ Revoke: set revoked_at in DB │
│ Verify: recompute HMAC, lookup sig in DB │
│ │
│ On use: old token revoked → new pair issued (rotation) │
│ On compromise: revoke-all by user_id │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ REVOCATION FLOW │
│ │
│ Logout (single): │
│ 1. Add access jti → Redis blocklist (TTL = remaining exp) │
│ 2. Set refresh revoked_at → PostgreSQL │
│ │
│ Logout (all sessions): │
│ 1. Revoke ALL refresh tokens for user_id → PostgreSQL │
│ 2. (Access tokens expire naturally within 15 min) │
│ │
│ Redis blocklist key: auth:revoked:<jti> │
│ Auto-cleanup: Redis TTL matches token expiration │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Middleware Stack (Request Processing Order)

```
  Incoming Request
       │
       ▼
  ┌─────────────────────┐
  │ 1. Correlation ID   │  Generate X-Request-ID if missing
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 2. Security Headers │  XSS, CSP, HSTS, X-Frame, Referrer
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 3. Request Size     │  Reject > 1MB body
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 4. Rate Limiting    │  Token bucket + Redis (per-IP, per-account)
  │                     │  429 + Retry-After on exceed
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 5. CORS             │  Check Origin, set Access-Control headers
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 6. Metrics          │  Record: start time, endpoint, method
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 7. Auth (if needed) │  Extract Bearer token, validate JWT,
  │                     │  check revocation, set claims in context
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 8. RBAC (if needed) │  Check roles/scopes from claims
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 9. Validation       │  Bind + validate request body,
  │                     │  set validated_request in context
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 10. Handler         │  Business logic, call service layer
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐
  │ 11. Metrics (after) │  Record: duration, status code
  └─────────┬───────────┘
            ▼
       Response
```
