# Security Profile — NIST SP 800-63-4 Compliance

**Updated**: 2026-02-24
**Target**: AAL2 (Authenticator Assurance Level 2)

## Assurance Level Summary

| Level | Meaning | Our Target |
|---|---|---|
| AAL1 | Single-factor | Minimum for basic access |
| **AAL2** | **Multi-factor required** | **Our baseline** |
| AAL3 | Cryptographic proof + hardware | Future (Phase 3) |

## Password Policy (NIST Rev 4)

These are NIST mandates — not suggestions:

| Requirement | Value | NIST Ref |
|---|---|---|
| Min length (single-factor) | **15 characters** | SP 800-63B §3.1.1 |
| Min length (as MFA component) | **8 characters** | SP 800-63B §3.1.1 |
| Max length | **at least 64 chars** | SP 800-63B §3.1.1 |
| Character types | All Unicode, ASCII, space | SP 800-63B §3.1.1 |
| Composition rules | **NONE** (no "must have uppercase") | SP 800-63B §3.1.1 |
| Periodic rotation | **FORBIDDEN** (only on compromise) | SP 800-63B §3.1.1 |
| Breached password check | **REQUIRED** (HaveIBeenPwned k-anonymity) | SP 800-63B §3.1.1 |
| Security questions | **FORBIDDEN** | SP 800-63B §3.1.1 |
| Password hints | **FORBIDDEN** (to unauthenticated) | SP 800-63B §3.1.1 |
| Truncation | **FORBIDDEN** (verify entire password) | SP 800-63B §3.1.1 |
| Paste support | Permitted (for password managers) | SP 800-63B §3.1.1 |

## Cryptographic Requirements

| Component | Algorithm | Parameters |
|---|---|---|
| Password hashing | Argon2id | m=19456 (19 MiB), t=2, p=1 |
| Password salt | crypto/rand | 128-bit (NIST min: 32-bit) |
| Pepper (keyed hash) | HMAC-SHA-256 | 256-bit key (HSM/KMS stored) |
| JWT signing | ES256 (ECDSA P-256) | 256-bit key, 128-bit security |
| JWT signing (alt) | EdDSA (Ed25519) | 256-bit key, 128-bit security |
| Session tokens | crypto/rand | 256-bit (NIST min: 64-bit) |
| API tokens | crypto/rand | 128-bit minimum |
| TLS | TLS 1.3 | AES-256-GCM, CHACHA20-POLY1305 |
| Token signatures | HMAC-SHA-256 | 256-bit key |

## Session Management (AAL2)

| Requirement | Value | NIST Ref |
|---|---|---|
| Overall timeout | **24 hours max** | SP 800-63B AAL2 |
| Inactivity timeout | **1 hour max** | SP 800-63B AAL2 |
| After inactivity | Single-factor reauth OK (before overall timeout) | SP 800-63B AAL2 |
| After overall timeout | Full MFA re-authentication required | SP 800-63B AAL2 |
| Cookie: Secure | **Required** | SP 800-63B §5.1 |
| Cookie: HttpOnly | **Required** | SP 800-63B §5.1 |
| Cookie: SameSite | **Strict** or **Lax** | SP 800-63B §5.1 |
| Cookie: prefix | `__Host-` with `Path=/` | SP 800-63B §5.1 |
| CSRF protection | **Required** on all state-changing endpoints | SP 800-63B §5.1 |
| Session token entropy | 256-bit from crypto/rand | SP 800-63B §5.1 |
| Logout | Erase/invalidate session secret | SP 800-63B §5.1 |

## Rate Limiting (NIST)

| Requirement | Value |
|---|---|
| Max failed attempts per account | **100** before lockout |
| Progressive delay | 30s increments |
| Biometric failures | 5 consecutive (10 with PAD) |
| Reset on success | Yes |

## Audit Logging (SP 800-53 AU-2/AU-3)

### Required Events
- Successful and failed authentication attempts
- Password changes and resets
- Account lockouts and unlocks
- Session creation, reauth, termination
- MFA enrollment and de-enrollment
- Administrative privilege usage
- Authenticator binding and unbinding
- Rate limit triggers

### Audit Record Fields
- Event type
- Timestamp (UTC, NTP-synced)
- Source system/component
- Source IP, user agent
- Outcome (success/failure)
- Subject ID (never passwords/secrets)
- Correlation ID

## Token Design

### Prefixes (for automated leak detection)
- `qf_at_` — Access token
- `qf_rt_` — Refresh token
- `qf_ac_` — Authorization code
- `qf_ak_` — API key

### Storage
- **Access tokens**: Signature only in DB (full token never stored)
- **Refresh tokens**: Signature in Redis with metadata, TTL-based expiry
- **API keys**: Hashed (Argon2id), never stored in plaintext

### JWT Claims
```json
{
  "sub": "user-uuid",
  "iss": "auth.quantflow.studio",
  "aud": ["api.quantflow.studio"],
  "exp": 1740000000,
  "iat": 1739999100,
  "jti": "unique-token-id",
  "client_id": "client-uuid",
  "client_type": "user|service|agent",
  "roles": ["admin", "user"],
  "scopes": ["read", "write"]
}
```

## M2M / AI Agent Security

NIST SP 800-63-4 explicitly excludes M2M. We follow SP 800-207 (Zero Trust) + SP 800-53 (IA controls):

- Unique identity per agent/service instance
- Short-lived tokens (5-15 min for agents)
- OAuth2 Client Credentials flow
- DPoP for proof-of-possession (Phase 2)
- mTLS for transport-level identity (Phase 2)
- Full audit trail with delegation chain
- Emergency revocation capability (kill switch)
- Principle of least privilege (scoped tokens)
