# Client Model — Users vs Systems

**Updated**: 2026-02-24

## Two Client Types

The auth service treats **Users** (humans) and **Systems** (services + AI agents) as first-class citizens with distinct authentication flows, token policies, and security profiles.

## Client Type: User (Human)

### Authentication Flow
- **Primary**: Authorization Code + PKCE (OAuth 2.1)
- **Phase 1**: Email/password → JWT pair
- **Phase 2**: + TOTP/WebAuthn (MFA)
- **Phase 2**: + Social login (Google, GitHub, Apple)

### Token Policy
| Token | Lifetime | Storage | Revocable |
|---|---|---|---|
| Access | 15 min | Not stored (signature verification) | Via jti blocklist |
| Refresh | 14 days | Redis with metadata | Immediate |
| Session | 24h overall, 1h idle | Redis | Immediate |

### Security Profile
- NIST AAL2: MFA required (Phase 2)
- Rate limit: 10 failed logins/hour per account
- Password: NIST Rev 4 compliant (15-char min, no composition rules)
- Breached password check on registration and change
- Progressive lockout on failed attempts

### Identity Model
```go
type User struct {
    ID            uuid.UUID
    Email         string     // unique, validated
    PasswordHash  string     // Argon2id
    Roles         []string   // ["admin", "user"]
    Status        string     // active, suspended, locked
    MFAEnabled    bool       // Phase 2
    CreatedAt     time.Time
    UpdatedAt     time.Time
    LastLoginAt   *time.Time
    PasswordChangedAt time.Time
}
```

---

## Client Type: System (Service / AI Agent)

### Authentication Flow
- **Primary**: OAuth2 Client Credentials (client_id + client_secret)
- **Phase 2**: + DPoP (proof-of-possession token binding)
- **Phase 2**: + mTLS (certificate-based)
- **Phase 2**: + Token Exchange (RFC 8693) for delegation chains

### Token Policy
| Token | Lifetime | Storage | Revocable |
|---|---|---|---|
| Access | 5-15 min (configurable per client) | Not stored (signature verification) | Via jti blocklist |
| Refresh | None (or sender-constrained) | N/A | N/A |

### Security Profile
- No MFA (cryptographic auth methods instead)
- Rate limit: higher throughput, stricter burst limits per client
- API keys: 128-bit entropy, hashed storage, scoped, rotatable
- Short-lived tokens only — no long-lived sessions
- Emergency revocation (kill switch) for all tokens of a client

### Identity Model
```go
type Client struct {
    ID                    uuid.UUID
    Name                  string     // human-readable identifier
    ClientType            string     // "service" | "agent"
    TokenEndpointAuthMethod string   // "client_secret_basic" | "client_secret_post" | "private_key_jwt" | "none"
    SecretHash            string     // Argon2id hashed
    Scopes                []string   // allowed scopes
    Roles                 []string   // ["service", "agent"]
    Owner                 string     // owning entity/team
    SkipConsent           bool       // true for first-party
    AccessTokenTTL        time.Duration // per-client override
    Status                string     // active, suspended, revoked
    CreatedAt             time.Time
    UpdatedAt             time.Time
    LastUsedAt            *time.Time
}
```

---

## Comparison Matrix

| Aspect | User (Human) | System (Service/Agent) |
|---|---|---|
| Auth flow | Auth Code + PKCE | Client Credentials |
| Token lifetime | 15min access, 14d refresh | 5-15min access, no refresh |
| MFA | TOTP + WebAuthn (Phase 2) | DPoP / mTLS (Phase 2) |
| Session | Interactive, idle timeout | Stateless, per-request |
| Rate limits | Per-user, moderate | Per-client, high throughput |
| Audit trail | user_id + IP + device | client_id + service + delegation |
| Registration | Self-service (email/password) | Admin-only (controlled) |
| Credential type | Password + MFA | Secret / Certificate / DPoP key |

---

## Role System

### Built-in Roles (Phase 1)
| Role | Description | Assigned To |
|---|---|---|
| `admin` | Full system access | Human administrators |
| `user` | Standard user access | Human users |
| `service` | Service-to-service | Backend services |
| `agent` | AI agent access | AI agents (Pilot, etc.) |

### Phase 2: Casbin RBAC
- Policy-based: `sub, obj, act` (who, what resource, what action)
- Per-tenant role isolation
- Admin API for policy management

---

## Agent-Specific Considerations

### Why Agents Are Special
- Autonomous operation (no human in the loop per-request)
- May chain through multiple services (delegation)
- Higher risk of credential exposure (prompt injection, logs)
- Need emergency kill switch

### Mitigations
- Unique identity per agent instance (never shared credentials)
- Short-lived tokens (5-15 min max)
- Scoped to minimum required permissions
- Full audit trail with `client_type: agent` marker
- DPoP binding prevents token theft (Phase 2)
- Token Exchange with `act` claims for delegation chains (Phase 2)
- Centralized revocation with sub-second propagation
