-- 000018_consent_grants.up.sql
-- Durable remembered-consent grants for the OIDC provider: records which
-- scopes a user has approved for a client so future authorization requests
-- can skip the consent screen when the user asked to be remembered
-- (see GH-431, GH-467). Ephemeral login/consent challenges and one-time
-- authorization codes live in Redis (internal/oidc), not here.
--
-- Decision: user_id is TEXT (not UUID) to match users.id (000003). 000010
-- and 000014 originally got this wrong and had to be fixed post-hoc
-- (GH-444) because Postgres rejects FKs on type mismatch.

CREATE TABLE consent_grants (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenants (id),
    user_id    TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  UUID        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    scopes     TEXT[]      NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_consent_grants_tenant_id ON consent_grants (tenant_id);
CREATE INDEX idx_consent_grants_user_id ON consent_grants (user_id);
CREATE INDEX idx_consent_grants_client_id ON consent_grants (client_id);

-- Only one active (non-revoked) grant per tenant+user+client; re-granting
-- after revocation inserts a new row rather than updating the old one, per
-- the auditable/revocable design in tech-decisions.md.
CREATE UNIQUE INDEX idx_consent_grants_tenant_user_client_active
    ON consent_grants (tenant_id, user_id, client_id) WHERE revoked_at IS NULL;

ALTER TABLE consent_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_consent_grants ON consent_grants
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
