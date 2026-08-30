-- 000019_create_api_keys_table.up.sql
-- API keys for service/agent authentication (see GH-485). The table was
-- never created despite internal/storage/apikey_repository.go targeting it
-- since its introduction — every query against api_keys 500'd with
-- "relation does not exist". Columns match apiKeyColumns in
-- apikey_repository.go and domain.APIKey exactly.
--
-- key_hash stores a SHA-256 hex digest of the raw key (deterministic,
-- indexed lookup), not an Argon2id hash: API keys are 256-bit random
-- secrets, not human passwords, so salted slow hashing both defeats
-- indexed lookup and adds needless per-request latency. See
-- ValidateAPIKey in internal/admin/apikey_service.go.

CREATE TABLE api_keys (
    id                        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 UUID        NOT NULL REFERENCES tenants (id),
    client_id                 UUID        NOT NULL REFERENCES clients (id),
    name                      TEXT        NOT NULL,
    key_hash                  TEXT        NOT NULL,
    previous_key_hash         TEXT        NOT NULL DEFAULT '',
    previous_key_expires_at   TIMESTAMPTZ,
    key_prefix                TEXT        NOT NULL,
    scopes                    TEXT[]      NOT NULL DEFAULT '{}',
    rate_limit                INTEGER     NOT NULL DEFAULT 0,
    status                    TEXT        NOT NULL DEFAULT 'active',
    expires_at                TIMESTAMPTZ,
    last_used_at              TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_api_keys ON api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
