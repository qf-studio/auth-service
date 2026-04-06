CREATE TABLE saml_idp_configs (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id           TEXT        NOT NULL UNIQUE,
    metadata_url        TEXT        NOT NULL DEFAULT '',
    metadata_xml        TEXT        NOT NULL DEFAULT '',
    sso_url             TEXT        NOT NULL,
    slo_url             TEXT        NOT NULL DEFAULT '',
    certificate         TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    attribute_mappings  JSONB       NOT NULL DEFAULT '{}',
    enabled             BOOLEAN     NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE saml_accounts (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    idp_id              UUID        NOT NULL REFERENCES saml_idp_configs (id) ON DELETE CASCADE,
    name_id             TEXT        NOT NULL,
    session_index       TEXT        NOT NULL DEFAULT '',
    cached_attributes   JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (idp_id, name_id)
);

CREATE INDEX idx_saml_idp_configs_entity_id ON saml_idp_configs (entity_id);
CREATE INDEX idx_saml_accounts_user_id ON saml_accounts (user_id);
CREATE INDEX idx_saml_accounts_idp_id ON saml_accounts (idp_id);
CREATE INDEX idx_saml_accounts_name_id ON saml_accounts (idp_id, name_id);
