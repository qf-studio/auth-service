CREATE TABLE rar_resource_types (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    type              TEXT        NOT NULL UNIQUE,
    description       TEXT        NOT NULL DEFAULT '',
    allowed_actions   TEXT[]      NOT NULL DEFAULT '{}',
    allowed_datatypes TEXT[]      NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE client_rar_allowed_types (
    client_id        UUID        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    resource_type_id UUID        NOT NULL REFERENCES rar_resource_types (id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (client_id, resource_type_id)
);

CREATE INDEX idx_client_rar_allowed_types_client ON client_rar_allowed_types (client_id);
CREATE INDEX idx_client_rar_allowed_types_resource_type ON client_rar_allowed_types (resource_type_id);
