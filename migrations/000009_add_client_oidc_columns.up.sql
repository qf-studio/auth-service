-- Extend clients table with OIDC provider fields.

ALTER TABLE clients
    ADD COLUMN redirect_uris    TEXT[]  NOT NULL DEFAULT '{}',
    ADD COLUMN is_third_party   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN approval_status  TEXT    NOT NULL DEFAULT 'approved';

ALTER TABLE clients
    ADD CONSTRAINT clients_approval_status_check CHECK (
        approval_status IN ('pending', 'approved', 'rejected')
    );

CREATE INDEX idx_clients_is_third_party ON clients (is_third_party) WHERE is_third_party = true;
