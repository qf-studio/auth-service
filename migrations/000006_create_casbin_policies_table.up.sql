-- 000006_create_casbin_policies_table.up.sql
-- Creates the Casbin policy storage table for RBAC enforcement.

CREATE TABLE casbin_policies (
    id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ptype TEXT NOT NULL DEFAULT '',
    v0    TEXT NOT NULL DEFAULT '',
    v1    TEXT NOT NULL DEFAULT '',
    v2    TEXT NOT NULL DEFAULT '',
    v3    TEXT NOT NULL DEFAULT '',
    v4    TEXT NOT NULL DEFAULT '',
    v5    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_casbin_policies_ptype ON casbin_policies (ptype);
CREATE INDEX idx_casbin_policies_lookup ON casbin_policies (ptype, v0, v1, v2);
