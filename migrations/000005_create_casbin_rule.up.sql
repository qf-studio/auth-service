-- casbin_rule stores Casbin policy and role-definition rows.
-- Each row is one policy line: p = sub, obj, act  or  g = user, role
CREATE TABLE IF NOT EXISTS casbin_rule (
    id      BIGSERIAL PRIMARY KEY,
    ptype   VARCHAR(100)  NOT NULL,   -- "p" (policy) or "g" (role definition)
    v0      VARCHAR(1000) NOT NULL DEFAULT '',
    v1      VARCHAR(1000) NOT NULL DEFAULT '',
    v2      VARCHAR(1000) NOT NULL DEFAULT '',
    v3      VARCHAR(1000) NOT NULL DEFAULT '',
    v4      VARCHAR(1000) NOT NULL DEFAULT '',
    v5      VARCHAR(1000) NOT NULL DEFAULT '',
    UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
);

CREATE INDEX IF NOT EXISTS idx_casbin_rule_ptype_v0 ON casbin_rule (ptype, v0);
