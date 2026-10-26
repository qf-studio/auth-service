-- 000022_users_email_case_insensitive_unique.up.sql
-- Makes user email uniqueness case-insensitive (GH-526): "Alice@x.com" and
-- "alice@x.com" must not be two accounts. The service layer now lower-cases
-- every address; this index enforces it at the database.
--
-- Rows are NOT merged or rewritten. If existing data already contains
-- addresses that differ only by case (within a tenant, soft-deleted rows
-- included — the existing unique constraint covers them too), the migration
-- aborts so an operator can resolve the accounts deliberately.
--
-- pending_email has no unique index, so none is added for it.

DO $$
DECLARE
    collisions BIGINT;
BEGIN
    SELECT COUNT(*) INTO collisions FROM (
        SELECT 1
        FROM users
        GROUP BY tenant_id, lower(email)
        HAVING COUNT(*) > 1
    ) AS dup;

    IF collisions > 0 THEN
        RAISE EXCEPTION 'cannot enforce case-insensitive email uniqueness: % (tenant_id, lower(email)) group(s) in users contain addresses that differ only by case; resolve them manually (e.g. SELECT tenant_id, lower(email), array_agg(id) FROM users GROUP BY 1, 2 HAVING COUNT(*) > 1) and re-run', collisions
            USING ERRCODE = 'unique_violation';
    END IF;
END $$;

CREATE UNIQUE INDEX idx_users_tenant_lower_email ON users (tenant_id, lower(email));
