-- 000017_add_client_redirect_uris.down.sql
ALTER TABLE clients DROP COLUMN redirect_uris;
