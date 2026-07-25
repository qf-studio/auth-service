-- 000017_add_client_redirect_uris.up.sql
-- Adds redirect_uris to clients, used to validate authorization requests for
-- public OAuth2 clients.

ALTER TABLE clients ADD COLUMN redirect_uris TEXT[] NOT NULL DEFAULT '{}';
