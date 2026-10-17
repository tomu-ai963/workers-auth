-- Postgres version of migrations/0003_magic_link_tokens.sql. Same tables, columns and indexes;
-- times are BIGINT epoch milliseconds (D1 INTEGER is 64-bit, Postgres
-- INTEGER is not), counters stay INTEGER, JSON stays TEXT.
-- Table names are unqualified: set search_path to apply them to another
-- schema (see README).
-- No Postgres store uses this table yet (D1/KV: d1MagicLinkStore / kvMagicLinkStore); it is
-- created so both schemas stay numbered and shaped alike.
--
-- @tomu-ai/workers-auth : magic-link tokens (d1MagicLinkStore)
-- token_hash is sha256(token) hex. The raw token only ever exists in the email.
-- The D1 store consumes tokens with DELETE ... RETURNING, which makes
-- single-use atomic. The KV store cannot offer that guarantee.

CREATE TABLE IF NOT EXISTS auth_magic_link_tokens (
  token_hash TEXT    PRIMARY KEY,
  email      TEXT    NOT NULL,
  expires_at BIGINT  NOT NULL,
  created_at BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_magic_link_tokens_expires_at
  ON auth_magic_link_tokens (expires_at);
