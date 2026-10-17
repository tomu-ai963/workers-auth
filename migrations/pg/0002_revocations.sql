-- Postgres version of migrations/0002_revocations.sql. Same tables, columns and indexes;
-- times are BIGINT epoch milliseconds (D1 INTEGER is 64-bit, Postgres
-- INTEGER is not), counters stay INTEGER, JSON stays TEXT.
-- Table names are unqualified: set search_path to apply them to another
-- schema (see README).
-- No Postgres store uses this table yet (D1/KV: revocationList (D1 + KV only)); it is
-- created so both schemas stay numbered and shaped alike.
--
-- @tomu-ai/workers-auth : revocation list (revocationList)
-- Only needed when the primary store is KV and immediate revocation matters.
-- expires_at is the original session's absolute expiry (epoch ms); rows past it
-- can be deleted because the session would have expired on its own.

CREATE TABLE IF NOT EXISTS auth_revocations (
  sid_hash   TEXT    PRIMARY KEY,
  expires_at BIGINT  NOT NULL,
  revoked_at BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_revocations_expires_at
  ON auth_revocations (expires_at);
