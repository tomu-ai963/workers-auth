-- Postgres version of migrations/0005_user_revocations.sql. Same tables, columns and indexes;
-- times are BIGINT epoch milliseconds (D1 INTEGER is 64-bit, Postgres
-- INTEGER is not), counters stay INTEGER, JSON stays TEXT.
-- Table names are unqualified: set search_path to apply them to another
-- schema (see README).
-- No Postgres store uses this table yet (D1/KV: revocationList (D1 + KV only)); it is
-- created so both schemas stay numbered and shaped alike.
--
-- @tomu-ai/workers-auth : user-level revocation markers (revocationList)
-- "Log out everywhere" cannot be built by enumerating sessions: KV listing is
-- eventually consistent, so a session created moments before the revocation may
-- not appear in the listing and would survive. One timestamp per user needs no
-- enumeration, so it cannot miss anything.
--
-- A session is invalid when session.created_at < revoked_before.
-- revoked_before is written as (now + 1) so a session created in the same
-- millisecond as the revocation is caught too.
--
-- NOTE: these rows must outlive every session they invalidate. Deleting one
-- early silently un-revokes every session created before it. See
-- revocationList().cleanup() and its maxSessionLifetimeSec option.

CREATE TABLE IF NOT EXISTS auth_user_revocations (
  user_id        TEXT    PRIMARY KEY,
  revoked_before BIGINT  NOT NULL,
  revoked_at     BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_user_revocations_revoked_before
  ON auth_user_revocations (revoked_before);
