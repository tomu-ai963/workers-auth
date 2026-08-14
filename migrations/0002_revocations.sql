-- @tomu-ai/workers-auth : revocation list (revocationList)
-- Only needed when the primary store is KV and immediate revocation matters.
-- expires_at is the original session's absolute expiry (epoch ms); rows past it
-- can be deleted because the session would have expired on its own.

CREATE TABLE IF NOT EXISTS auth_revocations (
  sid_hash   TEXT    PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_revocations_expires_at
  ON auth_revocations (expires_at);
