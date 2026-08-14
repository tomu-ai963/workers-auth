-- @tomu-ai/workers-auth : magic-link tokens (d1MagicLinkStore)
-- token_hash is sha256(token) hex. The raw token only ever exists in the email.
-- The D1 store consumes tokens with DELETE ... RETURNING, which makes
-- single-use atomic. The KV store cannot offer that guarantee.

CREATE TABLE IF NOT EXISTS auth_magic_link_tokens (
  token_hash TEXT    PRIMARY KEY,
  email      TEXT    NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_magic_link_tokens_expires_at
  ON auth_magic_link_tokens (expires_at);
