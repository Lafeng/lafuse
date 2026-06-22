CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id INTEGER,
  username TEXT,
  scope TEXT NOT NULL DEFAULT 'upload',
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER
);
