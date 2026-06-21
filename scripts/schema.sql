DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS media;
DROP TABLE IF EXISTS stats;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE media (
  id TEXT PRIMARY KEY,
  ext TEXT NOT NULL,
  size INTEGER,
  user_id INTEGER,
  username TEXT,
  original_name TEXT,
  original_name_lc TEXT,
  object_key TEXT,
  thumb_key TEXT,
  has_thumb INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT
);
CREATE INDEX idx_media_id_desc ON media (id DESC);
CREATE INDEX idx_media_username_id_desc ON media (username, id DESC);
CREATE INDEX idx_media_ext_id_desc ON media (ext, id DESC);
CREATE INDEX idx_media_original_name_lc_id_desc ON media (original_name_lc, id DESC);
CREATE INDEX idx_media_username_original_name_lc_id_desc ON media (username, original_name_lc, id DESC);
CREATE UNIQUE INDEX idx_media_sha256_unique ON media (sha256) WHERE sha256 IS NOT NULL;
CREATE TABLE stats (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);
INSERT INTO stats (key, value) VALUES ('media_count', 0);
