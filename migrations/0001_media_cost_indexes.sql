ALTER TABLE media ADD COLUMN original_name_lc TEXT;

UPDATE media
SET original_name_lc = LOWER(COALESCE(original_name, id || '.' || ext))
WHERE original_name_lc IS NULL;

UPDATE media
SET original_name = id || '.' || ext
WHERE original_name IS NULL;

UPDATE media
SET object_key = 'i/' || id || '.' || ext
WHERE object_key IS NULL;

UPDATE media
SET thumb_key = 't/' || id || '.jpg'
WHERE has_thumb = 1 AND thumb_key IS NULL;

CREATE TABLE IF NOT EXISTS stats (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO stats (key, value)
VALUES ('media_count', (SELECT COUNT(*) FROM media));

CREATE INDEX IF NOT EXISTS idx_media_id_desc ON media (id DESC);
CREATE INDEX IF NOT EXISTS idx_media_username_id_desc ON media (username, id DESC);
CREATE INDEX IF NOT EXISTS idx_media_ext_id_desc ON media (ext, id DESC);
CREATE INDEX IF NOT EXISTS idx_media_original_name_lc_id_desc ON media (original_name_lc, id DESC);
CREATE INDEX IF NOT EXISTS idx_media_username_original_name_lc_id_desc ON media (username, original_name_lc, id DESC);

DROP INDEX IF EXISTS idx_media_sha256;

UPDATE media
SET sha256 = NULL
WHERE sha256 IS NOT NULL
  AND id NOT IN (
    SELECT MAX(id)
    FROM media
    WHERE sha256 IS NOT NULL
    GROUP BY sha256
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_media_sha256_unique ON media (sha256) WHERE sha256 IS NOT NULL;
