const PAGE_SIZE = 50;
const EXTENSION_KINDS = {
  image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'svg', 'avif', 'ico'],
  video: ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'],
  document: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'json', 'xml', 'html'],
  archive: ['zip', 'gz', 'tar', 'tgz', '7z', 'rar'],
};
const ALL_KNOWN_EXTENSIONS = Object.values(EXTENSION_KINDS).flat();

export { PAGE_SIZE };

function nextPrefix(value) {
  if (!value) return '';
  const chars = [...value];
  const last = chars.pop();
  return `${chars.join('')}${String.fromCodePoint(last.codePointAt(0) + 1)}`;
}

function addSearchClause(clauses, values, params, features) {
  if (!params.query) return;
  if (features.searchMode === 'contains') {
    clauses.push('original_name_lc LIKE ?');
    values.push(`%${params.query}%`);
    return;
  }

  const upperBound = nextPrefix(params.query);
  clauses.push('original_name_lc >= ?');
  values.push(params.query);
  if (upperBound) {
    clauses.push('original_name_lc < ?');
    values.push(upperBound);
  }
}

function buildMediaWhere(params, features) {
  const clauses = [];
  const values = [];
  if (params.cursor) {
    clauses.push('id < ?');
    values.push(params.cursor);
  }
  addSearchClause(clauses, values, params, features);
  if (params.uploader) {
    clauses.push('username = ?');
    values.push(params.uploader);
  }
  if (params.kind && EXTENSION_KINDS[params.kind]) {
    clauses.push(`ext IN (${EXTENSION_KINDS[params.kind].map(() => '?').join(',')})`);
    values.push(...EXTENSION_KINDS[params.kind]);
  } else if (params.kind === 'file') {
    clauses.push(`ext NOT IN (${ALL_KNOWN_EXTENSIONS.map(() => '?').join(',')})`);
    values.push(...ALL_KNOWN_EXTENSIONS);
  }
  return {
    sql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    values,
  };
}

export async function listMedia(database, params, features) {
  const limit = PAGE_SIZE + 1;
  const filtered = Boolean(params.query || params.uploader || params.kind);
  const where = buildMediaWhere(params, features);

  const countPromise = !filtered && features.enableTotalCount
    ? database.prepare("SELECT value FROM stats WHERE key = 'media_count'").first()
    : Promise.resolve(null);
  const dataPromise = database
    .prepare(`
      SELECT id, ext, size, user_id, username, original_name, object_key, thumb_key, has_thumb
      FROM media
      ${where.sql}
      ORDER BY id DESC
      LIMIT ?
    `)
    .bind(...where.values, limit)
    .all();

  const [countRow, dataResult] = await Promise.all([countPromise, dataPromise]);
  const rows = dataResult.results ?? [];
  const pageRows = rows.slice(0, PAGE_SIZE);

  return {
    rows: pageRows,
    totalCount: countRow?.value ?? null,
    hasMore: rows.length > PAGE_SIZE,
    nextCursor: rows.length > PAGE_SIZE ? pageRows[pageRows.length - 1]?.id : null,
  };
}

export async function findMediaBySha256(database, sha256) {
  return database
    .prepare(`
      SELECT id, ext, size, user_id, username, original_name, object_key, thumb_key, has_thumb
      FROM media
      WHERE sha256 = ?
      ORDER BY id DESC
      LIMIT 1
    `)
    .bind(sha256)
    .first();
}

export async function insertMedia(database, media) {
  return database
    .prepare(`
      INSERT INTO media (id, ext, size, user_id, username, original_name, original_name_lc, object_key, thumb_key, has_thumb, sha256)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      media.id,
      media.ext,
      media.size,
      media.userId,
      media.username,
      media.originalName,
      media.originalName.toLowerCase(),
      media.objectKey,
      media.thumbKey,
      media.hasThumb ? 1 : 0,
      media.sha256,
    )
    .run();
}

export async function listUploaders(database) {
  const result = await database
    .prepare(`
      SELECT username
      FROM users
      WHERE username IS NOT NULL AND username != ''
      ORDER BY username ASC
      LIMIT 100
    `)
    .all();
  return (result.results ?? []).map(row => row.username);
}

export async function findMediaForDelete(database, ids) {
  const placeholders = ids.map(() => '?').join(',');
  const rows = await database
    .prepare(`SELECT id, object_key, thumb_key, has_thumb FROM media WHERE id IN (${placeholders})`)
    .bind(...ids)
    .all();
  return rows.results ?? [];
}

export async function deleteMediaRows(database, ids) {
  const placeholders = ids.map(() => '?').join(',');
  return database
    .prepare(`DELETE FROM media WHERE id IN (${placeholders})`)
    .bind(...ids)
    .run();
}

export async function updateMediaCount(database, delta) {
  if (!delta) return;
  await database
    .prepare("UPDATE stats SET value = MAX(0, value + ?) WHERE key = 'media_count'")
    .bind(delta)
    .run();
}
