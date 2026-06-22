export async function findActiveApiToken(database, id, tokenHash, now) {
  return database
    .prepare(`
      SELECT id, name, user_id, username, scope, created_at, expires_at, revoked_at
      FROM api_tokens
      WHERE id = ? AND token_hash = ?
      LIMIT 1
    `)
    .bind(id, tokenHash)
    .first()
    .then(row => {
      if (!row) return null;
      if (row.revoked_at != null) return null;
      if (row.expires_at != null && Number(row.expires_at) <= now) return null;
      return row;
    });
}

export async function listApiTokens(database) {
  const rows = await database
    .prepare(`
      SELECT id, name, user_id, username, scope, created_at, expires_at, revoked_at
      FROM api_tokens
      ORDER BY created_at DESC
      LIMIT 100
    `)
    .all();
  return rows.results ?? [];
}

export async function insertApiToken(database, token) {
  return database
    .prepare(`
      INSERT INTO api_tokens (id, name, token_hash, user_id, username, scope, created_at, expires_at, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
    `)
    .bind(
      token.id,
      token.name,
      token.tokenHash,
      token.userId,
      token.username,
      token.scope,
      token.createdAt,
      token.expiresAt,
    )
    .run();
}

export async function revokeApiToken(database, id, revokedAt) {
  return database
    .prepare(`
      UPDATE api_tokens
      SET revoked_at = ?
      WHERE id = ? AND revoked_at IS NULL
    `)
    .bind(revokedAt, id)
    .run();
}
