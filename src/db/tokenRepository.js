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
