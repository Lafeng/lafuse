import {
  createPlainApiToken,
  hashApiToken,
  invalidateApiTokenCache,
} from '../authToken.js';
import { json } from '../http.js';
import {
  insertApiToken,
  listApiTokens,
  revokeApiToken,
} from '../db/tokenRepository.js';

const MAX_NAME_LENGTH = 48;

function cleanText(value, fallback = '') {
  return String(value || fallback)
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
}

function parseExpiresAt(value) {
  if (value == null || value === '') return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function getTokenResponse(row) {
  return {
    id: row.id,
    name: row.name,
    userId: row.user_id,
    username: row.username,
    scope: row.scope,
    createdAt: Number(row.created_at) * 1000,
    expiresAt: row.expires_at == null ? null : Number(row.expires_at) * 1000,
    revokedAt: row.revoked_at == null ? null : Number(row.revoked_at) * 1000,
  };
}

export async function apiTokens({ config }) {
  const tokens = await listApiTokens(config.database);
  return json({ tokens: tokens.map(getTokenResponse) });
}

export async function apiCreateToken({ request, config, user }) {
  const body = await request.json().catch(() => ({}));
  const name = cleanText(body.name, 'PicGo').slice(0, MAX_NAME_LENGTH);
  if (!name) return json({ error: '缺少 Token 名称' }, 400);

  const expiresAt = parseExpiresAt(body.expiresAt);
  const now = Math.floor(Date.now() / 1000);
  const plain = createPlainApiToken();
  const tokenHash = await hashApiToken(plain.token, config.authSalt);

  await insertApiToken(config.database, {
    id: plain.id,
    name,
    tokenHash,
    userId: user.userId,
    username: user.username,
    scope: 'upload',
    createdAt: now,
    expiresAt,
  });

  return json({
    token: plain.token,
    item: getTokenResponse({
      id: plain.id,
      name,
      user_id: user.userId,
      username: user.username,
      scope: 'upload',
      created_at: now,
      expires_at: expiresAt,
      revoked_at: null,
    }),
  });
}

export async function apiRevokeToken({ request, config }) {
  const body = await request.json().catch(() => ({}));
  const id = cleanText(body.id).toLowerCase();
  if (!/^[a-z0-9]{12}$/.test(id)) return json({ error: 'Token ID 无效' }, 400);

  const result = await revokeApiToken(config.database, id, Math.floor(Date.now() / 1000));
  const changed = result.changes ?? result.meta?.changes ?? 0;
  if (!changed) return json({ error: 'Token 不存在或已撤销' }, 404);
  invalidateApiTokenCache(id);
  return json({ ok: true, id });
}
