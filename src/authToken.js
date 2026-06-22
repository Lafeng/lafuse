import { findActiveApiToken } from './db/tokenRepository.js';

const TOKEN_RE = /^lafuse_v1_([a-z0-9]{12})_([A-Za-z0-9_-]{32,})$/;
const TOKEN_CACHE_TTL_MS = 60_000;
const TOKEN_CACHE_MAX = 100;
const tokenCache = new Map();
const tokenKeyCache = new Map();
const TOKEN_SECRET_BYTES = 33;

function getRandomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64UrlEncode(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hexEncode(bytes) {
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function createPlainApiToken() {
  const id = hexEncode(getRandomBytes(6));
  const secret = base64UrlEncode(getRandomBytes(TOKEN_SECRET_BYTES));
  return {
    id,
    token: `lafuse_v1_${id}_${secret}`,
  };
}

export async function hashApiToken(token, salt) {
  if (!tokenKeyCache.has(salt)) {
    tokenKeyCache.set(salt, crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(`lafuse-api-token:${salt}`),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    ));
  }
  const key = await tokenKeyCache.get(salt);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(token),
  );
  return base64UrlEncode(signature);
}

export function parseBearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

export function parseApiToken(token) {
  const match = TOKEN_RE.exec(token);
  if (!match) return null;
  return {
    id: match[1],
    secret: match[2],
  };
}

function getTokenCacheKey(id, tokenHash) {
  return `${id}:${tokenHash}`;
}

function getCachedTokenUser(id, tokenHash, nowMs) {
  const cached = tokenCache.get(getTokenCacheKey(id, tokenHash));
  if (!cached) return null;
  if (cached.cacheExpiresAt <= nowMs) {
    tokenCache.delete(getTokenCacheKey(id, tokenHash));
    return null;
  }
  if (cached.expiresAt != null && Number(cached.expiresAt) <= Math.floor(nowMs / 1000)) {
    tokenCache.delete(getTokenCacheKey(id, tokenHash));
    return null;
  }
  return cached.user;
}

function cacheTokenUser(id, tokenHash, row, user, nowMs) {
  if (tokenCache.size >= TOKEN_CACHE_MAX) {
    tokenCache.delete(tokenCache.keys().next().value);
  }
  tokenCache.set(getTokenCacheKey(id, tokenHash), {
    user,
    expiresAt: row.expires_at,
    cacheExpiresAt: nowMs + TOKEN_CACHE_TTL_MS,
  });
}

export function invalidateApiTokenCache(id) {
  for (const key of tokenCache.keys()) {
    if (key.startsWith(`${id}:`)) tokenCache.delete(key);
  }
}

export async function getApiTokenUser(request, config) {
  const token = parseBearerToken(request);
  const parsed = parseApiToken(token);
  if (!parsed) return null;

  const tokenHash = await hashApiToken(token, config.authSalt);
  const nowMs = Date.now();
  const cached = getCachedTokenUser(parsed.id, tokenHash, nowMs);
  if (cached) return cached;

  const row = await findActiveApiToken(
    config.database,
    parsed.id,
    tokenHash,
    Math.floor(nowMs / 1000),
  );
  if (!row || row.scope !== 'upload') return null;

  const user = {
    tokenId: row.id,
    tokenName: row.name,
    userId: row.user_id,
    username: row.username || row.name,
    role: 'api',
  };
  cacheTokenUser(parsed.id, tokenHash, row, user, nowMs);
  return user;
}
