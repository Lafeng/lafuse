// ═══════════════════════════════════════════════════════════════════════════════
// Lafuse Worker — High-performance Cloudflare Workers entry point
//
// Architecture:
//   1. Constants & Config
//   2. Response utilities
//   3. Auth utilities (rate limiting, sessions)
//   4. Route handlers (grouped by domain)
//   5. Route table (declarative, O(1) dispatch)
//   6. Router entry point
//
// Database schema (D1):
//   CREATE TABLE users (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     username TEXT UNIQUE NOT NULL,
//     password_hash TEXT NOT NULL,
//     role TEXT NOT NULL DEFAULT 'user'
//   );
//   CREATE TABLE media (
//     id TEXT PRIMARY KEY,
//     ext TEXT NOT NULL,
//     user_id INTEGER,
//     username TEXT
//   );
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Constants ───────────────────────────────────────────────────────────────

const CONTENT_TYPES = {
  // Images
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
  gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
  svg: 'image/svg+xml', ico: 'image/x-icon', tiff: 'image/tiff', avif: 'image/avif',
  // Videos
  mp4: 'video/mp4', avi: 'video/x-msvideo', mov: 'video/quicktime',
  webm: 'video/webm', mkv: 'video/x-matroska', flv: 'video/x-flv', wmv: 'video/x-ms-wmv',
  // Audio
  mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac', aac: 'audio/aac',
  // Documents
  pdf: 'application/pdf',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  // Archives
  zip: 'application/zip', gz: 'application/gzip', tar: 'application/x-tar',
  '7z': 'application/x-7z-compressed', rar: 'application/x-rar-compressed',
  // Text / Code
  txt: 'text/plain', csv: 'text/csv', json: 'application/json',
  xml: 'application/xml', html: 'text/html', css: 'text/css', js: 'application/javascript',
};

const CACHE_TTL = { HTML: 3600, IMAGE: 86400, API: 300, STATIC: 86400 };

/** Brute-force protection */
const MAX_LOGIN_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW = 900; // 15 minutes (seconds)


// ─── Config ──────────────────────────────────────────────────────────────────
//
// _config is initialised once on the first request and reused for the lifetime
// of the isolate.  env bindings are stable across requests within one isolate.
//
let _config = null;

function buildConfig(env) {
  return {
    domain: env.DOMAIN,
    database: env.DATABASE,
    r2Bucket: env.R2_BUCKET,
    kvNamespace: env.KV_NAMESPACE,
    authSalt: env.AUTH_SALT ?? '6db26ef6',
    sessionCookieName: env.SESSION_COOKIE_NAME ?? 'lafuse_session',
    sessionTtlSeconds: (env.SESSION_TTL_DAYS ? parseInt(env.SESSION_TTL_DAYS, 10) : 7) * 86400,
    maxSize: (env.MAX_SIZE_MB ? parseInt(env.MAX_SIZE_MB, 10) : 10) * 1048576,
  };
}

// ─── Response Utilities ──────────────────────────────────────────────────────

function json(data, status = 200, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function parseHttpDate(value) {
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

function normalizeEtag(value) {
  if (!value) return '';
  return value.trim().replace(/^W\//i, '');
}

function matchesIfNoneMatch(ifNoneMatch, etag) {
  if (!ifNoneMatch || !etag) return false;
  if (ifNoneMatch.trim() === '*') return true;
  const target = normalizeEtag(etag);
  return ifNoneMatch
    .split(',')
    .map(v => normalizeEtag(v))
    .some(candidate => candidate === target);
}

function shouldReturnNotModified(request, etag, lastModified) {
  const ifNoneMatch = request.headers.get('If-None-Match');
  if (ifNoneMatch) return matchesIfNoneMatch(ifNoneMatch, etag);

  const ifModifiedSince = request.headers.get('If-Modified-Since');
  if (!ifModifiedSince || !lastModified) return false;

  const since = parseHttpDate(ifModifiedSince);
  const modifiedAt = parseHttpDate(lastModified);
  if (since === null || modifiedAt === null) return false;
  return modifiedAt <= since;
}

function buildNotModifiedResponse(headersSource) {
  const headers = new Headers();
  for (const key of ['ETag', 'Last-Modified', 'Cache-Control', 'CDN-Cache-Control', 'Vary', 'Expires']) {
    const value = headersSource.get(key);
    if (value) headers.set(key, value);
  }
  return new Response(null, { status: 304, headers });
}

function parseMediaPathname(pathname) {
  // Accepts /i/{id}.{ext}  (original file)
  //      or /t/{id}.jpg    (thumbnail)
  const slash2 = pathname.indexOf('/', 1);
  if (slash2 < 0) return null;
  const prefix = pathname.substring(1, slash2); // 'i' | 't'
  if (prefix !== 'i' && prefix !== 't') return null;

  const fileName = pathname.substring(slash2 + 1);
  const dotIdx = fileName.lastIndexOf('.');
  if (dotIdx < 1) return null;

  const originalId = fileName.substring(0, dotIdx);
  const extension = fileName.substring(dotIdx + 1).toLowerCase();
  const isThumb = prefix === 't';
  const r2Key = isThumb ? `t/${originalId}` : originalId;

  return { r2Key, extension, isThumb, originalId };
}

function buildMediaHeaders({ etag, lastModified, contentType, contentLength }) {
  const headers = new Headers({
    'Content-Type': contentType,
    'Content-Disposition': 'inline',
    ETag: etag,
    // immutable: IDs are random & never change, skip revalidation within max-age
    'Cache-Control': `public, max-age=${CACHE_TTL.IMAGE}, immutable`,
    'CDN-Cache-Control': `public, max-age=${CACHE_TTL.IMAGE}, immutable`,
  });

  if (lastModified) headers.set('Last-Modified', lastModified);
  // Content-Length is required by Safari to cache responses correctly
  if (contentLength != null) headers.set('Content-Length', String(contentLength));
  return headers;
}

// ─── Auth Utilities ──────────────────────────────────────────────────────────

function parseCookies(header) {
  if (!header) return {};
  const out = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    out[part.substring(0, eq).trim()] = decodeURIComponent(part.substring(eq + 1).trim());
  }
  return out;
}

async function hashPassword(password, salt) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${salt}:${password}`),
  );
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function createSessionId() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function buildSessionCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function clearSessionCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

// ─── Rate Limiting ───────────────────────────────────────────────────────────

async function getRateLimitCount(ip, kv) {
  const raw = await kv.get(`ratelimit:${ip}`);
  return raw ? parseInt(raw, 10) : 0;
}

async function recordFailedAttempt(ip, kv) {
  const key = `ratelimit:${ip}`;
  const count = (await getRateLimitCount(ip, kv)) + 1;
  await kv.put(key, String(count), { expirationTtl: RATE_LIMIT_WINDOW });
  return count;
}

async function clearRateLimit(ip, kv) {
  await kv.delete(`ratelimit:${ip}`);
}

// ─── Media ID Generation ─────────────────────────────────────────────────────
//
// Format: {base36_timestamp}{8_char_random}
//   - Sortable: lexicographic order ≈ chronological order
//   - Timestamp extractable: parseInt(id.slice(0, -8), 36)
//   - Collision-proof: 4 random bytes per millisecond
//

function generateMediaId() {
  const r = crypto.getRandomValues(new Uint8Array(4));
  return Date.now().toString(36)
    + Array.from(r, b => b.toString(36).padStart(2, '0')).join('');
}

function extractTimestampFromId(id) {
  return parseInt(id.slice(0, -8), 36);
}

async function getSessionUser(request, config) {
  const sid = parseCookies(request.headers.get('Cookie'))[config.sessionCookieName];
  if (!sid) return null;
  const raw = await config.kvNamespace.get(`session:${sid}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

// ─── Route Handlers: Pages ───────────────────────────────────────────────────

async function serveIndex({ request, config, env }) {
  const user = await getSessionUser(request, config);
  if (!user) return Response.redirect(new URL('/login', request.url), 302);
  return env.ASSETS.fetch(new Request(new URL('/index.html', request.url)));
}

async function serveLogin({ request, config, env }) {
  const user = await getSessionUser(request, config);
  if (user) return Response.redirect(new URL('/', request.url), 302);
  return env.ASSETS.fetch(new Request(new URL('/login.html', request.url)));
}

// ─── Route Handlers: Auth API ────────────────────────────────────────────────

async function apiLogin({ request, config }) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const kv = config.kvNamespace;

  // Check ban before any processing
  const attempts = await getRateLimitCount(ip, kv);
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    return json({ error: '登录尝试次数过多，请15分钟后再试' }, 429);
  }

  try {
    const { username, password } = await request.json();
    if (!username || !password) return json({ error: '缺少用户名或密码' }, 400);

    const row = await config.database
      .prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?')
      .bind(username)
      .first();

    if (!row) {
      await recordFailedAttempt(ip, kv);
      return json({ error: '用户名或密码错误' }, 401);
    }

    const hash = await hashPassword(password, config.authSalt);
    if (hash !== row.password_hash.toLowerCase()) {
      const count = await recordFailedAttempt(ip, kv);
      const remaining = MAX_LOGIN_ATTEMPTS - count;
      return json({
        error: remaining > 0
          ? `用户名或密码错误，还剩 ${remaining} 次尝试机会`
          : '登录尝试次数过多，请15分钟后再试',
      }, 401);
    }

    // Success — clear rate limit and create session
    await clearRateLimit(ip, kv);
    const sessionId = createSessionId();
    const payload = { userId: row.id, username: row.username, role: row.role };
    await config.kvNamespace.put(`session:${sessionId}`, JSON.stringify(payload), {
      expirationTtl: config.sessionTtlSeconds,
    });

    return json({ ok: true, user: payload }, 200, {
      'Set-Cookie': buildSessionCookie(config.sessionCookieName, sessionId, config.sessionTtlSeconds),
    });
  } catch (e) {
    return json({ error: e.message ?? '登录失败' }, 500);
  }
}

async function apiLogout({ request, config }) {
  const sid = parseCookies(request.headers.get('Cookie'))[config.sessionCookieName];
  if (sid) await config.kvNamespace.delete(`session:${sid}`);
  return json({ ok: true }, 200, {
    'Set-Cookie': clearSessionCookie(config.sessionCookieName),
  });
}

async function apiSession({ request, config }) {
  const user = await getSessionUser(request, config);
  return json({ user: user ?? null });
}

// ─── Route Handlers: Media API ───────────────────────────────────────────────

async function apiMedia({ config, url }) {
  const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10));
  const pageSize = 50;
  const offset = (page - 1) * pageSize;

  const [countRow, dataResult] = await Promise.all([
    config.database.prepare('SELECT COUNT(*) as count FROM media').first(),
    config.database
      .prepare('SELECT id, ext, user_id, username FROM media ORDER BY id DESC LIMIT ? OFFSET ?')
      .bind(pageSize, offset)
      .all(),
  ]);

  return json({
    media: dataResult.results.map(r => ({
      url: `https://${config.domain}/i/${r.id}.${r.ext}`,
      createdAt: extractTimestampFromId(r.id),
      userId: r.user_id,
      username: r.username,
    })),
    totalCount: countRow.count,
    totalPages: Math.ceil(countRow.count / pageSize),
    currentPage: page,
  });
}

async function apiUpload({ request, config, user }) {
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file) throw new Error('缺少文件');
    if (file.size > config.maxSize) {
      return json({ error: `文件大小超过${config.maxSize / 1048576}MB限制` }, 413);
    }

    const id = generateMediaId();
    const ext = file.name.split('.').pop().toLowerCase();

    await config.r2Bucket.put(id, file.stream(), {
      httpMetadata: { contentType: file.type },
    });

    await config.database
      .prepare('INSERT INTO media (id, ext, user_id, username) VALUES (?, ?, ?, ?)')
      .bind(id, ext, user.userId, user.username)
      .run();

    return json({ data: `https://${config.domain}/i/${id}.${ext}` });
  } catch (e) {
    console.error('R2 上传错误:', e);
    return json({ error: e.message }, 500);
  }
}

async function apiDelete({ request, config }) {
  try {
    const urls = await request.json();
    if (!Array.isArray(urls) || urls.length === 0) {
      return json({ message: '没有要删除的项' }, 400);
    }

    // Extract media IDs from URLs for primary-key deletion
    // URLs have the form https://domain/i/{id}.{ext}
    const ids = urls.map(u => {
      const stem = new URL(u).pathname.split('/').pop();
      return stem.substring(0, stem.lastIndexOf('.'));
    });
    const placeholders = ids.map(() => '?').join(',');
    const cache = caches.default;

    const [dbResult] = await Promise.all([
      config.database
        .prepare(`DELETE FROM media WHERE id IN (${placeholders})`)
        .bind(...ids)
        .run(),
      Promise.all(urls.map(async (u, i) => {
        const id = ids[i];
        const origin = new URL(u).origin;
        const thumbUrl = `${origin}/t/${id}.jpg`;
        await Promise.all([
          cache.delete(new Request(u)),
          cache.delete(new Request(thumbUrl)),
          config.r2Bucket.delete(id),
          config.r2Bucket.delete(`t/${id}`),
        ]);
      })),
    ]);

    return dbResult.changes === 0
      ? json({ message: '未找到要删除的项' }, 404)
      : json({ message: '删除成功' });
  } catch (e) {
    return json({ error: '删除失败', details: e.message }, 500);
  }
}

async function apiUploadThumb({ request, config, url }) {
  try {
    const id = url.searchParams.get('id');
    if (!id) return json({ error: '缺少文件 ID' }, 400);

    // Security: verify the original file exists in the DB
    const row = await config.database
      .prepare('SELECT id FROM media WHERE id = ?')
      .bind(id)
      .first();
    if (!row) return json({ error: '原始文件不存在' }, 404);

    const formData = await request.formData();
    const thumb = formData.get('thumb');
    if (!thumb) return json({ error: '缺少缩略图文件' }, 400);

    await config.r2Bucket.put(`t/${id}`, thumb.stream(), {
      httpMetadata: { contentType: 'image/jpeg' },
    });

    return json({ ok: true });
  } catch (e) {
    console.error('缩略图上传错误:', e);
    return json({ error: e.message }, 500);
  }
}

// ─── Fallback Handler: Media Serving ─────────────────────────────────────────

async function serveMedia({ request, config, executionCtx }) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const cache = caches.default;
  const cacheKey = new Request(request.url);

  const cached = await cache.match(cacheKey);
  if (cached) {
    const etag = cached.headers.get('ETag');
    const lastModified = cached.headers.get('Last-Modified');
    if (shouldReturnNotModified(request, etag, lastModified)) {
      return buildNotModifiedResponse(cached.headers);
    }
    if (request.method === 'HEAD') {
      return new Response(null, { status: cached.status, headers: cached.headers });
    }
    return cached;
  }

  // Extract media info from URL path: /i/{id}.{ext} or /thumb/{id}.jpg
  const parsedMedia = parseMediaPathname(new URL(request.url).pathname);
  if (!parsedMedia) return new Response('File not found', { status: 404 });
  const { r2Key, extension, isThumb, originalId } = parsedMedia;

  if (!isThumb) {
    // Primary-key point-read — fastest possible D1 lookup
    const mediaRow = await config.database
      .prepare('SELECT id FROM media WHERE id = ?')
      .bind(originalId)
      .first();

    if (!mediaRow) {
      const resp = new Response('File not found', { status: 404 });
      await cache.put(cacheKey, resp.clone());
      return resp;
    }
  }

  const mediaObjectHead = await config.r2Bucket.head(r2Key);
  if (!mediaObjectHead) return new Response('File not found', { status: 404 });

  const etag = mediaObjectHead.httpEtag || `"${mediaObjectHead.etag}"`;
  const lastModified = mediaObjectHead.uploaded
    ? new Date(mediaObjectHead.uploaded).toUTCString()
    : undefined;
  const contentType = mediaObjectHead.httpMetadata?.contentType || CONTENT_TYPES[extension] || 'application/octet-stream';
  const contentLength = mediaObjectHead.size ?? null;
  const mediaHeaders = buildMediaHeaders({ etag, lastModified, contentType, contentLength });

  if (shouldReturnNotModified(request, etag, lastModified)) {
    return buildNotModifiedResponse(mediaHeaders);
  }

  if (request.method === 'HEAD') {
    return new Response(null, { status: 200, headers: mediaHeaders });
  }

  const mediaObject = await config.r2Bucket.get(r2Key);
  if (!mediaObject) return new Response('File not found', { status: 404 });

  const resp = new Response(mediaObject.body, { headers: mediaHeaders });
  // Non-blocking cache write — response is returned to the client immediately
  executionCtx?.waitUntil(cache.put(cacheKey, resp.clone()));
  return resp;
}

// ─── Route Table ──────────────────────────────────────────────────────────────
//
//  Route key = first path segment (up to but not including the second '/').
//  Flat paths like /api.upload have no second slash, so the key is the full slug.
//
//    /              → ''
//    /login         → 'login'
//    /i/abc.jpg     → 'i'
//    /t/abc.jpg     → 't'
//    /api.upload    → 'api.upload'
//    /css/main.css  → 'css'
//
//  Single O(1) table lookup dispatches every request — zero branching.
//
//  fn:     handler receiving { request, url, config, env, user }
//  method: restrict to a single HTTP method (omit = any)
//  auth:   'user' | 'admin' — session resolved once, injected into ctx
//  assets: true   — forward directly to env.ASSETS, no further processing
//

const ROUTES = {
  // ── Static assets (forwarded to Workers Assets, no config needed) ───────────
  'css':                { assets: true },
  'js':                 { assets: true },
  'fonts':              { assets: true },
  'images':             { assets: true },

  // ── Pages ──────────────────────────────────────────────────────────────────
  '':                   { fn: serveIndex },            // GET  /
  'login':              { fn: serveLogin },            // GET  /login

  // ── Media serving (handler enforces GET/HEAD internally) ───────────────────
  'i':                  { fn: serveMedia },            // GET  /i/{id}.{ext}
  't':                  { fn: serveMedia },            // GET  /t/{id}.jpg  (thumbnail)

  // ── API ────────────────────────────────────────────────────────────────────
  'api.login':          { fn: apiLogin,         method: 'POST' },
  'api.logout':         { fn: apiLogout,        method: 'POST' },
  'api.session':        { fn: apiSession },
  'api.media':          { fn: apiMedia,         auth: 'admin' },
  'api.upload':         { fn: apiUpload,        method: 'POST', auth: 'user' },
  'api.upload-thumb':   { fn: apiUploadThumb,   method: 'POST', auth: 'user' },
  'api.delete-images':  { fn: apiDelete,        method: 'POST', auth: 'admin' },
};

// ─── Entry Point ─────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, executionCtx) {
    const url = new URL(request.url);
    const { pathname } = url;

    // ① Derive route key — one indexOf + one substring, zero branching
    const seg1End = pathname.indexOf('/', 1);
    const routeKey = seg1End > 0 ? pathname.substring(1, seg1End) : pathname.substring(1);

    // ② Single O(1) table lookup — resolves every request type
    const route = ROUTES[routeKey];
    if (!route) return new Response('Not Found', { status: 404 });

    // ③ Static assets — no config, no auth, return immediately
    if (route.assets) return env.ASSETS.fetch(request);

    // ④ Method gate
    if (route.method && request.method !== route.method) {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // ⑤ Config — initialised once per isolate lifetime, reused on every request
    _config ??= buildConfig(env);
    const ctx = { request, url, config: _config, env, executionCtx, user: null };

    // ⑥ Auth middleware (resolved once, injected into ctx)
    if (route.auth) {
      const user = await getSessionUser(request, _config);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      if (route.auth === 'admin' && user.role !== 'admin') {
        return json({ error: 'Forbidden' }, 403);
      }
      ctx.user = user;
    }

    // ⑦ Dispatch
    return route.fn(ctx);
  },
};
