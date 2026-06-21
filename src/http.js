export function json(data, status = 200, extraHeaders) {
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

export function shouldReturnNotModified(request, etag, lastModified) {
  const ifNoneMatch = request.headers.get('If-None-Match');
  if (ifNoneMatch) return matchesIfNoneMatch(ifNoneMatch, etag);

  const ifModifiedSince = request.headers.get('If-Modified-Since');
  if (!ifModifiedSince || !lastModified) return false;

  const since = parseHttpDate(ifModifiedSince);
  const modifiedAt = parseHttpDate(lastModified);
  if (since === null || modifiedAt === null) return false;
  return modifiedAt <= since;
}

export function buildNotModifiedResponse(headersSource) {
  const headers = new Headers();
  for (const key of ['ETag', 'Last-Modified', 'Cache-Control', 'CDN-Cache-Control', 'Vary', 'Expires']) {
    const value = headersSource.get(key);
    if (value) headers.set(key, value);
  }
  return new Response(null, { status: 304, headers });
}

export function getPublicOrigin(request, config) {
  const current = new URL(request.url);
  if (current.hostname === 'localhost' || current.hostname === '127.0.0.1') {
    return current.origin;
  }
  if (/^https?:\/\//i.test(config.domain)) return config.domain.replace(/\/+$/, '');
  return `https://${config.domain}`;
}
