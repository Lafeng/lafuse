import {
  buildNotModifiedResponse,
  shouldReturnNotModified,
} from './http.js';
import {
  CACHE_TTL,
  getContentDisposition,
  getContentType,
} from './mediaMetadata.js';

export function generateMediaId() {
  const r = crypto.getRandomValues(new Uint8Array(4));
  return Date.now().toString(36)
    + Array.from(r, b => b.toString(36).padStart(2, '0')).join('');
}

export function extractTimestampFromId(id) {
  return parseInt(id.slice(0, -8), 36);
}

export function parseMediaPathname(pathname) {
  const slash2 = pathname.indexOf('/', 1);
  if (slash2 < 0) return null;
  const prefix = pathname.substring(1, slash2);
  if (prefix !== 'i' && prefix !== 't') return null;

  const fileName = pathname.substring(slash2 + 1);
  const dotIdx = fileName.lastIndexOf('.');
  if (dotIdx < 1) return null;

  const originalId = fileName.substring(0, dotIdx);
  const extension = fileName.substring(dotIdx + 1).toLowerCase();
  const isThumb = prefix === 't';
  const r2Key = `${prefix}/${fileName}`;

  return { r2Key, extension, isThumb, originalId };
}

export function buildMediaHeaders({ etag, lastModified, contentType, contentLength, extension }) {
  const headers = new Headers({
    'Content-Type': contentType,
    'Content-Disposition': getContentDisposition(extension),
    ETag: etag,
    'Cache-Control': `public, max-age=${CACHE_TTL.MEDIA}, immutable`,
    'CDN-Cache-Control': `public, max-age=${CACHE_TTL.MEDIA}, immutable`,
    'X-Content-Type-Options': 'nosniff',
  });

  if (lastModified) headers.set('Last-Modified', lastModified);
  if (contentLength != null) headers.set('Content-Length', String(contentLength));
  return headers;
}

function buildNotFoundResponse() {
  return new Response('File not found', {
    status: 404,
    headers: {
      'Cache-Control': `public, max-age=${CACHE_TTL.NOT_FOUND}`,
      'CDN-Cache-Control': `public, max-age=${CACHE_TTL.NOT_FOUND}`,
    },
  });
}

export async function serveMedia({ request, config, executionCtx }) {
  if (!config.allowWorkerMediaProxy) {
    return new Response('Worker media proxy is disabled', {
      status: 410,
      headers: { 'Cache-Control': `public, max-age=${CACHE_TTL.NOT_FOUND}` },
    });
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const cache = caches.default;
  const cacheUrl = new URL(request.url);
  cacheUrl.search = '';
  const cacheKey = new Request(cacheUrl.toString(), { method: request.method });

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

  const parsedMedia = parseMediaPathname(new URL(request.url).pathname);
  if (!parsedMedia) return buildNotFoundResponse();
  const { r2Key, extension } = parsedMedia;

  if (request.method === 'HEAD') {
    const mediaObjectHead = await config.r2Bucket.head(r2Key);
    if (!mediaObjectHead) return buildNotFoundResponse();

    const etag = mediaObjectHead.httpEtag || `"${mediaObjectHead.etag}"`;
    const lastModified = mediaObjectHead.uploaded
      ? new Date(mediaObjectHead.uploaded).toUTCString()
      : undefined;
    const contentType = mediaObjectHead.httpMetadata?.contentType || getContentType(extension);
    const contentLength = mediaObjectHead.size ?? null;
    const mediaHeaders = buildMediaHeaders({ etag, lastModified, contentType, contentLength, extension });

    if (shouldReturnNotModified(request, etag, lastModified)) {
      return buildNotModifiedResponse(mediaHeaders);
    }

    return new Response(null, { status: 200, headers: mediaHeaders });
  }

  const mediaObject = await config.r2Bucket.get(r2Key);
  if (!mediaObject) {
    const resp = buildNotFoundResponse();
    executionCtx?.waitUntil(cache.put(cacheKey, resp.clone()));
    return resp;
  }

  const etag = mediaObject.httpEtag || `"${mediaObject.etag}"`;
  const lastModified = mediaObject.uploaded
    ? new Date(mediaObject.uploaded).toUTCString()
    : undefined;
  const contentType = mediaObject.httpMetadata?.contentType || getContentType(extension);
  const contentLength = mediaObject.size ?? null;
  const mediaHeaders = buildMediaHeaders({ etag, lastModified, contentType, contentLength, extension });

  if (shouldReturnNotModified(request, etag, lastModified)) {
    return buildNotModifiedResponse(mediaHeaders);
  }

  const resp = new Response(mediaObject.body, { headers: mediaHeaders });
  executionCtx?.waitUntil(cache.put(cacheKey, resp.clone()));
  return resp;
}
