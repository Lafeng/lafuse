import {
  findMediaBySha256,
  findMediaForDelete,
  listMedia,
  listUploaders,
  deleteMediaRows,
  updateMediaCount,
} from '../db/mediaRepository.js';
import { json } from '../http.js';
import {
  buildMediaUrl,
  deleteMediaObjects,
  getMediaOrigin,
} from '../storage/mediaStorage.js';
import { extractTimestampFromId } from '../media.js';
import { uploadMedia } from '../services/mediaUploadService.js';

const MEDIA_LIST_CACHE_TTL = 10_000;
const MEDIA_LIST_CACHE_MAX = 100;
const UPLOADERS_CACHE_TTL = 300_000;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const MAX_SEARCH_LENGTH = 80;

const mediaListCache = new Map();
let uploadersCache;

function getMediaListCacheKey(request, config, params) {
  return [
    getMediaOrigin(request, config),
    params.cursor || '',
    params.query || '',
    params.uploader || '',
    params.kind || '',
    config.features.enableTotalCount ? 'count' : 'no-count',
    config.features.searchMode,
  ].join(':');
}

export function clearMediaListCache() {
  mediaListCache.clear();
  uploadersCache = null;
}

function setMediaListCache(key, payload) {
  if (mediaListCache.size >= MEDIA_LIST_CACHE_MAX) {
    mediaListCache.delete(mediaListCache.keys().next().value);
  }
  mediaListCache.set(key, {
    expiresAt: Date.now() + MEDIA_LIST_CACHE_TTL,
    payload,
  });
}

function normalizeSearch(value) {
  return (value || '').trim().toLowerCase().slice(0, MAX_SEARCH_LENGTH);
}

function getListParams(url, features) {
  const kind = url.searchParams.get('kind') || 'all';
  const query = normalizeSearch(url.searchParams.get('q') || url.searchParams.get('search') || '');
  return {
    cursor: url.searchParams.get('cursor') || '',
    query: query.length >= features.searchMinLength ? query : '',
    uploader: normalizeSearch(url.searchParams.get('uploader') || ''),
    kind: kind === 'all' ? '' : kind,
  };
}

function getMediaResponse(row, origin) {
  const hasThumb = Boolean(row.has_thumb);
  return {
    id: row.id,
    originalName: row.original_name || `${row.id}.${row.ext}`,
    url: buildMediaUrl(origin, row.object_key),
    thumbUrl: hasThumb ? buildMediaUrl(origin, row.thumb_key) : null,
    hasThumb,
    createdAt: extractTimestampFromId(row.id),
    size: row.size ?? null,
    userId: row.user_id,
    username: row.username,
    uploadSource: row.upload_source,
  };
}

export async function apiMedia({ request, config, url }) {
  const params = getListParams(url, config.features);
  const cacheKey = getMediaListCacheKey(request, config, params);
  const cached = mediaListCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return json(cached.payload);
  }

  const origin = getMediaOrigin(request, config);
  const result = await listMedia(config.database, params, config.features);
  const payload = {
    media: result.rows.map(row => getMediaResponse(row, origin)),
    totalCount: result.totalCount,
    hasMore: result.hasMore,
    nextCursor: result.nextCursor,
  };
  setMediaListCache(cacheKey, payload);
  return json(payload);
}

export async function apiUpload({ request, config, user }) {
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    const rawSha256 = formData.get('sha256') || '';
    const thumb = formData.get('thumb');
    const payload = await uploadMedia({ request, config, user, file, thumb, rawSha256, uploadSource: 'web' });
    clearMediaListCache();
    return json(payload);
  } catch (e) {
    console.error('R2 上传错误:', e);
    return json({ error: e.message }, e.status || 500);
  }
}

export async function apiExists({ request, config, url }) {
  if (!config.features.enableUploadDedupe) return json({ exists: false });
  const sha256 = url.searchParams.get('sha256');
  if (!sha256 || !SHA256_RE.test(sha256)) return json({ exists: false });
  const size = Number(url.searchParams.get('size'));

  const row = await findMediaBySha256(config.database, sha256.toLowerCase());
  if (!row) return json({ exists: false });
  if (Number.isFinite(size) && Number(row.size) !== size) return json({ exists: false });

  const origin = getMediaOrigin(request, config);
  const hasThumb = Boolean(row.has_thumb);
  return json({
    exists: true,
    media: {
      id: row.id,
      originalName: row.original_name || `${row.id}.${row.ext}`,
      url: buildMediaUrl(origin, row.object_key),
      thumbUrl: hasThumb ? buildMediaUrl(origin, row.thumb_key) : null,
      hasThumb,
      uploadSource: row.upload_source,
    },
  });
}

export async function apiUploaders({ config }) {
  if (uploadersCache && uploadersCache.expiresAt > Date.now()) {
    return json(uploadersCache.payload);
  }

  const payload = {
    uploaders: await listUploaders(config.database),
  };
  uploadersCache = {
    expiresAt: Date.now() + UPLOADERS_CACHE_TTL,
    payload,
  };
  return json(payload);
}

async function deleteMediaByIds({ ids, config }) {
  const uniqueIds = [...new Set(ids.filter(Boolean))];
  if (!uniqueIds.length) {
    return json({ message: '没有要删除的项' }, 400);
  }

  const media = await findMediaForDelete(config.database, uniqueIds);
  if (!media.length) return json({ message: '未找到要删除的项' }, 404);

  await deleteMediaObjects(
    config,
    media.flatMap(item => [item.object_key, item.has_thumb ? item.thumb_key : null]),
  );

  const dbResult = await deleteMediaRows(config.database, uniqueIds);
  const deletedCount = dbResult.changes ?? dbResult.meta?.changes ?? media.length;
  if (config.features.enableTotalCount) {
    await updateMediaCount(config.database, -deletedCount);
  }
  clearMediaListCache();

  return deletedCount === 0
    ? json({ message: '未找到要删除的项' }, 404)
    : json({ message: '删除成功', deletedIds: media.map(item => item.id) });
}

export async function apiDeleteMedia({ request, config }) {
  try {
    const payload = await request.json();
    const ids = Array.isArray(payload) ? payload : payload?.ids;
    if (!Array.isArray(ids) || ids.length === 0) {
      return json({ message: '没有要删除的项' }, 400);
    }

    return deleteMediaByIds({ ids, config });
  } catch (e) {
    return json({ error: '删除失败', details: e.message }, 500);
  }
}
