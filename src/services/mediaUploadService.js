import {
  findMediaBySha256,
  insertMedia,
  updateMediaCount,
} from '../db/mediaRepository.js';
import {
  buildMediaUrl,
  buildObjectKey,
  buildThumbKey,
  deleteMediaObjects,
  getMediaOrigin,
  putMediaObject,
} from '../storage/mediaStorage.js';
import { generateMediaId } from '../media.js';

const SHA256_RE = /^[a-f0-9]{64}$/i;
const UPLOAD_SOURCES = new Set(['web', 'api']);

export function sanitizeOriginalName(name) {
  const clean = String(name || 'unnamed')
    .split(/[\\/]/)
    .pop()
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
  return (clean || 'unnamed').slice(0, 180);
}

export function getExtensionFromName(name) {
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : 'bin';
  return /^[a-z0-9]{1,12}$/.test(ext) ? ext : 'bin';
}

export function shouldAcceptSha256(value, config) {
  return config.features.enableUploadDedupe && SHA256_RE.test(value || '');
}

export function isReusableShaMatch(row, file) {
  return row && Number(row.size) === file.size;
}

export function shouldStoreThumb(thumb, config) {
  return Boolean(
    config.features.enableThumbnails
    && thumb
    && typeof thumb === 'object'
    && typeof thumb.stream === 'function'
    && thumb.size > 0
  );
}

function isUploadFile(file) {
  return Boolean(
    file
    && typeof file === 'object'
    && typeof file.stream === 'function'
    && Number.isFinite(file.size)
  );
}

export function getUploadPayload(request, config, media, reused = false) {
  const origin = getMediaOrigin(request, config);
  return {
    id: media.id,
    originalName: media.original_name || media.originalName || `${media.id}.${media.ext}`,
    data: buildMediaUrl(origin, media.object_key || media.objectKey),
    thumbUrl: media.has_thumb || media.hasThumb
      ? buildMediaUrl(origin, media.thumb_key || media.thumbKey)
      : null,
    hasThumb: Boolean(media.has_thumb || media.hasThumb),
    uploadSource: media.upload_source || media.uploadSource || 'web',
    reused,
  };
}

function normalizeUploadSource(source) {
  return UPLOAD_SOURCES.has(source) ? source : 'web';
}

export async function uploadMedia({ request, config, user, file, thumb, rawSha256 = '', uploadSource = 'web' }) {
  if (!isUploadFile(file)) {
    const error = new Error('缺少文件');
    error.status = 400;
    throw error;
  }
  if (file.size > config.maxSize) {
    const limitMb = config.maxSize / 1048576;
    const error = new Error(`文件大小超过${limitMb}MB限制`);
    error.status = 413;
    throw error;
  }

  const sha256 = shouldAcceptSha256(rawSha256, config) ? rawSha256.toLowerCase() : null;
  if (sha256) {
    const existing = await findMediaBySha256(config.database, sha256);
    if (isReusableShaMatch(existing, file)) {
      return getUploadPayload(request, config, existing, true);
    }
  }

  const id = generateMediaId();
  const originalName = sanitizeOriginalName(file.name);
  const ext = getExtensionFromName(originalName);
  const objectKey = buildObjectKey(id, ext);
  const hasThumb = shouldStoreThumb(thumb, config);
  const thumbKey = hasThumb ? buildThumbKey(id) : null;
  const normalizedUploadSource = normalizeUploadSource(uploadSource);

  const putOps = [
    putMediaObject(config, objectKey, file.stream(), file.type),
  ];
  if (hasThumb) {
    putOps.push(putMediaObject(config, thumbKey, thumb.stream(), 'image/jpeg'));
  }
  try {
    await Promise.all(putOps);
  } catch (error) {
    await deleteMediaObjects(config, [objectKey, thumbKey]);
    throw error;
  }

  try {
    await insertMedia(config.database, {
      id,
      ext,
      size: file.size,
      userId: user.userId,
      username: user.username,
      originalName,
      objectKey,
      thumbKey,
      hasThumb,
      uploadSource: normalizedUploadSource,
      sha256,
    });
  } catch (error) {
    await deleteMediaObjects(config, [objectKey, thumbKey]);
    if (sha256) {
      const existing = await findMediaBySha256(config.database, sha256);
      if (isReusableShaMatch(existing, file)) {
        return getUploadPayload(request, config, existing, true);
      }
    }
    throw error;
  }

  if (config.features.enableTotalCount) {
    try {
      await updateMediaCount(config.database, 1);
    } catch (error) {
      console.warn('更新媒体总数失败:', error);
    }
  }

  return getUploadPayload(request, config, {
    id,
    ext,
    originalName,
    objectKey,
    thumbKey,
    hasThumb,
    uploadSource: normalizedUploadSource,
  });
}
