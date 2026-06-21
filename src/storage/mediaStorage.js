import { getPublicOrigin } from '../http.js';
import { getObjectHttpMetadata } from '../mediaMetadata.js';

export function getMediaOrigin(request, config) {
  return config.mediaPublicOrigin || getPublicOrigin(request, config);
}

export function buildObjectKey(id, ext) {
  return `i/${id}.${ext}`;
}

export function buildThumbKey(id) {
  return `t/${id}.jpg`;
}

export function buildMediaUrl(origin, key) {
  return `${origin}/${key}`;
}

export function getMediaPublicUrl(request, config, key) {
  return buildMediaUrl(getMediaOrigin(request, config), key);
}

export async function putMediaObject(config, key, body, contentType) {
  return config.r2Bucket.put(key, body, {
    httpMetadata: getObjectHttpMetadata(key, contentType),
  });
}

export async function deleteMediaObjects(config, keys) {
  const uniqueKeys = [...new Set(keys.filter(Boolean))];
  if (!uniqueKeys.length) return;
  await Promise.all(uniqueKeys.map(key => config.r2Bucket.delete(key)));
}
