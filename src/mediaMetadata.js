export const CONTENT_TYPES = {
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
  gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
  svg: 'image/svg+xml', ico: 'image/x-icon', tiff: 'image/tiff', avif: 'image/avif',
  mp4: 'video/mp4', avi: 'video/x-msvideo', mov: 'video/quicktime',
  webm: 'video/webm', mkv: 'video/x-matroska', flv: 'video/x-flv', wmv: 'video/x-ms-wmv',
  mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac', aac: 'audio/aac',
  pdf: 'application/pdf',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  zip: 'application/zip', gz: 'application/gzip', tar: 'application/x-tar',
  '7z': 'application/x-7z-compressed', rar: 'application/x-rar-compressed',
  txt: 'text/plain', csv: 'text/csv', json: 'application/json',
  xml: 'application/xml', html: 'text/html', css: 'text/css', js: 'application/javascript',
};

export const CACHE_TTL = { MEDIA: 31536000, NOT_FOUND: 60 };

const INLINE_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'tiff', 'avif',
  'mp4', 'mov', 'webm', 'mp3', 'wav', 'ogg', 'pdf', 'txt',
]);

export function getContentType(extension, fallback = 'application/octet-stream') {
  return CONTENT_TYPES[extension] || fallback;
}

export function getContentDisposition(extension) {
  return INLINE_EXTENSIONS.has(extension) ? 'inline' : 'attachment';
}

export function getExtensionFromKey(key) {
  const dotIndex = key.lastIndexOf('.');
  return dotIndex >= 0 ? key.slice(dotIndex + 1).toLowerCase() : '';
}

export function getObjectHttpMetadata(key, contentType) {
  const extension = getExtensionFromKey(key);
  return {
    contentType: contentType || getContentType(extension),
    contentDisposition: getContentDisposition(extension),
    cacheControl: `public, max-age=${CACHE_TTL.MEDIA}, immutable`,
  };
}
