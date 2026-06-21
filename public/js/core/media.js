(function () {
  const IMAGE_EXTS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'svg', 'avif', 'ico']);
  const VIDEO_EXTS = new Set(['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm']);
  const DOCUMENT_EXTS = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'json', 'xml', 'html']);
  const ARCHIVE_EXTS = new Set(['zip', 'gz', 'tar', 'tgz', '7z', 'rar']);
  const COMPRESSIBLE_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/bmp']);

  const KIND_LABELS = {
    image: '图片',
    video: '视频',
    document: '文档',
    archive: '压缩包',
    file: '文件',
  };

  const getExtensionFromName = (name = '') => {
    const clean = name.split('?')[0].split('#')[0];
    const dot = clean.lastIndexOf('.');
    return dot >= 0 ? clean.slice(dot + 1).toLowerCase() : 'file';
  };

  const getExtension = (url) => getExtensionFromName(url.split('/').pop() ?? '');

  const getKind = (extension) => {
    if (IMAGE_EXTS.has(extension)) return 'image';
    if (VIDEO_EXTS.has(extension)) return 'video';
    if (DOCUMENT_EXTS.has(extension)) return 'document';
    if (ARCHIVE_EXTS.has(extension)) return 'archive';
    return 'file';
  };

  const shouldCompressImage = (file) => {
    const ext = getExtensionFromName(file.name);
    if (ext === 'gif' || ext === 'svg') return false;
    return COMPRESSIBLE_IMAGE_TYPES.has(file.type) || ['jpg', 'jpeg', 'png', 'webp', 'bmp'].includes(ext);
  };

  const createLocalPreview = (file) => {
    const extension = getExtensionFromName(file.name);
    if (!IMAGE_EXTS.has(extension) && !file.type.startsWith('image/')) return '';
    return URL.createObjectURL(file);
  };

  const getMediaMeta = (item) => {
    const { formatBytes, formatTime } = window.LafuseFormatters;
    const extension = item.extension || getExtension(item.url);
    const stem = item.url.split('/').pop() ?? '';
    const dot = stem.lastIndexOf('.');
    const id = item.id || (dot > 0 ? stem.substring(0, dot) : stem);
    const kind = getKind(extension);
    const hasThumb = Boolean(item.hasThumb && item.thumbUrl);
    const displayName = item.originalName || item.name || stem;
    const previewSrc = hasThumb ? item.thumbUrl : (kind === 'image' ? item.url : null);

    return {
      extension,
      kind,
      kindLabel: KIND_LABELS[kind],
      hasThumb,
      thumbUrl: hasThumb ? item.thumbUrl : null,
      previewSrc,
      detailSrc: kind === 'image' ? item.url : null,
      id,
      displayName,
      idLabel: stem,
      sizeLabel: item.size != null ? formatBytes(item.size) : null,
      timeLabel: formatTime(item.createdAt),
      fullTimeLabel: formatTime(item.createdAt, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      userLabel: item.username,
    };
  };

  window.LafuseMedia = {
    createLocalPreview,
    getExtension,
    getExtensionFromName,
    getKind,
    getMediaMeta,
    shouldCompressImage,
  };
}());
