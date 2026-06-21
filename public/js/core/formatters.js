(function () {
  const getNameFromUrl = (url) => decodeURIComponent((url || '').split('/').pop() || 'file');

  const formatLinks = (items, format) => {
    const list = items.map(item => (typeof item === 'string' ? { url: item } : item));
    const formatters = {
      url: values => values.map(item => item.url).join('\n\n'),
      markdown: values => values.map(item => {
        const name = item.name || getNameFromUrl(item.url);
        return item.kind === 'image' ? `![${name}](${item.url})` : `[${name}](${item.url})`;
      }).join('\n\n'),
    };
    return formatters[format]?.(list) ?? list.map(item => item.url).join('\n');
  };

  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes) || bytes == null) return '-';
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const formatTime = (value, options = {}) => {
    if (!value) return '-';
    return new Date(value).toLocaleString('zh-CN', {
      timeZone: 'Asia/Shanghai',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      ...options,
    });
  };

  const fallbackId = () => `${Date.now()}-${Math.random().toString(16).slice(2)}`;

  window.LafuseFormatters = {
    fallbackId,
    formatBytes,
    formatLinks,
    formatTime,
  };
}());
