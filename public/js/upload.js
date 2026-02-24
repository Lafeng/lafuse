const formatLinks = (urls, format) => {
  const formatters = {
    url: list => list.join('\n\n'),
    bbcode: list => list.map(url => `[img]${url}[/img]`).join('\n\n'),
    markdown: list => list.map(url => `![image](${url})`).join('\n\n')
  };
  return formatters[format]?.(urls) ?? urls.join('\n');
};

const formatBytes = (bytes) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
};

const getExtension = (url) => url.split('.').pop().toLowerCase();
const COMPRESSION_PREF_KEY = 'lafuse:enableCompression';

const IMAGE_EXTS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'svg', 'avif', 'ico']);
const VIDEO_EXTS = new Set(['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm']);

const getMediaMeta = (item) => {
  const extension = getExtension(item.url);
  const stem = item.url.split('/').pop() ?? '';
  const id = stem.substring(0, stem.lastIndexOf('.'));
  const isImage = IMAGE_EXTS.has(extension);
  const isVideo = VIDEO_EXTS.has(extension);
  const kind = isVideo ? 'video' : isImage ? 'image' : 'file';
  const hasThumb = isImage || isVideo;
  // item.url is https://domain/i/{id}.{ext} — thumb lives at /t/{id}.jpg
  const origin = item.url.substring(0, item.url.indexOf('/i/'));
  const thumbUrl = hasThumb ? `${origin}/t/${id}.jpg` : null;
  return {
    extension,
    kind,
    hasThumb,
    thumbUrl,
    idLabel: stem,
    timeLabel: new Date(item.createdAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    userLabel: item.username
  };
};

/** Generate a JPEG thumbnail from an image File (max 400 px on longest side). */
const generateImageThumbnail = async (file) => {
  try {
    const bitmap = await createImageBitmap(file);
    const maxDim = 400;
    const scale = Math.min(maxDim / bitmap.width, maxDim / bitmap.height, 1);
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(bitmap.width * scale);
    canvas.height = Math.round(bitmap.height * scale);
    canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.82));
    return blob ? new File([blob], 'thumb.jpg', { type: 'image/jpeg' }) : null;
  } catch {
    return null;
  }
};

/** Generate a JPEG thumbnail by capturing the first useful frame of a video File. */
const generateVideoThumbnail = (file) => new Promise(resolve => {
  const video = document.createElement('video');
  const objectUrl = URL.createObjectURL(file);
  const cleanup = () => URL.revokeObjectURL(objectUrl);

  const capture = () => {
    try {
      const maxDim = 400;
      const w = video.videoWidth || 640;
      const h = video.videoHeight || 360;
      const scale = Math.min(maxDim / w, maxDim / h, 1);
      const canvas = document.createElement('canvas');
      canvas.width = Math.round(w * scale);
      canvas.height = Math.round(h * scale);
      canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
      canvas.toBlob(blob => {
        cleanup();
        resolve(blob ? new File([blob], 'thumb.jpg', { type: 'image/jpeg' }) : null);
      }, 'image/jpeg', 0.82);
    } catch { cleanup(); resolve(null); }
  };

  video.muted = true;
  video.playsInline = true;
  video.preload = 'metadata';
  video.addEventListener('error', () => { cleanup(); resolve(null); });
  video.addEventListener('loadedmetadata', () => {
    video.currentTime = Math.min(video.duration * 0.1, 1);
  });
  video.addEventListener('seeked', capture, { once: true });
  // Fall back: if seeked never fires, capture after loadeddata
  video.addEventListener('loadeddata', () => setTimeout(capture, 200), { once: true });
  video.src = objectUrl;
  video.load();
});

/** Upload a thumbnail blob to the server for a given file ID. */
const uploadThumb = async (fileId, thumbFile) => {
  const fd = new FormData();
  fd.append('thumb', thumbFile, 'thumb.jpg');
  await fetch(`/api.upload-thumb?id=${fileId}`, { method: 'POST', body: fd });
};

const uploadWithProgress = (url, formData, onProgress) => new Promise((resolve, reject) => {
  const xhr = new XMLHttpRequest();
  xhr.upload.addEventListener('progress', (event) => {
    if (event.lengthComputable) {
      onProgress(Math.round((event.loaded / event.total) * 100));
    }
  });
  xhr.onload = () => {
    if (xhr.status >= 200 && xhr.status < 300) {
      try {
        resolve(JSON.parse(xhr.responseText));
      } catch {
        reject(new Error('响应解析失败'));
      }
      return;
    }
    try {
      const data = JSON.parse(xhr.responseText);
      reject(new Error(data.error ?? `上传失败: HTTP ${xhr.status}`));
    } catch {
      reject(new Error(`上传失败: HTTP ${xhr.status}`));
    }
  };
  xhr.onerror = () => reject(new Error('网络错误，请检查网络连接'));
  xhr.ontimeout = () => reject(new Error('上传超时，请重试'));
  xhr.timeout = 120000;
  xhr.open('POST', url);
  xhr.send(formData);
});

const compressImage = async (file) => {
  const bitmap = await createImageBitmap(file);
  const maxWidth = 2560;
  const scale = Math.min(1, maxWidth / bitmap.width);
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.86));
  if (!blob) return file;
  const dotIndex = file.name.lastIndexOf('.');
  const baseName = dotIndex > 0 ? file.name.slice(0, dotIndex) : file.name;
  return new File([blob], `${baseName}.jpg`, { type: 'image/jpeg' });
};

document.addEventListener('alpine:init', () => {
  Alpine.data('uploadApp', () => ({
    // === Common state ===
    user: null,
    view: 'upload', // 'upload' | 'admin'
    toasts: [],

    // === Upload state ===
    uploads: [],
    dragActive: false,
    format: 'url',
    linkOutput: '',
    enableCompression: true,

    // === Admin state ===
    adminMedia: [],
    adminSelectedKeys: new Set(),
    adminCurrentPage: 1,
    adminTotalPages: 1,
    adminTotalCount: 0,
    adminLoading: false,
    adminDropdownOpen: false,

    get adminPageLabel() {
      return `第 ${this.adminCurrentPage} / ${this.adminTotalPages} 页 (共 ${this.adminTotalCount} 个)`;
    },

    async init() {
      this.enableCompression = this.readCompressionPreference();
      this.$watch('enableCompression', (value) => {
        this.writeCompressionPreference(value);
      });
      await this.loadSession();
      this.setupPasteListener();
    },
    readCompressionPreference() {
      const raw = localStorage.getItem(COMPRESSION_PREF_KEY);
      if (raw === null) return true;
      return raw === '1';
    },
    writeCompressionPreference(value) {
      localStorage.setItem(COMPRESSION_PREF_KEY, value ? '1' : '0');
    },
    async loadSession() {
      const response = await fetch('/api.session');
      const data = await response.json();
      if (!data?.user) {
        window.location.href = '/login';
        return;
      }
      this.user = data.user;
    },
    async logout() {
      await fetch('/api.logout', { method: 'POST' });
      window.location.href = '/login';
    },

    // === View toggle ===
    async toggleView() {
      if (this.user?.role !== 'admin') return;
      if (this.view === 'upload') {
        this.view = 'admin';
        if (this.adminMedia.length === 0) {
          await this.adminLoadMedia();
        }
      } else {
        this.view = 'upload';
      }
    },
    openFilePicker() {
      this.$refs.fileInput.click();
    },
    handleFiles(event) {
      const files = [...event.target.files];
      event.target.value = '';
      this.queueFiles(files);
    },
    handleDrop(event) {
      this.dragActive = false;
      this.queueFiles([...event.dataTransfer.files]);
    },
    setupPasteListener() {
      window.addEventListener('paste', (event) => {
        const items = [...event.clipboardData.items];
        const files = items
          .filter(item => item.kind === 'file')
          .map(item => item.getAsFile())
          .filter(Boolean);
        if (files.length) {
          this.queueFiles(files);
        }
      });
    },
    async queueFiles(files) {
      for (const file of files) {
        await this.uploadFile(file);
      }
    },
    async uploadFile(file) {
      const uploadIndex = this.uploads.length;
      this.uploads.unshift({
        id: crypto.randomUUID?.() ?? `${Date.now()}-${Math.random()}`,
        name: file.name,
        size: file.size,
        type: file.type,
        progress: 0,
        status: 'uploading',
        url: ''
      });

      let processedFile = file;
      if (this.enableCompression && file.type.startsWith('image/') && file.type !== 'image/gif') {
        processedFile = await compressImage(file);
      }

      try {
        const formData = new FormData();
        formData.append('file', processedFile, processedFile.name);
        const responseData = await uploadWithProgress('/api.upload', formData, (progress) => {
          // Use index-based update to ensure Alpine reactivity
          this.uploads[0].progress = progress;
        });
        if (responseData.error) throw new Error(responseData.error);
        this.uploads[0].status = 'done';
        this.uploads[0].progress = 100;
        this.uploads[0].url = responseData.data;
        this.updateLinks();
        this.toast('上传成功', 'success');

        // Generate and upload thumbnail for images and videos (best-effort, non-blocking)
        const ext = getExtension(responseData.data);
        if (IMAGE_EXTS.has(ext) || VIDEO_EXTS.has(ext)) {
          (async () => {
            try {
              const stem = responseData.data.split('/').pop();
              const fileId = stem.substring(0, stem.lastIndexOf('.'));
              const thumbFile = IMAGE_EXTS.has(ext)
                ? await generateImageThumbnail(processedFile)
                : await generateVideoThumbnail(file); // use original for video
              if (thumbFile) await uploadThumb(fileId, thumbFile);
            } catch (e) {
              console.warn('缩略图生成失败，已跳过:', e);
            }
          })();
        }
      } catch (error) {
        this.uploads[0].status = 'error';
        this.toast(error?.message ?? '上传失败', 'error');
      }
    },
    statusText(item) {
      if (item.status === 'done') return '上传完成';
      if (item.status === 'error') return '上传失败';
      return `上传中 ${item.progress}%`;
    },
    updateLinks() {
      const urls = this.uploads.filter(item => item.url).map(item => item.url);
      this.linkOutput = formatLinks(urls, this.format);
    },
    setFormat(format) {
      this.format = format;
      this.updateLinks();
    },
    async copyLinks() {
      if (!this.linkOutput) return;
      try {
        await navigator.clipboard.writeText(this.linkOutput);
        this.toast('已复制到剪贴板', 'success');
      } catch {
        this.toast('复制失败', 'error');
      }
    },
    toast(message, tone) {
      const id = crypto.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
      this.toasts.push({ id, message, tone });
      setTimeout(() => {
        this.toasts = this.toasts.filter(toast => toast.id !== id);
      }, 2600);
    },
    formatBytes,

    // === Admin methods ===
    async adminLoadMedia() {
      this.adminLoading = true;
      try {
        const response = await fetch(`/api.media?page=${this.adminCurrentPage}`);
        if (!response.ok) throw new Error('加载失败');
        const data = await response.json();
        this.adminTotalCount = data.totalCount;
        this.adminTotalPages = data.totalPages;
        this.adminMedia = (data.media ?? []).map(item => ({
          ...item,
          ...getMediaMeta(item)
        }));
        this.adminSelectedKeys.clear();
        this.$nextTick(() => this.adminInitLazyLoad());
      } catch (error) {
        console.error('加载媒体数据失败:', error);
        this.toast('加载媒体数据失败', 'error');
      } finally {
        this.adminLoading = false;
      }
    },
    adminToggleSelection(item) {
      if (this.adminSelectedKeys.has(item.url)) {
        this.adminSelectedKeys.delete(item.url);
      } else {
        this.adminSelectedKeys.add(item.url);
      }
    },
    adminToggleSelectAll() {
      if (this.adminSelectedKeys.size === this.adminMedia.length) {
        this.adminSelectedKeys.clear();
      } else {
        this.adminMedia.forEach(item => this.adminSelectedKeys.add(item.url));
      }
    },
    async adminDeleteSelected() {
      if (this.adminSelectedKeys.size === 0) return;
      if (!confirm('确定要删除选中的媒体文件吗？此操作无法撤回。')) return;
      try {
        const response = await fetch('/api.delete-images', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify([...this.adminSelectedKeys])
        });
        if (!response.ok) throw new Error('删除失败');
        this.adminMedia = this.adminMedia.filter(item => !this.adminSelectedKeys.has(item.url));
        this.adminTotalCount -= this.adminSelectedKeys.size;
        this.adminSelectedKeys.clear();
        this.toast('删除成功', 'success');
        if (this.adminMedia.length === 0 && this.adminCurrentPage > 1) {
          this.adminCurrentPage -= 1;
          await this.adminLoadMedia();
        }
      } catch (error) {
        this.toast(error?.message ?? '删除失败，请重试', 'error');
      }
    },
    async adminCopyLinks(fmt) {
      const urls = [...this.adminSelectedKeys];
      if (urls.length === 0) return;
      try {
        await navigator.clipboard.writeText(formatLinks(urls, fmt));
        this.toast('已复制到剪贴板', 'success');
      } catch {
        this.toast('复制失败', 'error');
      }
    },
    async adminGoToPage(page) {
      if (page < 1 || page > this.adminTotalPages) return;
      this.adminCurrentPage = page;
      await this.adminLoadMedia();
    },
    adminInitLazyLoad() {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          const container = entry.target;
          const skeleton = container.querySelector('.skeleton');
          const img = container.querySelector('img[data-src]');
          if (img) {
            img.src = img.dataset.src;
            img.onload = () => { img.classList.add('loaded'); skeleton?.classList.add('hidden'); };
            img.onerror = () => { img.classList.add('loaded'); skeleton?.classList.add('hidden'); };
          } else {
            skeleton?.classList.add('hidden');
          }
          observer.unobserve(container);
        });
      }, { threshold: 0.1 });
      this.$root.querySelectorAll('.media-preview').forEach(el => observer.observe(el));
    }
  }));
});
