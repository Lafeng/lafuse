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

const toJpgFileName = (name) => {
  const dotIndex = name.lastIndexOf('.');
  const baseName = dotIndex > 0 ? name.slice(0, dotIndex) : name;
  return `${baseName}.jpg`;
};

const getMediaMeta = (item) => {
  const extension = getExtension(item.url);
  const stem = item.url.split('/').pop() ?? '';
  const imageExt = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'svg', 'avif'];
  const videoExt = ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'];
  const isImage = imageExt.includes(extension);
  const isVideo = videoExt.includes(extension);
  const kind = isVideo ? 'video' : isImage ? 'image' : 'file';
  return {
    extension,
    kind,
    idLabel: stem,
    timeLabel: new Date(item.createdAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    userLabel: item.username
  };
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
  return new File([blob], toJpgFileName(file.name), {
    type: 'image/jpeg'
  });
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
      const response = await fetch('/api/session');
      const data = await response.json();
      if (!data?.user) {
        window.location.href = '/login';
        return;
      }
      this.user = data.user;
    },
    async logout() {
      await fetch('/api/logout', { method: 'POST' });
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
        const responseData = await uploadWithProgress('/upload', formData, (progress) => {
          // Use index-based update to ensure Alpine reactivity
          this.uploads[0].progress = progress;
        });
        if (responseData.error) throw new Error(responseData.error);
        this.uploads[0].status = 'done';
        this.uploads[0].progress = 100;
        this.uploads[0].url = responseData.data;
        this.updateLinks();
        this.toast('上传成功', 'success');
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
        const response = await fetch(`/api/media?page=${this.adminCurrentPage}`);
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
        const response = await fetch('/delete-images', {
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
          const video = container.querySelector('video');
          const img = container.querySelector('img');
          if (video?.dataset.src) {
            video.src = video.dataset.src;
            video.onloadeddata = () => {
              video.classList.add('loaded');
              skeleton?.classList.add('hidden');
            };
          } else if (img?.dataset.src) {
            img.src = img.dataset.src;
            img.onload = () => {
              img.classList.add('loaded');
              skeleton?.classList.add('hidden');
            };
          } else {
            skeleton?.classList.add('hidden');
          }
          observer.unobserve(container);
        });
      }, { threshold: 0.2 });
      this.$root.querySelectorAll('.media-card').forEach(card => observer.observe(card));
    }
  }));
});
