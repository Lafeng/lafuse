const {
  COMPRESSION_PREF_KEY,
  MAX_PARALLEL_UPLOADS,
} = window.LafuseConfig;
const {
  fallbackId,
  formatBytes,
  formatLinks,
} = window.LafuseFormatters;
const {
  createLocalPreview,
  getExtension,
  getExtensionFromName,
  getKind,
  getMediaMeta,
  shouldCompressImage,
} = window.LafuseMedia;
const { copyToClipboard } = window.LafuseClipboard;
const {
  compressImage,
  generateImageThumbnail,
  generateVideoThumbnail,
} = window.LafuseImageTools;
const {
  findExistingUpload,
  getFileHash,
  uploadWithProgress,
} = window.LafuseUploadTransport;

document.addEventListener('alpine:init', () => {
  Alpine.data('uploadApp', () => ({
    user: null,
    view: 'upload',
    toasts: [],

    uploads: [],
    activeUploadCount: 0,
    dragActive: false,
    enableCompression: true,
    MAX_PARALLEL_UPLOADS,

    adminMedia: [],
    adminSelectedIds: new Set(),
    adminCurrentPage: 1,
    adminCursorStack: [''],
    adminNextCursor: null,
    adminHasMore: false,
    adminLoadedCursor: null,
    adminLoadedFilterKey: '',
    adminLoadPromise: null,
    adminTotalCount: null,
    adminLoading: false,
    adminSearch: '',
    adminKind: 'all',
    adminUploader: 'all',
    adminSort: 'newest',
    adminActiveAsset: null,
    adminUploaderList: [],
    adminFilterTimer: null,

    get uploadStats() {
      const activeStates = new Set(['queued', 'compressing', 'thumbnailing', 'hashing', 'uploading']);
      return this.uploads.reduce((stats, item) => {
        if (item.status === 'done') stats.done += 1;
        if (item.status === 'error') stats.error += 1;
        if (activeStates.has(item.status)) stats.active += 1;
        return stats;
      }, { done: 0, error: 0, active: 0 });
    },

    get successfulUploads() {
      return this.uploads.filter(item => item.status === 'done' && item.url);
    },

    get adminPageLabel() {
      return `第 ${this.adminCurrentPage} 页`;
    },

    get adminTotalLabel() {
      return this.adminTotalCount == null ? '-' : this.adminTotalCount;
    },

    get selectedAdminMedia() {
      return this.adminMedia.filter(item => this.adminSelectedIds.has(item.id));
    },

    get adminUploaderOptions() {
      const uploaders = new Set(this.adminUploaderList);
      this.adminMedia.forEach(item => {
        const value = item.userLabel || item.username;
        if (value) uploaders.add(value);
      });
      return [...uploaders].sort((a, b) => a.localeCompare(b));
    },

    get visibleAdminMedia() {
      let list = [...this.adminMedia];
      const sorters = {
        newest: (a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0),
        oldest: (a, b) => (a.createdAt ?? 0) - (b.createdAt ?? 0),
        largest: (a, b) => (b.size ?? 0) - (a.size ?? 0),
        smallest: (a, b) => (a.size ?? 0) - (b.size ?? 0),
      };
      return list.sort(sorters[this.adminSort] ?? sorters.newest);
    },

    async init() {
      this.enableCompression = this.readCompressionPreference();
      this.$watch('enableCompression', value => this.writeCompressionPreference(value));
      this.$watch('adminSearch', () => this.adminReloadForFilters());
      this.$watch('adminKind', () => this.adminReloadForFilters());
      this.$watch('adminUploader', () => this.adminReloadForFilters());
      await this.loadSession();
      this.setupPasteListener();
      window.addEventListener('popstate', () => this.onHashChange());
    },

    readCompressionPreference() {
      const raw = localStorage.getItem(COMPRESSION_PREF_KEY);
      return raw === null ? true : raw === '1';
    },

    writeCompressionPreference(value) {
      localStorage.setItem(COMPRESSION_PREF_KEY, value ? '1' : '0');
    },

    async loadSession() {
      const response = await fetch('/api.session');
      const data = await response.json();
      if (data?.features) {
        window.LafuseConfig.features = {
          ...window.LafuseConfig.features,
          ...data.features,
        };
      }
      if (!data?.user) {
        window.location.href = '/login';
        return;
      }
      this.user = data.user;
      const hash = location.hash.slice(1);
      if (hash === 'admin' && this.user.role === 'admin') {
        await this.setView('admin');
      }
    },

    async logout() {
      await fetch('/api.logout', { method: 'POST' });
      window.location.href = '/login';
    },

    async setViewWithHistory(view) {
      const next = view === 'admin' && this.user?.role === 'admin' ? 'admin' : 'upload';
      history.pushState({ view: next }, '', `#${next}`);
      await this.setView(next);
    },

    async onHashChange() {
      await this.setView(location.hash.slice(1) || 'upload');
    },

    async setView(view) {
      if (view === 'admin' && this.user?.role === 'admin') {
        this.view = 'admin';
        if (!this.adminUploaderList.length) await this.adminLoadUploaders();
        if (!this.adminMedia.length) await this.adminLoadMedia();
        return;
      }
      this.view = 'upload';
    },

    openFilePicker() {
      this.$refs.fileInput.click();
    },

    handleFiles(event) {
      this.queueFiles([...event.target.files]);
      event.target.value = '';
    },

    handleDrop(event) {
      this.dragActive = false;
      const files = [...(event.dataTransfer?.files ?? [])];
      if (files.length) this.queueFiles(files);
    },

    handleDragLeave(event) {
      if (event.clientX <= 0 || event.clientY <= 0 || event.clientX >= window.innerWidth || event.clientY >= window.innerHeight) {
        this.dragActive = false;
      }
    },

    setupPasteListener() {
      window.addEventListener('paste', (event) => {
        const files = [...(event.clipboardData?.items ?? [])]
          .filter(item => item.kind === 'file')
          .map(item => item.getAsFile())
          .filter(Boolean);
        if (files.length) this.queueFiles(files);
      });
    },

    queueFiles(files) {
      const items = files.map(file => ({
        id: crypto.randomUUID?.() ?? fallbackId(),
        file,
        name: file.name || '未命名文件',
        extension: getExtensionFromName(file.name),
        size: file.size,
        processedSize: null,
        type: file.type,
        previewSrc: createLocalPreview(file),
        progress: 0,
        status: 'queued',
        error: '',
        url: '',
      }));

      if (!items.length) return;
      this.uploads = [...items, ...this.uploads];
      this.processUploadQueue();
    },

    processUploadQueue() {
      while (this.activeUploadCount < MAX_PARALLEL_UPLOADS) {
        const next = this.uploads.find(item => item.status === 'queued');
        if (!next) return;
        this.activeUploadCount += 1;
        this.runUpload(next)
          .catch(error => {
            next.status = 'error';
            next.error = error?.message ?? '上传失败';
            this.toast(next.error, 'error');
          })
          .finally(() => {
            this.activeUploadCount = Math.max(0, this.activeUploadCount - 1);
            this.processUploadQueue();
          });
      }
    },

    async runUpload(item) {
      item.error = '';
      item.progress = 2;
      let processedFile = item.file;

      if (this.enableCompression && shouldCompressImage(item.file)) {
        item.status = 'compressing';
        processedFile = await compressImage(item.file);
        item.processedSize = processedFile.size;
        item.extension = getExtensionFromName(processedFile.name);
      }

      const features = window.LafuseConfig.features;
      const shouldHash = features.uploadDedupe && processedFile.size <= features.hashMaxBytes;
      let sha256 = '';
      if (shouldHash) {
        item.status = 'hashing';
        item.progress = Math.max(item.progress, 6);
        sha256 = await getFileHash(processedFile);
      }
      if (sha256) {
        const existing = await findExistingUpload(sha256, processedFile.size);
        if (existing) {
          item.status = 'done';
          item.progress = 100;
          item.url = existing.url;
          item.mediaId = existing.id;
          item.extension = getExtension(existing.url);
          item.processedSize = processedFile.size;
          this.toast('已复用已有资源', 'success');
          return;
        }
      }

      if (features.thumbnails) {
        item.status = 'thumbnailing';
        item.progress = Math.max(item.progress, 7);
      }
      const thumbFile = await this.createUploadThumbnail(processedFile, item.file);

      item.status = 'uploading';
      item.progress = Math.max(item.progress, 8);
      const formData = new FormData();
      formData.append('file', processedFile, processedFile.name);
      if (sha256) formData.append('sha256', sha256);
      if (thumbFile) formData.append('thumb', thumbFile, 'thumb.jpg');

      const responseData = await uploadWithProgress('/api.upload', formData, progress => {
        item.progress = Math.max(item.progress, progress);
      });
      if (responseData.error) throw new Error(responseData.error);

      item.status = 'done';
      item.progress = 100;
      item.url = responseData.data;
      item.mediaId = responseData.id;
      item.extension = getExtension(responseData.data);
      item.processedSize = processedFile.size;
      if (responseData.reused) {
        this.toast('已复用已有资源', 'success');
        return;
      }
      this.toast('上传成功', 'success');
      this.prependUploadedAsset(responseData, processedFile.size);
    },

    async createUploadThumbnail(processedFile, originalFile) {
      const features = window.LafuseConfig.features;
      if (!features.thumbnails) return null;
      const extension = getExtensionFromName(processedFile.name);
      const kind = getKind(extension);
      if (kind !== 'image' && kind !== 'video') return null;
      if (kind === 'video' && !features.videoThumbnails) return null;

      try {
        return kind === 'image'
          ? await generateImageThumbnail(processedFile)
          : await generateVideoThumbnail(originalFile);
      } catch (error) {
        console.warn('缩略图生成失败，已跳过:', error);
        return null;
      }
    },

    prependUploadedAsset(responseData, size) {
      if (this.user?.role !== 'admin') return;
      if (this.adminTotalCount != null) this.adminTotalCount += 1;
      if (this.adminCurrentPage !== 1) return;
      const item = {
        id: responseData.id,
        url: responseData.data,
        originalName: responseData.originalName || responseData.name || responseData.id,
        hasThumb: Boolean(responseData.hasThumb),
        thumbUrl: responseData.thumbUrl ?? null,
        createdAt: Date.now(),
        size,
        userId: this.user.userId,
        username: this.user.username,
        uploadSource: responseData.uploadSource || 'web',
      };
      this.adminMedia = [{ ...item, ...getMediaMeta(item) }, ...this.adminMedia];
      this.adminLoadedCursor = this.adminCursorStack[0] || '';
    },

    retryUpload(item) {
      if (item.status !== 'error') return;
      item.progress = 0;
      item.error = '';
      item.url = '';
      item.status = 'queued';
      this.processUploadQueue();
    },

    removeUpload(item) {
      if (item.previewSrc?.startsWith('blob:')) URL.revokeObjectURL(item.previewSrc);
      this.uploads = this.uploads.filter(upload => upload.id !== item.id);
    },

    clearFinished() {
      this.uploads
        .filter(item => item.status === 'done' && item.previewSrc?.startsWith('blob:'))
        .forEach(item => URL.revokeObjectURL(item.previewSrc));
      this.uploads = this.uploads.filter(item => item.status !== 'done');
    },

    statusText(item) {
      if (item.status === 'queued') return '排队中';
      if (item.status === 'compressing') return '压缩中';
      if (item.status === 'thumbnailing') return '准备缩略图';
      if (item.status === 'hashing') return '查重中';
      if (item.status === 'done') return '完成';
      if (item.status === 'error') return item.error || '失败';
      return `${item.progress}%`;
    },

    async copySuccessfulLinks(format = 'url') {
      const links = this.successfulUploads.map(item => this.linkItem(item));
      if (!links.length) return;
      const label = format === 'markdown' ? 'Markdown' : 'URL';
      await this.copyText(formatLinks(links, format), `已复制全部 ${label}`);
    },

    async copyItemLink(item, format = 'url') {
      if (!item?.url) return;
      const label = format === 'markdown' ? 'Markdown' : 'URL';
      await this.copyText(formatLinks([this.linkItem(item)], format), `已复制 ${label}`);
    },

    linkItem(item) {
      return {
        url: item.url,
        name: item.displayName || item.name || item.originalName || item.idLabel,
        kind: item.kind || getKind(item.extension || getExtension(item.url)),
      };
    },

    async copyText(text, message = '已复制') {
      try {
        await copyToClipboard(text);
        this.toast(message, 'success');
      } catch {
        this.toast('复制失败', 'error');
      }
    },

    toast(message, tone = 'info') {
      const id = crypto.randomUUID?.() ?? fallbackId();
      this.toasts.push({ id, message, tone });
      setTimeout(() => {
        this.toasts = this.toasts.filter(toast => toast.id !== id);
      }, 2600);
    },

    formatBytes,
    formatLinks,

    handleAssetPreviewError(item) {
      if (!item) return;
      if (item.kind === 'image' && item.previewSrc === item.thumbUrl && item.url) {
        item.previewSrc = item.url;
        return;
      }
      item.previewSrc = '';
      item.hasThumb = false;
    },

    async adminRefresh() {
      this.adminCurrentPage = 1;
      this.adminCursorStack = [''];
      this.adminLoadedCursor = null;
      await this.adminLoadMedia();
    },

    async adminReloadForFilters() {
      clearTimeout(this.adminFilterTimer);
      this.adminFilterTimer = setTimeout(() => this.adminReloadForFiltersNow(), 500);
    },

    async adminReloadForFiltersNow() {
      this.adminActiveAsset = null;
      this.adminSelectedIds = new Set();
      this.adminCurrentPage = 1;
      this.adminCursorStack = [''];
      this.adminLoadedCursor = null;
      if (this.view === 'admin') await this.adminLoadMedia(true);
    },

    async adminLoadUploaders() {
      try {
        const response = await fetch('/api.uploaders');
        const data = await response.json();
        if (response.ok) this.adminUploaderList = data.uploaders ?? [];
      } catch (error) {
        console.warn('加载上传者列表失败:', error);
      }
    },

    async adminLoadMedia(force = false) {
      const cursor = this.adminCursorStack[this.adminCurrentPage - 1] || '';
      if (this.adminLoadPromise) return this.adminLoadPromise;
      const filterKey = `${this.adminSearch.trim()}|${this.adminKind}|${this.adminUploader}`;
      if (!force && this.adminLoadedCursor === cursor && this.adminLoadedFilterKey === filterKey && this.adminMedia.length) return;

      this.adminLoading = true;
      this.adminLoadPromise = (async () => {
        const params = new URLSearchParams();
        const search = this.adminSearch.trim();
        const minSearchLength = window.LafuseConfig.features.searchMinLength ?? 2;
        if (cursor) params.set('cursor', cursor);
        if (search.length >= minSearchLength) params.set('q', search);
        if (this.adminKind !== 'all') params.set('kind', this.adminKind);
        if (this.adminUploader !== 'all') params.set('uploader', this.adminUploader);
        const query = params.toString();
        const response = await fetch(`/api.media${query ? `?${query}` : ''}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data?.error ?? '加载失败');

        this.adminTotalCount = data.totalCount ?? null;
        this.adminHasMore = Boolean(data.hasMore);
        this.adminNextCursor = data.nextCursor ?? null;
        this.adminMedia = (data.media ?? []).map(item => ({
          ...item,
          ...getMediaMeta(item),
        }));
        if (
          this.adminUploader !== 'all'
          && !this.adminUploaderOptions.includes(this.adminUploader)
        ) {
          this.adminUploader = 'all';
        }
        this.adminSelectedIds = new Set();
        this.adminActiveAsset = null;
        this.adminLoadedCursor = cursor;
        this.adminLoadedFilterKey = filterKey;
      })();

      try {
        await this.adminLoadPromise;
      } catch (error) {
        console.error('加载媒体数据失败:', error);
        this.toast(error?.message ?? '加载媒体数据失败', 'error');
      } finally {
        this.adminLoadPromise = null;
        this.adminLoading = false;
      }
    },

    adminOpenAsset(item) {
      this.adminActiveAsset = item;
    },

    adminToggleSelection(item, checked) {
      const next = new Set(this.adminSelectedIds);
      const shouldSelect = typeof checked === 'boolean' ? checked : !next.has(item.id);
      if (shouldSelect) next.add(item.id);
      else next.delete(item.id);
      this.adminSelectedIds = next;
    },

    adminClearSelection() {
      this.adminSelectedIds = new Set();
    },

    adminToggleSelectAll() {
      const ids = this.visibleAdminMedia.map(item => item.id);
      const allSelected = ids.length > 0 && ids.every(id => this.adminSelectedIds.has(id));
      const next = new Set(this.adminSelectedIds);
      ids.forEach(id => {
        if (allSelected) next.delete(id);
        else next.add(id);
      });
      this.adminSelectedIds = next;
    },

    async adminCopySelected(format = 'url') {
      const links = this.selectedAdminMedia.map(item => this.linkItem(item));
      if (!links.length) return;
      await this.copyText(formatLinks(links, format), '已复制选中链接');
    },

    async copyAsset(item, format = 'url') {
      await this.copyText(formatLinks([this.linkItem(item)], format), '已复制链接');
    },

    async adminDeleteSelected() {
      const ids = [...this.adminSelectedIds];
      if (!ids.length) return;
      if (!confirm(`确定删除选中的 ${ids.length} 个资源吗？此操作无法撤回。`)) return;
      await this.adminDeleteIds(ids);
    },

    async adminDeleteItem(item) {
      if (!item) return;
      if (!confirm(`确定删除 ${item.displayName} 吗？此操作无法撤回。`)) return;
      await this.adminDeleteIds([item.id]);
    },

    async adminDeleteIds(ids) {
      try {
        const response = await fetch('/api.delete-media', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids }),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data?.error ?? data?.message ?? '删除失败');

        const deleted = new Set(data.deletedIds ?? ids);
        this.adminMedia = this.adminMedia.filter(item => !deleted.has(item.id));
        if (this.adminTotalCount != null) {
          this.adminTotalCount = Math.max(0, this.adminTotalCount - deleted.size);
        }
        this.adminSelectedIds = new Set([...this.adminSelectedIds].filter(id => !deleted.has(id)));
        if (this.adminActiveAsset && deleted.has(this.adminActiveAsset.id)) {
          this.adminActiveAsset = null;
        }
        this.toast('删除成功', 'success');

        if (this.adminMedia.length === 0 && this.adminCurrentPage > 1) {
          this.adminCurrentPage -= 1;
          this.adminLoadedCursor = null;
          await this.adminLoadMedia();
        }
      } catch (error) {
        this.toast(error?.message ?? '删除失败，请重试', 'error');
      }
    },

    async adminGoPreviousPage() {
      if (this.adminCurrentPage <= 1) return;
      this.adminCurrentPage -= 1;
      this.adminLoadedCursor = null;
      await this.adminLoadMedia();
    },

    async adminGoNextPage() {
      if (!this.adminHasMore || !this.adminNextCursor) return;
      this.adminCursorStack[this.adminCurrentPage] = this.adminNextCursor;
      this.adminCurrentPage += 1;
      this.adminLoadedCursor = null;
      await this.adminLoadMedia();
    },
  }));
});
