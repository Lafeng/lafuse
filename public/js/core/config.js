(function () {
  window.LafuseConfig = {
    MAX_PARALLEL_UPLOADS: 3,
    COMPRESSION_PREF_KEY: 'lafuse:enableCompression',
    features: {
      uploadDedupe: false,
      thumbnails: false,
      videoThumbnails: false,
      totalCount: false,
      searchMode: 'prefix',
      searchMinLength: 2,
      hashMaxBytes: 20 * 1024 * 1024,
    },
  };
}());
