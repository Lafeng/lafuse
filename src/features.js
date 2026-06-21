const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

function parseBoolean(value, fallback) {
  if (value == null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  return fallback;
}

function parseInteger(value, fallback, { min, max } = {}) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  if (min != null && parsed < min) return min;
  if (max != null && parsed > max) return max;
  return parsed;
}

export function buildFeatureConfig(env) {
  const lowCostMode = parseBoolean(env.LOW_COST_MODE, true);
  const enableUploadDedupe = parseBoolean(env.ENABLE_UPLOAD_DEDUPE, !lowCostMode);
  const enableThumbnails = parseBoolean(env.ENABLE_THUMBNAILS, !lowCostMode);

  return {
    lowCostMode,
    enableUploadDedupe,
    enableThumbnails,
    enableVideoThumbnails: parseBoolean(env.ENABLE_VIDEO_THUMBNAILS, false),
    enableTotalCount: parseBoolean(env.ENABLE_TOTAL_COUNT, !lowCostMode),
    searchMode: env.SEARCH_MODE === 'contains' ? 'contains' : 'prefix',
    searchMinLength: parseInteger(env.SEARCH_MIN_LENGTH, 2, { min: 0, max: 20 }),
    hashMaxBytes: parseInteger(env.HASH_MAX_MB, lowCostMode ? 20 : 100, { min: 1, max: 512 }) * 1048576,
  };
}

export function getClientConfig(config) {
  return {
    features: {
      uploadDedupe: config.features.enableUploadDedupe,
      thumbnails: config.features.enableThumbnails,
      videoThumbnails: config.features.enableVideoThumbnails,
      totalCount: config.features.enableTotalCount,
      searchMode: config.features.searchMode,
      searchMinLength: config.features.searchMinLength,
      hashMaxBytes: config.features.hashMaxBytes,
    },
  };
}
