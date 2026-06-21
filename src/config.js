import { buildFeatureConfig } from './features.js';

export function buildConfig(env) {
  if (!env.AUTH_SALT) {
    throw new Error('AUTH_SALT must be configured as a Worker secret or local dev variable');
  }

  const features = buildFeatureConfig(env);
  const domain = env.DOMAIN;
  const mediaPublicOrigin = env.MEDIA_PUBLIC_ORIGIN?.replace(/\/+$/, '') || '';
  const localDomain = !domain || /(^|\/\/)(localhost|127\.0\.0\.1)(:|\/|$)/i.test(domain);
  const allowWorkerMediaProxy = localDomain || env.ALLOW_WORKER_MEDIA_PROXY === '1';
  if (features.lowCostMode && !mediaPublicOrigin && !allowWorkerMediaProxy) {
    throw new Error('MEDIA_PUBLIC_ORIGIN is required in LOW_COST_MODE to avoid Worker media proxy costs');
  }

  return {
    domain,
    mediaPublicOrigin,
    allowWorkerMediaProxy,
    database: env.DATABASE,
    r2Bucket: env.R2_BUCKET,
    kvNamespace: env.KV_NAMESPACE,
    authSalt: env.AUTH_SALT,
    sessionCookieName: env.SESSION_COOKIE_NAME ?? 'lafuse_session',
    sessionTtlSeconds: (env.SESSION_TTL_DAYS ? parseInt(env.SESSION_TTL_DAYS, 10) : 7) * 86400,
    maxSize: (env.MAX_SIZE_MB ? parseInt(env.MAX_SIZE_MB, 10) : 10) * 1048576,
    features,
  };
}
