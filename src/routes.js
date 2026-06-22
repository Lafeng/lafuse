import { serveMedia } from './media.js';
import {
  apiLogin,
  apiLogout,
  apiSession,
} from './handlers/authApi.js';
import {
  apiExists,
  apiDeleteMedia,
  apiMedia,
  apiUpload,
  apiUploaders,
} from './handlers/mediaApi.js';
import {
  apiV1Ping,
  apiV1Upload,
} from './handlers/tokenUploadApi.js';
import {
  serveIndex,
  serveLogin,
} from './handlers/pages.js';

export const ROUTES = {
  css: { assets: true },
  js: { assets: true },
  fonts: { assets: true },
  images: { assets: true },
  'lafuse-logo.png': { assets: true },

  '': { fn: serveIndex },
  login: { fn: serveLogin },

  i: { fn: serveMedia },
  t: { fn: serveMedia },

  'api.login': { fn: apiLogin, method: 'POST' },
  'api.logout': { fn: apiLogout, method: 'POST' },
  'api.session': { fn: apiSession },
  'api.media': { fn: apiMedia, auth: 'admin' },
  'api.uploaders': { fn: apiUploaders, auth: 'admin' },
  'api.exists': { fn: apiExists, auth: 'user' },
  'api.upload': { fn: apiUpload, method: 'POST', auth: 'user' },
  'api.delete-media': { fn: apiDeleteMedia, method: 'POST', auth: 'admin' },
  'api/v1/ping': { fn: apiV1Ping },
  'api/v1/upload': { fn: apiV1Upload, method: 'POST' },
};

export function getRouteKey(pathname) {
  if (pathname.startsWith('/api/v1/')) return pathname.slice(1);
  const seg1End = pathname.indexOf('/', 1);
  return seg1End > 0 ? pathname.substring(1, seg1End) : pathname.substring(1);
}
