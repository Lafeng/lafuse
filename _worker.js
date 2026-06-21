import { getSessionUser } from './src/auth.js';
import { buildConfig } from './src/config.js';
import { json } from './src/http.js';
import { getRouteKey, ROUTES } from './src/routes.js';

let configCache = null;

export default {
  async fetch(request, env, executionCtx) {
    const url = new URL(request.url);
    const route = ROUTES[getRouteKey(url.pathname)];
    if (!route) return new Response('Not Found', { status: 404 });

    if (route.assets) return env.ASSETS.fetch(request);

    if (route.method && request.method !== route.method) {
      return new Response('Method Not Allowed', { status: 405 });
    }

    configCache ??= buildConfig(env);
    const ctx = { request, url, config: configCache, env, executionCtx, user: null };

    if (route.auth) {
      const user = await getSessionUser(request, configCache);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      if (route.auth === 'admin' && user.role !== 'admin') {
        return json({ error: 'Forbidden' }, 403);
      }
      ctx.user = user;
    }

    return route.fn(ctx);
  },
};
