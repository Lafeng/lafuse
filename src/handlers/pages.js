import { getSessionUser } from '../auth.js';

export async function serveIndex({ request, config, env }) {
  const user = await getSessionUser(request, config);
  if (!user) return Response.redirect(new URL('/login', request.url), 302);
  return env.ASSETS.fetch(new Request(new URL('/index.html', request.url)));
}

export async function serveLogin({ request, config, env }) {
  const user = await getSessionUser(request, config);
  if (user) return Response.redirect(new URL('/', request.url), 302);
  return env.ASSETS.fetch(new Request(new URL('/login.html', request.url)));
}
