import {
  buildSessionCookie,
  clearSessionCookie,
  createSessionToken,
  getSessionUser,
  hashPassword,
  isSecureRequest,
} from '../auth.js';
import { json } from '../http.js';
import {
  clearRateLimit,
  getRateLimitCount,
  MAX_LOGIN_ATTEMPTS,
  recordFailedAttempt,
} from '../rateLimit.js';
import { getClientConfig } from '../features.js';

export async function apiLogin({ request, config }) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const kv = config.kvNamespace;

  const attempts = await getRateLimitCount(ip, kv);
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    return json({ error: '登录尝试次数过多，请15分钟后再试' }, 429);
  }

  try {
    const { username, password } = await request.json();
    if (!username || !password) return json({ error: '缺少用户名或密码' }, 400);

    const row = await config.database
      .prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?')
      .bind(username)
      .first();

    if (!row) {
      await recordFailedAttempt(ip, kv, attempts);
      return json({ error: '用户名或密码错误' }, 401);
    }

    const hash = await hashPassword(password, config.authSalt);
    if (hash !== row.password_hash.toLowerCase()) {
      const count = await recordFailedAttempt(ip, kv, attempts);
      const remaining = MAX_LOGIN_ATTEMPTS - count;
      return json({
        error: remaining > 0
          ? `用户名或密码错误，还剩 ${remaining} 次尝试机会`
          : '登录尝试次数过多，请15分钟后再试',
      }, 401);
    }

    if (attempts > 0) await clearRateLimit(ip, kv);
    const payload = { userId: row.id, username: row.username, role: row.role };
    const sessionToken = await createSessionToken(payload, config.sessionTtlSeconds, config.authSalt);

    return json({ ok: true, user: payload }, 200, {
      'Set-Cookie': buildSessionCookie(
        config.sessionCookieName,
        sessionToken,
        config.sessionTtlSeconds,
        isSecureRequest(request),
      ),
    });
  } catch (e) {
    return json({ error: e.message ?? '登录失败' }, 500);
  }
}

export async function apiLogout({ request, config }) {
  return json({ ok: true }, 200, {
    'Set-Cookie': clearSessionCookie(config.sessionCookieName, isSecureRequest(request)),
  });
}

export async function apiSession({ request, config }) {
  const user = await getSessionUser(request, config);
  return json({ user: user ?? null, ...getClientConfig(config) });
}
