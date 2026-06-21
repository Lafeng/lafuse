export const MAX_LOGIN_ATTEMPTS = 5;
export const RATE_LIMIT_WINDOW = 900;

export async function getRateLimitCount(ip, kv) {
  const raw = await kv.get(`ratelimit:${ip}`);
  return raw ? parseInt(raw, 10) : 0;
}

export async function recordFailedAttempt(ip, kv, currentCount = null) {
  const key = `ratelimit:${ip}`;
  const count = (currentCount ?? await getRateLimitCount(ip, kv)) + 1;
  await kv.put(key, String(count), { expirationTtl: RATE_LIMIT_WINDOW });
  return count;
}

export async function clearRateLimit(ip, kv) {
  await kv.delete(`ratelimit:${ip}`);
}
