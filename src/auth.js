const sessionKeyCache = new Map();

export function parseCookies(header) {
  if (!header) return {};
  const out = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    out[part.substring(0, eq).trim()] = decodeURIComponent(part.substring(eq + 1).trim());
  }
  return out;
}

export async function hashPassword(password, salt) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${salt}:${password}`),
  );
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncode(value) {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function getSessionSigningKey(salt) {
  if (!sessionKeyCache.has(salt)) {
    sessionKeyCache.set(salt, crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(`lafuse-session:${salt}`),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    ));
  }
  return sessionKeyCache.get(salt);
}

async function signSessionPayload(payload, salt) {
  const key = await getSessionSigningKey(salt);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(payload),
  );
  return base64UrlEncode(new Uint8Array(signature));
}

async function verifySessionToken(token, salt) {
  const [payloadPart, signature] = token.split('.');
  if (!payloadPart || !signature) return null;

  const expected = await signSessionPayload(payloadPart, salt);
  if (expected !== signature) return null;

  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadPart)));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return {
      userId: payload.userId,
      username: payload.username,
      role: payload.role,
    };
  } catch {
    return null;
  }
}

export async function createSessionToken(user, maxAge, salt) {
  const payload = base64UrlEncode(JSON.stringify({
    userId: user.userId,
    username: user.username,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + maxAge,
  }));
  const signature = await signSessionPayload(payload, salt);
  return `${payload}.${signature}`;
}

export function isSecureRequest(request) {
  return new URL(request.url).protocol === 'https:';
}

export function buildSessionCookie(name, value, maxAge, secure) {
  const secureAttr = secure ? '; Secure' : '';
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly${secureAttr}; SameSite=Lax`;
}

export function clearSessionCookie(name, secure) {
  const secureAttr = secure ? '; Secure' : '';
  return `${name}=; Path=/; Max-Age=0; HttpOnly${secureAttr}; SameSite=Lax`;
}

export async function getSessionUser(request, config) {
  const sid = parseCookies(request.headers.get('Cookie'))[config.sessionCookieName];
  if (!sid) return null;
  return verifySessionToken(sid, config.authSalt);
}
