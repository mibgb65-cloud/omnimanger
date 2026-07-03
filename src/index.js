const MAX_VAULT_BYTES = 1024 * 1024;
const MAX_AUTH_BYTES = 4096;
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const REGISTRATION_SETTING_KEY = "settings:registration-open";
const RATE_LIMITS = {
  registerIp: { limit: 5, windowSeconds: 60 * 60 },
  registerEmail: { limit: 3, windowSeconds: 60 * 60 },
  loginIp: { limit: 30, windowSeconds: 15 * 60 },
  loginEmail: { limit: 10, windowSeconds: 15 * 60 },
  vaultRead: { limit: 120, windowSeconds: 60 },
  vaultWrite: { limit: 60, windowSeconds: 60 },
  adminSettings: { limit: 20, windowSeconds: 60 },
};

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; "),
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch {
        return json({ error: "Internal server error." }, 500);
      }
    }

    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  },
};

async function handleApi(request, env, url) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
        ...SECURITY_HEADERS,
      },
    });
  }

  if (!env.VAULT) {
    return json({ error: "KV binding VAULT is not configured." }, 500);
  }

  if (!env.SESSION_SECRET) {
    return json({ error: "SESSION_SECRET is not configured." }, 500);
  }

  if (url.pathname === "/api/auth/register" && request.method === "POST") {
    return registerUser(request, env, url);
  }

  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    return loginUser(request, env, url);
  }

  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    return logoutUser(url);
  }

  if (url.pathname === "/api/auth/me" && request.method === "GET") {
    const user = await getSessionUser(request, env);
    return json({ user: user ? publicUser(user, env) : null });
  }

  if (url.pathname === "/api/admin/settings" && request.method === "GET") {
    const user = await requireAdminUser(request, env);
    if (user instanceof Response) return user;
    return getAdminSettings(env);
  }

  if (url.pathname === "/api/admin/settings" && request.method === "PUT") {
    const user = await requireAdminUser(request, env);
    if (user instanceof Response) return user;
    const limited = await enforceRateLimit(
      env,
      "admin-settings",
      user.id,
      RATE_LIMITS.adminSettings.limit,
      RATE_LIMITS.adminSettings.windowSeconds,
    );
    if (limited) return limited;
    return putAdminSettings(request, env);
  }

  if (url.pathname === "/api/vault" && request.method === "GET") {
    const user = await requireSessionUser(request, env);
    if (user instanceof Response) return user;
    const limited = await enforceRateLimit(
      env,
      "vault-read",
      user.id,
      RATE_LIMITS.vaultRead.limit,
      RATE_LIMITS.vaultRead.windowSeconds,
    );
    if (limited) return limited;
    return getVault(env, user);
  }

  if (url.pathname === "/api/vault" && request.method === "PUT") {
    const user = await requireSessionUser(request, env);
    if (user instanceof Response) return user;
    const limited = await enforceRateLimit(
      env,
      "vault-write",
      user.id,
      RATE_LIMITS.vaultWrite.limit,
      RATE_LIMITS.vaultWrite.windowSeconds,
    );
    if (limited) return limited;
    return putVault(request, env, user);
  }

  return json({ error: "Not found." }, 404);
}

async function registerUser(request, env, url) {
  const ipLimited = await enforceRateLimit(
    env,
    "register-ip",
    getClientIp(request),
    RATE_LIMITS.registerIp.limit,
    RATE_LIMITS.registerIp.windowSeconds,
  );
  if (ipLimited) return ipLimited;

  const body = await readJsonBody(request, MAX_AUTH_BYTES);
  if (body instanceof Response) return body;

  const email = normalizeEmail(body.email);
  if (!EMAIL_PATTERN.test(email)) {
    return json({ error: "Email is invalid." }, 400);
  }

  const emailLimited = await enforceRateLimit(
    env,
    "register-email",
    email,
    RATE_LIMITS.registerEmail.limit,
    RATE_LIMITS.registerEmail.windowSeconds,
  );
  if (emailLimited) return emailLimited;

  const authSecret = decodeAuthSecret(body.authSecret);
  if (!authSecret) {
    return json({ error: "Auth secret is invalid." }, 400);
  }

  const registrationOpen = await getRegistrationOpen(env);
  const adminEmail = getAdminEmail(env);
  const isAdminRegistration = Boolean(adminEmail && email === adminEmail);
  if (!registrationOpen && !isAdminRegistration) {
    return json({ error: "Registration is closed." }, 403);
  }

  const emailKey = userEmailKey(email);
  const existingUserId = await env.VAULT.get(emailKey, "text");
  if (existingUserId) {
    return json({ error: "Account already exists." }, 409);
  }

  const authSalt = crypto.getRandomValues(new Uint8Array(16));
  const authHash = await hashAuthSecret(authSecret, authSalt);
  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    email,
    role: isAdminRegistration ? "admin" : "user",
    authSalt: bytesToBase64(authSalt),
    authHash,
    createdAt: now,
    updatedAt: now,
  };

  await env.VAULT.put(userKey(user.id), JSON.stringify(user));
  await env.VAULT.put(emailKey, user.id);

  return createSessionResponse({ user: publicUser(user, env) }, user, env, url);
}

async function loginUser(request, env, url) {
  const ipLimited = await enforceRateLimit(
    env,
    "login-ip",
    getClientIp(request),
    RATE_LIMITS.loginIp.limit,
    RATE_LIMITS.loginIp.windowSeconds,
  );
  if (ipLimited) return ipLimited;

  const body = await readJsonBody(request, MAX_AUTH_BYTES);
  if (body instanceof Response) return body;

  const email = normalizeEmail(body.email);
  const authSecret = decodeAuthSecret(body.authSecret);
  if (!EMAIL_PATTERN.test(email) || !authSecret) {
    return json({ error: "Email or password is invalid." }, 400);
  }

  const emailLimited = await enforceRateLimit(
    env,
    "login-email",
    email,
    RATE_LIMITS.loginEmail.limit,
    RATE_LIMITS.loginEmail.windowSeconds,
  );
  if (emailLimited) return emailLimited;

  const user = await getUserByEmail(env, email);
  if (!user) {
    return json({ error: "Email or password is invalid." }, 401);
  }

  const authSalt = base64ToBytes(user.authSalt);
  const authHash = await hashAuthSecret(authSecret, authSalt);
  if (!timingSafeEqual(authHash, user.authHash)) {
    return json({ error: "Email or password is invalid." }, 401);
  }

  return createSessionResponse({ user: publicUser(user, env) }, user, env, url);
}

function logoutUser(url) {
  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": makeExpiredSessionCookie(url),
    },
  );
}

async function getVault(env, user) {
  const stored = await env.VAULT.getWithMetadata(vaultKey(user.id), "text");
  if (!stored.value) {
    return json({ envelope: null, updatedAt: null });
  }

  try {
    return json({
      envelope: JSON.parse(stored.value),
      updatedAt: stored.metadata?.updatedAt ?? null,
    });
  } catch {
    return json({ error: "Stored vault data is invalid." }, 500);
  }
}

async function putVault(request, env, user) {
  const body = await readJsonBody(request, MAX_VAULT_BYTES);
  if (body instanceof Response) return body;

  if (!isVaultEnvelope(body)) {
    return json({ error: "Body is not a valid encrypted vault envelope." }, 400);
  }

  const updatedAt = new Date().toISOString();
  body.updatedAt = updatedAt;
  await env.VAULT.put(vaultKey(user.id), JSON.stringify(body), {
    metadata: { updatedAt, userId: user.id },
  });

  return json({ ok: true, updatedAt });
}

async function getAdminSettings(env) {
  return json({
    registrationOpen: await getRegistrationOpen(env),
    adminEmailConfigured: Boolean(getAdminEmail(env)),
  });
}

async function putAdminSettings(request, env) {
  const body = await readJsonBody(request, MAX_AUTH_BYTES);
  if (body instanceof Response) return body;
  if (typeof body.registrationOpen !== "boolean") {
    return json({ error: "registrationOpen must be a boolean." }, 400);
  }

  await env.VAULT.put(REGISTRATION_SETTING_KEY, body.registrationOpen ? "true" : "false");
  return json({ registrationOpen: body.registrationOpen });
}

async function getRegistrationOpen(env) {
  return (await env.VAULT.get(REGISTRATION_SETTING_KEY, "text")) === "true";
}

async function readJsonBody(request, maxBytes) {
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (contentLength > maxBytes) {
    return json({ error: "Payload is too large." }, 413);
  }

  const body = await request.text();
  if (body.length > maxBytes) {
    return json({ error: "Payload is too large." }, 413);
  }

  try {
    return JSON.parse(body);
  } catch {
    return json({ error: "Body must be JSON." }, 400);
  }
}

async function getSessionUser(request, env) {
  const cookie = parseCookies(request.headers.get("cookie") || "").vault_session;
  if (!cookie) return null;

  const parts = cookie.split(".");
  if (parts.length !== 2) return null;

  const [payloadValue, signature] = parts;
  const expectedSignature = await signSessionPayload(payloadValue, env.SESSION_SECRET);
  if (!timingSafeEqual(signature, expectedSignature)) return null;

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadValue)));
  } catch {
    return null;
  }

  if (!payload?.sub || !payload.exp || Date.now() >= payload.exp * 1000) {
    return null;
  }

  return getUserById(env, payload.sub);
}

async function requireSessionUser(request, env) {
  const user = await getSessionUser(request, env);
  return user || json({ error: "Unauthorized." }, 401);
}

async function requireAdminUser(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Unauthorized." }, 401);
  if (!isAdminUser(user, env)) return json({ error: "Forbidden." }, 403);
  return user;
}

async function createSessionResponse(data, user, env, url) {
  const payload = {
    sub: user.id,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS,
  };
  const payloadValue = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const signature = await signSessionPayload(payloadValue, env.SESSION_SECRET);

  return json(data, 200, {
    "Set-Cookie": makeSessionCookie(`${payloadValue}.${signature}`, url),
  });
}

async function signSessionPayload(payloadValue, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadValue));
  return base64UrlEncode(new Uint8Array(signature));
}

async function hashAuthSecret(authSecret, salt) {
  const input = new Uint8Array(salt.length + authSecret.length);
  input.set(salt, 0);
  input.set(authSecret, salt.length);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return bytesToBase64(new Uint8Array(digest));
}

function decodeAuthSecret(value) {
  if (typeof value !== "string") return null;
  try {
    const bytes = base64ToBytes(value);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const cookies = {};
  for (const part of cookieHeader.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (!name) continue;
    cookies[name] = rest.join("=");
  }
  return cookies;
}

function makeSessionCookie(value, url) {
  const secure = url.protocol === "https:" ? "; Secure" : "";
  return [
    `vault_session=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${SESSION_MAX_AGE_SECONDS}`,
    secure.slice(2),
  ]
    .filter(Boolean)
    .join("; ");
}

function makeExpiredSessionCookie(url) {
  const secure = url.protocol === "https:" ? "; Secure" : "";
  return ["vault_session=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0", secure.slice(2)]
    .filter(Boolean)
    .join("; ");
}

async function getUserByEmail(env, email) {
  const id = await env.VAULT.get(userEmailKey(email), "text");
  return id ? getUserById(env, id) : null;
}

async function getUserById(env, id) {
  const raw = await env.VAULT.get(userKey(id), "text");
  if (!raw) return null;

  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function publicUser(user, env) {
  return {
    id: user.id,
    email: user.email,
    isAdmin: isAdminUser(user, env),
  };
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getAdminEmail(env) {
  return normalizeEmail(env.ADMIN_EMAIL || "");
}

function isAdminUser(user, env) {
  const adminEmail = getAdminEmail(env);
  return Boolean(adminEmail && normalizeEmail(user.email) === adminEmail);
}

function userEmailKey(email) {
  return `user-email:${email}`;
}

function userKey(id) {
  return `user:${id}`;
}

function vaultKey(userId) {
  return `vault:${userId}`;
}

async function enforceRateLimit(env, scope, identifier, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(now / windowSeconds);
  const idHash = await hashIdentifier(identifier || "unknown");
  const key = `rate:${scope}:${bucket}:${idHash}`;
  const current = Number((await env.VAULT.get(key, "text")) || "0");
  if (current >= limit) {
    return json(
      { error: "Too many requests. Try again later." },
      429,
      {
        "Retry-After": String(windowSeconds),
        "X-RateLimit-Limit": String(limit),
        "X-RateLimit-Remaining": "0",
      },
    );
  }

  await env.VAULT.put(key, String(current + 1), {
    expirationTtl: windowSeconds + 60,
  });
  return null;
}

async function hashIdentifier(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(String(value)));
  return base64UrlEncode(new Uint8Array(digest));
}

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
}

function isVaultEnvelope(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      value.version === 1 &&
      value.kdf &&
      value.kdf.name === "PBKDF2-SHA256" &&
      Number.isInteger(value.kdf.iterations) &&
      typeof value.kdf.salt === "string" &&
      value.cipher &&
      value.cipher.name === "AES-GCM" &&
      typeof value.cipher.iv === "string" &&
      typeof value.cipher.data === "string",
  );
}

function timingSafeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    diff |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return diff === 0;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    const chunk = bytes.subarray(offset, offset + 0x8000);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function base64UrlEncode(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function withSecurityHeaders(response) {
  const next = new Response(response.body, response);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    next.headers.set(key, value);
  }
  return next;
}
