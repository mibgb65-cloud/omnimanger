const MAX_VAULT_BYTES = 1024 * 1024;
const MAX_AUTH_BYTES = 4096;
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const REGISTRATION_SETTING_KEY = "settings:registration-open";
const INVITE_INDEX_KEY = "admin:invites";
const AUDIT_INDEX_KEY = "admin:audit";
const AUTH_VERIFIER_VERSION = 3;
const MIN_VAULT_KDF_ITERATIONS = 100000;
const MAX_VAULT_KDF_ITERATIONS = 2000000;
const INVITE_TTL_SECONDS = 7 * 24 * 60 * 60;
const LOGIN_COOLDOWN_THRESHOLD = 3;
const LOGIN_COOLDOWN_STEPS_SECONDS = [30, 120, 600, 1800];
const LOGIN_FAILURE_TTL_SECONDS = 24 * 60 * 60;
const RATE_LIMITS = {
  registerIp: { limit: 5, windowSeconds: 60 * 60 },
  registerEmail: { limit: 3, windowSeconds: 60 * 60 },
  loginIp: { limit: 30, windowSeconds: 15 * 60 },
  loginEmail: { limit: 10, windowSeconds: 15 * 60 },
  vaultRead: { limit: 120, windowSeconds: 60 },
  vaultWrite: { limit: 60, windowSeconds: 60 },
  adminSettings: { limit: 20, windowSeconds: 60 },
  passwordChange: { limit: 5, windowSeconds: 15 * 60 },
  passwordVerify: { limit: 10, windowSeconds: 15 * 60 },
  sessionRevoke: { limit: 5, windowSeconds: 15 * 60 },
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

function logApiError(request, url, error) {
  console.error(
    JSON.stringify({
      event: "api_error",
      method: request.method,
      path: url.pathname,
      message: error?.message || "Unknown error",
    }),
  );
}

function logSecurityEvent(event, fields = {}) {
  console.log(
    JSON.stringify({
      event,
      at: new Date().toISOString(),
      ...fields,
    }),
  );
}

async function readJsonArray(env, key) {
  const raw = await env.VAULT.get(key, "text");
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function readJsonBody(request, maxBytes) {
  const rawContentLength = request.headers.get("content-length");
  const contentLength = rawContentLength === null ? 0 : Number(rawContentLength);
  if (!Number.isFinite(contentLength) || contentLength < 0) {
    return json({ error: "Content-Length is invalid." }, 400);
  }

  if (contentLength > maxBytes) {
    return json({ error: "Payload is too large." }, 413);
  }

  const buffer = await request.arrayBuffer();
  if (buffer.byteLength > maxBytes) {
    return json({ error: "Payload is too large." }, 413);
  }

  try {
    return JSON.parse(new TextDecoder().decode(buffer));
  } catch {
    return json({ error: "Body must be JSON." }, 400);
  }
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeInviteToken(token) {
  const normalized = String(token || "").trim();
  return /^[A-Za-z0-9_-]{24,128}$/.test(normalized) ? normalized : "";
}

function normalizeRevision(revision) {
  return revision === null || revision === undefined || revision === "" ? null : String(revision);
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

function inviteKey(token) {
  return `invite:${token}`;
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

async function recordUserActivity(env, user, fields) {
  const current = await getUserById(env, user.id);
  if (!current) return;

  await env.VAULT.put(
    userKey(user.id),
    JSON.stringify({
      ...current,
      ...fields,
      updatedAt: new Date().toISOString(),
    }),
  );
}

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
}

function isVaultEnvelope(value) {
  if (!value || typeof value !== "object" || value.version !== 1) return false;
  if (value.schemaVersion !== undefined && value.schemaVersion !== 1) return false;
  if (!value.kdf || value.kdf.name !== "PBKDF2-SHA256") return false;
  if (
    !Number.isInteger(value.kdf.iterations) ||
    value.kdf.iterations < MIN_VAULT_KDF_ITERATIONS ||
    value.kdf.iterations > MAX_VAULT_KDF_ITERATIONS
  ) {
    return false;
  }

  if (!isBase64Field(value.kdf.salt, 8, 128)) return false;
  if (!value.cipher || value.cipher.name !== "AES-GCM") return false;
  if (!isBase64Field(value.cipher.iv, 12, 12)) return false;
  if (!isBase64Field(value.cipher.data, 1, MAX_VAULT_BYTES)) return false;
  if (value.updatedAt !== undefined && !isIsoDateString(value.updatedAt)) return false;
  return true;
}

function isBase64Field(value, minBytes, maxBytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  if (value.length % 4 !== 0) return false;

  const decodedLength = base64DecodedLength(value);
  return decodedLength >= minBytes && decodedLength <= maxBytes;
}

function base64DecodedLength(value) {
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return Math.floor((value.length * 3) / 4) - padding;
}

function isIsoDateString(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
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
    binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + 0x8000));
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
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

export {
  AUDIT_INDEX_KEY,
  AUTH_VERIFIER_VERSION,
  EMAIL_PATTERN,
  INVITE_INDEX_KEY,
  INVITE_TTL_SECONDS,
  LOGIN_COOLDOWN_STEPS_SECONDS,
  LOGIN_COOLDOWN_THRESHOLD,
  LOGIN_FAILURE_TTL_SECONDS,
  MAX_AUTH_BYTES,
  MAX_VAULT_BYTES,
  RATE_LIMITS,
  REGISTRATION_SETTING_KEY,
  SESSION_MAX_AGE_SECONDS,
  base64ToBytes,
  base64UrlEncode,
  base64UrlToBytes,
  bytesToBase64,
  encoder,
  getAdminEmail,
  getClientIp,
  getUserByEmail,
  getUserById,
  inviteKey,
  isAdminUser,
  isVaultEnvelope,
  json,
  logApiError,
  logSecurityEvent,
  normalizeEmail,
  normalizeInviteToken,
  normalizeRevision,
  publicUser,
  readJsonArray,
  readJsonBody,
  recordUserActivity,
  timingSafeEqual,
  userEmailKey,
  userKey,
  vaultKey,
  withSecurityHeaders,
};
