import {
  SESSION_MAX_AGE_SECONDS,
  base64UrlEncode,
  base64UrlToBytes,
  encoder,
  getUserById,
  isAdminUser,
  json,
  timingSafeEqual,
} from "./core.js";

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

  const user = await getUserById(env, payload.sub);
  if (!user) return null;
  if ((payload.sv || "0") !== getSessionVersion(user)) return null;
  return user;
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
    sv: getSessionVersion(user),
    exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS,
  };
  const payloadValue = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const signature = await signSessionPayload(payloadValue, env.SESSION_SECRET);

  return json(data, 200, {
    "Set-Cookie": makeSessionCookie(`${payloadValue}.${signature}`, url),
  });
}

function getSessionVersion(user) {
  return typeof user.sessionVersion === "string" && user.sessionVersion ? user.sessionVersion : "0";
}

function createSessionVersion() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
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

export {
  createSessionResponse,
  createSessionVersion,
  getSessionUser,
  getSessionVersion,
  makeExpiredSessionCookie,
  requireAdminUser,
  requireSessionUser,
};
