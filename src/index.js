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
const RATE_LIMITS = {
  registerIp: { limit: 5, windowSeconds: 60 * 60 },
  registerEmail: { limit: 3, windowSeconds: 60 * 60 },
  loginIp: { limit: 30, windowSeconds: 15 * 60 },
  loginEmail: { limit: 10, windowSeconds: 15 * 60 },
  vaultRead: { limit: 120, windowSeconds: 60 },
  vaultWrite: { limit: 60, windowSeconds: 60 },
  adminSettings: { limit: 20, windowSeconds: 60 },
  passwordChange: { limit: 5, windowSeconds: 15 * 60 },
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (error) {
        logApiError(request, url, error);
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

  if (url.pathname === "/api/auth/logout-all" && request.method === "POST") {
    const user = await requireSessionUser(request, env);
    if (user instanceof Response) return user;
    const limited = await enforceRateLimit(
      env,
      "session-revoke",
      user.id,
      RATE_LIMITS.sessionRevoke.limit,
      RATE_LIMITS.sessionRevoke.windowSeconds,
    );
    if (limited) return limited;
    return logoutAllSessions(env, user, url);
  }

  if (url.pathname === "/api/auth/change-password" && request.method === "POST") {
    const user = await requireSessionUser(request, env);
    if (user instanceof Response) return user;
    const limited = await enforceRateLimit(
      env,
      "password-change",
      user.id,
      RATE_LIMITS.passwordChange.limit,
      RATE_LIMITS.passwordChange.windowSeconds,
    );
    if (limited) return limited;
    return changePassword(request, env, user);
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

  if (url.pathname === "/api/admin/invites" && request.method === "GET") {
    const user = await requireAdminUser(request, env);
    if (user instanceof Response) return user;
    return listInvites(env);
  }

  if (url.pathname === "/api/admin/invites" && request.method === "POST") {
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
    return createInvite(env, user);
  }

  if (url.pathname === "/api/admin/invites/revoke" && request.method === "POST") {
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
    return revokeInvite(request, env, user);
  }

  if (url.pathname === "/api/admin/audit" && request.method === "GET") {
    const user = await requireAdminUser(request, env);
    if (user instanceof Response) return user;
    return listAuditEvents(env);
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
  const inviteToken = normalizeInviteToken(body.inviteToken);
  const inviteAllowed = !registrationOpen && !isAdminRegistration ? await canUseInvite(env, inviteToken) : false;
  if (!registrationOpen && !isAdminRegistration && !inviteAllowed) {
    return json({ error: "Registration is closed." }, 403);
  }

  const emailKey = userEmailKey(email);
  const existingUserId = await env.VAULT.get(emailKey, "text");
  if (existingUserId) {
    return json({ error: "Account already exists." }, 409);
  }

  const authSalt = crypto.getRandomValues(new Uint8Array(16));
  const authVerifier = await makeAuthVerifier(env, authSecret, authSalt);
  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    email,
    role: isAdminRegistration ? "admin" : "user",
    auth: authVerifier,
    sessionVersion: createSessionVersion(),
    createdAt: now,
    updatedAt: now,
  };

  await env.VAULT.put(userKey(user.id), JSON.stringify(user));
  await env.VAULT.put(emailKey, user.id);
  if (inviteAllowed) {
    await consumeInvite(env, inviteToken, user);
  }

  logSecurityEvent("user_registered", { userId: user.id, role: user.role, invited: inviteAllowed });
  await recordAuditEvent(env, "user_registered", { userId: user.id, role: user.role, invited: inviteAllowed });
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
    logSecurityEvent("login_failed", { reason: "unknown_user" });
    await recordAuditEvent(env, "login_failed", { reason: "unknown_user" });
    return json({ error: "Email or password is invalid." }, 401);
  }

  const verified = await verifyAuthSecret(env, user, authSecret);
  if (!verified) {
    logSecurityEvent("login_failed", { reason: "bad_secret", userId: user.id });
    await recordAuditEvent(env, "login_failed", { reason: "bad_secret", userId: user.id });
    return json({ error: "Email or password is invalid." }, 401);
  }

  if (verified.upgradedUser) {
    await env.VAULT.put(userKey(verified.upgradedUser.id), JSON.stringify(verified.upgradedUser));
  }

  await recordUserActivity(env, verified.upgradedUser || user, { lastLoginAt: new Date().toISOString() });
  logSecurityEvent("login_succeeded", { userId: user.id });
  await recordAuditEvent(env, "login_succeeded", { userId: user.id });
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

async function logoutAllSessions(env, user, url) {
  const current = await getUserById(env, user.id);
  if (!current) return json({ error: "Unauthorized." }, 401);
  const updatedAt = new Date().toISOString();
  await env.VAULT.put(
    userKey(user.id),
    JSON.stringify({
      ...current,
      sessionVersion: createSessionVersion(),
      updatedAt,
    }),
  );
  logSecurityEvent("sessions_revoked", { userId: user.id });
  await recordAuditEvent(env, "sessions_revoked", { userId: user.id });
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
    return json({ envelope: null, updatedAt: null, revision: null });
  }

  try {
    const revision = stored.metadata?.revision ?? stored.metadata?.updatedAt ?? null;
    return json({
      envelope: JSON.parse(stored.value),
      updatedAt: stored.metadata?.updatedAt ?? null,
      revision,
    });
  } catch {
    return json({ error: "Stored vault data is invalid." }, 500);
  }
}

async function putVault(request, env, user) {
  const body = await readJsonBody(request, MAX_VAULT_BYTES);
  if (body instanceof Response) return body;

  const envelope = isVaultEnvelope(body) ? body : body?.envelope;
  const baseRevision = isVaultEnvelope(body) ? request.headers.get("If-Match") : normalizeRevision(body?.baseRevision);

  if (!isVaultEnvelope(envelope)) {
    return json({ error: "Body is not a valid encrypted vault envelope." }, 400);
  }

  const current = await env.VAULT.getWithMetadata(vaultKey(user.id), "text");
  const currentRevision = current.metadata?.revision ?? current.metadata?.updatedAt ?? null;
  if (current.value && baseRevision !== null && baseRevision !== currentRevision) {
    logSecurityEvent("vault_revision_conflict", { userId: user.id });
    return json(
      {
        error: "Vault has changed on another device.",
        currentRevision,
        updatedAt: current.metadata?.updatedAt ?? null,
      },
      409,
    );
  }

  const updatedAt = new Date().toISOString();
  const revision = crypto.randomUUID();
  envelope.updatedAt = updatedAt;
  await env.VAULT.put(vaultKey(user.id), JSON.stringify(envelope), {
    metadata: { updatedAt, userId: user.id, revision },
  });
  await recordUserActivity(env, user, { lastVaultSaveAt: updatedAt });

  return json({ ok: true, updatedAt, revision });
}

async function changePassword(request, env, user) {
  const body = await readJsonBody(request, MAX_VAULT_BYTES + MAX_AUTH_BYTES);
  if (body instanceof Response) return body;

  const authSecret = decodeAuthSecret(body.authSecret);
  const newAuthSecret = decodeAuthSecret(body.newAuthSecret);
  const envelope = body?.envelope;
  const baseRevision = normalizeRevision(body?.baseRevision);
  if (!authSecret || !newAuthSecret || !isVaultEnvelope(envelope)) {
    return json({ error: "Password change payload is invalid." }, 400);
  }

  const verified = await verifyAuthSecret(env, user, authSecret);
  if (!verified) {
    return json({ error: "Current password is invalid." }, 401);
  }

  const current = await env.VAULT.getWithMetadata(vaultKey(user.id), "text");
  const currentRevision = current.metadata?.revision ?? current.metadata?.updatedAt ?? null;
  if (current.value && baseRevision !== null && baseRevision !== currentRevision) {
    logSecurityEvent("password_change_revision_conflict", { userId: user.id });
    return json(
      {
        error: "Vault has changed on another device.",
        currentRevision,
        updatedAt: current.metadata?.updatedAt ?? null,
      },
      409,
    );
  }

  const updatedAt = new Date().toISOString();
  const revision = crypto.randomUUID();
  envelope.updatedAt = updatedAt;
  const nextUser = {
    ...(verified.upgradedUser || user),
    auth: await makeAuthVerifier(env, newAuthSecret, crypto.getRandomValues(new Uint8Array(16))),
    updatedAt,
  };
  delete nextUser.authHash;
  delete nextUser.authSalt;

  await env.VAULT.put(vaultKey(user.id), JSON.stringify(envelope), {
    metadata: { updatedAt, userId: user.id, revision },
  });
  await env.VAULT.put(userKey(nextUser.id), JSON.stringify(nextUser));
  logSecurityEvent("password_changed", { userId: user.id });
  await recordAuditEvent(env, "password_changed", { userId: user.id });
  return json({ ok: true, updatedAt, revision });
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
  logSecurityEvent("admin_registration_setting_changed", { registrationOpen: body.registrationOpen });
  await recordAuditEvent(env, "admin_registration_setting_changed", { registrationOpen: body.registrationOpen });
  return json({ registrationOpen: body.registrationOpen });
}

async function createInvite(env, user) {
  const token = base64UrlEncode(crypto.getRandomValues(new Uint8Array(24)));
  const now = new Date();
  const expiresAt = new Date(now.getTime() + INVITE_TTL_SECONDS * 1000).toISOString();
  const record = {
    createdBy: user.id,
    createdAt: now.toISOString(),
    expiresAt,
  };

  await env.VAULT.put(inviteKey(token), JSON.stringify(record), {
    expirationTtl: INVITE_TTL_SECONDS + 60,
  });
  await upsertInviteIndex(env, { token, ...record, status: "active" });

  logSecurityEvent("invite_created", { userId: user.id, expiresAt });
  await recordAuditEvent(env, "invite_created", { userId: user.id, expiresAt });
  return json({ token, expiresAt });
}

async function listInvites(env) {
  const invites = (await readJsonArray(env, INVITE_INDEX_KEY)).map(publicInviteRecord);
  return json({ invites });
}

async function revokeInvite(request, env, user) {
  const body = await readJsonBody(request, MAX_AUTH_BYTES);
  if (body instanceof Response) return body;
  const token = normalizeInviteToken(body.token);
  if (!token) return json({ error: "Invite token is invalid." }, 400);

  const raw = await env.VAULT.get(inviteKey(token), "text");
  if (raw) await env.VAULT.delete(inviteKey(token));
  const revokedAt = new Date().toISOString();
  await updateInviteIndex(env, token, {
    revokedAt,
    revokedBy: user.id,
    status: "revoked",
  });
  logSecurityEvent("invite_revoked", { userId: user.id });
  await recordAuditEvent(env, "invite_revoked", { userId: user.id });
  return json({ ok: true, revokedAt });
}

async function getRegistrationOpen(env) {
  return (await env.VAULT.get(REGISTRATION_SETTING_KEY, "text")) === "true";
}

async function canUseInvite(env, token) {
  if (!token) return false;
  const raw = await env.VAULT.get(inviteKey(token), "text");
  if (!raw) return false;

  try {
    const invite = JSON.parse(raw);
    return Boolean(invite.expiresAt && Date.now() < Date.parse(invite.expiresAt));
  } catch {
    return false;
  }
}

async function consumeInvite(env, token, user) {
  const key = inviteKey(token);
  const raw = await env.VAULT.get(key, "text");
  if (!raw) return;

  try {
    const invite = JSON.parse(raw);
    invite.usedBy = user.id;
    invite.usedEmail = user.email;
    invite.usedAt = new Date().toISOString();
    await updateInviteIndex(env, token, {
      usedBy: user.id,
      usedEmail: user.email,
      usedAt: invite.usedAt,
      status: "used",
    });
    await env.VAULT.put(`used-${key}:${user.id}`, JSON.stringify(invite), {
      expirationTtl: INVITE_TTL_SECONDS,
    });
  } catch {
    // The account was already created; deleting the token is the important part.
  }

  await env.VAULT.delete(key);
}

async function upsertInviteIndex(env, invite) {
  const invites = await readJsonArray(env, INVITE_INDEX_KEY);
  const next = [invite, ...invites.filter((item) => item.token !== invite.token)].slice(0, 100);
  await env.VAULT.put(INVITE_INDEX_KEY, JSON.stringify(next));
}

async function updateInviteIndex(env, token, fields) {
  const invites = await readJsonArray(env, INVITE_INDEX_KEY);
  const index = invites.findIndex((item) => item.token === token);
  if (index === -1) {
    invites.unshift({
      token,
      createdAt: fields.revokedAt || new Date().toISOString(),
      ...fields,
    });
  } else {
    invites[index] = {
      ...invites[index],
      ...fields,
    };
  }
  await env.VAULT.put(INVITE_INDEX_KEY, JSON.stringify(invites.slice(0, 100)));
}

function publicInviteRecord(invite) {
  const status =
    invite.status === "used" || invite.usedAt
      ? "used"
      : invite.status === "revoked" || invite.revokedAt
        ? "revoked"
        : invite.expiresAt && Date.now() >= Date.parse(invite.expiresAt)
          ? "expired"
          : "active";
  return {
    token: invite.token,
    createdAt: invite.createdAt || null,
    expiresAt: invite.expiresAt || null,
    usedAt: invite.usedAt || null,
    usedEmail: invite.usedEmail || null,
    revokedAt: invite.revokedAt || null,
    status,
  };
}

async function listAuditEvents(env) {
  return json({ events: (await readJsonArray(env, AUDIT_INDEX_KEY)).map(publicAuditEvent) });
}

async function recordAuditEvent(env, type, details = {}) {
  try {
    const events = await readJsonArray(env, AUDIT_INDEX_KEY);
    events.unshift({
      id: crypto.randomUUID(),
      type,
      at: new Date().toISOString(),
      details,
    });
    await env.VAULT.put(AUDIT_INDEX_KEY, JSON.stringify(events.slice(0, 100)));
  } catch {
    // Audit logging must never block the primary security action.
  }
}

function publicAuditEvent(event) {
  return {
    id: event.id,
    type: event.type,
    at: event.at,
    details: event.details || {},
  };
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

async function hashAuthSecret(authSecret, salt) {
  const input = new Uint8Array(salt.length + authSecret.length);
  input.set(salt, 0);
  input.set(authSecret, salt.length);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return bytesToBase64(new Uint8Array(digest));
}

async function makeAuthVerifier(env, authSecret, salt) {
  return {
    version: AUTH_VERIFIER_VERSION,
    name: "HMAC-SHA256",
    salt: bytesToBase64(salt),
    hash: await signAuthSecret(env, authSecret, salt),
  };
}

async function verifyAuthSecret(env, user, authSecret) {
  if (user.auth?.version === 3 && user.auth.name === "HMAC-SHA256") {
    if (!isBase64Field(user.auth.salt, 8, 128) || !isBase64Field(user.auth.hash, 32, 32)) {
      return null;
    }

    try {
      const salt = base64ToBytes(user.auth.salt);
      const hash = await signAuthSecret(env, authSecret, salt);
      return timingSafeEqual(hash, user.auth.hash) ? { upgradedUser: null } : null;
    } catch {
      return null;
    }
  }

  if (user.auth?.version === 2 && user.auth.name === "PBKDF2-SHA256") {
    if (
      !Number.isInteger(user.auth.iterations) ||
      user.auth.iterations < 100000 ||
      user.auth.iterations > 1000000 ||
      !isBase64Field(user.auth.salt, 8, 128) ||
      !isBase64Field(user.auth.hash, 32, 32)
    ) {
      return null;
    }

    try {
      const salt = base64ToBytes(user.auth.salt);
      const material = await crypto.subtle.importKey("raw", authSecret, "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations: user.auth.iterations,
          hash: "SHA-256",
        },
        material,
        256,
      );
      if (!timingSafeEqual(bytesToBase64(new Uint8Array(bits)), user.auth.hash)) return null;

      const nextUser = {
        ...user,
        auth: await makeAuthVerifier(env, authSecret, crypto.getRandomValues(new Uint8Array(16))),
        updatedAt: new Date().toISOString(),
      };
      return { upgradedUser: nextUser };
    } catch {
      return null;
    }
  }

  if (!user.authSalt || !user.authHash) return null;

  let authSalt;
  try {
    authSalt = base64ToBytes(user.authSalt);
  } catch {
    return null;
  }

  const authHash = await hashAuthSecret(authSecret, authSalt);
  if (!timingSafeEqual(authHash, user.authHash)) return null;

  const nextUser = {
    ...user,
    auth: await makeAuthVerifier(env, authSecret, crypto.getRandomValues(new Uint8Array(16))),
    updatedAt: new Date().toISOString(),
  };
  delete nextUser.authHash;
  delete nextUser.authSalt;
  return { upgradedUser: nextUser };
}

async function signAuthSecret(env, authSecret, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(getAuthPepper(env)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const payload = new Uint8Array(salt.length + authSecret.length);
  payload.set(salt, 0);
  payload.set(authSecret, salt.length);
  const signature = await crypto.subtle.sign("HMAC", key, payload);
  return bytesToBase64(new Uint8Array(signature));
}

function getAuthPepper(env) {
  return env.AUTH_PEPPER || env.SESSION_SECRET;
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

function normalizeInviteToken(token) {
  const normalized = String(token || "").trim();
  return /^[A-Za-z0-9_-]{24,128}$/.test(normalized) ? normalized : "";
}

function normalizeRevision(revision) {
  if (revision === null || revision === undefined || revision === "") return null;
  return String(revision);
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
  if (!value || typeof value !== "object" || value.version !== 1) return false;
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
