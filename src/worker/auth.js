import {
  EMAIL_PATTERN,
  MAX_AUTH_BYTES,
  MAX_VAULT_BYTES,
  RATE_LIMITS,
  getAdminEmail,
  getClientIp,
  getUserByEmail,
  getUserById,
  isVaultEnvelope,
  json,
  logSecurityEvent,
  normalizeEmail,
  normalizeInviteToken,
  normalizeRevision,
  publicUser,
  readJsonBody,
  recordUserActivity,
  userEmailKey,
  userKey,
  vaultKey,
} from "./core.js";
import { canUseInvite, consumeInvite, getRegistrationOpen, recordAuditEvent } from "./admin.js";
import { decodeAuthSecret, makeAuthVerifier, verifyAuthSecret } from "./auth-crypto.js";
import {
  clearLoginFailures,
  enforceRateLimit,
  getLoginCooldown,
  loginCooldownResponse,
  recordLoginFailure,
} from "./rate-limit.js";
import { createSessionResponse, createSessionVersion, makeExpiredSessionCookie } from "./session.js";

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
  const inviteAllowed = !registrationOpen && !isAdminRegistration
    ? await canUseInvite(env, inviteToken)
    : false;

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

  logSecurityEvent("user_registered", {
    userId: user.id,
    role: user.role,
    invited: inviteAllowed,
  });
  await recordAuditEvent(env, "user_registered", {
    userId: user.id,
    role: user.role,
    invited: inviteAllowed,
  });
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

  const cooldown = await getLoginCooldown(env, email);
  if (cooldown) return loginCooldownResponse(cooldown.retryAfter);

  const user = await getUserByEmail(env, email);
  if (!user) {
    const failure = await recordLoginFailure(env, email);
    logSecurityEvent("login_failed", { reason: "unknown_user" });
    await recordAuditEvent(env, "login_failed", { reason: "unknown_user" });
    if (failure.retryAfter) return loginCooldownResponse(failure.retryAfter);
    return json({ error: "Email or password is invalid." }, 401);
  }

  const verified = await verifyAuthSecret(env, user, authSecret);
  if (!verified) {
    const failure = await recordLoginFailure(env, email);
    logSecurityEvent("login_failed", { reason: "bad_secret", userId: user.id });
    await recordAuditEvent(env, "login_failed", { reason: "bad_secret", userId: user.id });
    if (failure.retryAfter) return loginCooldownResponse(failure.retryAfter);
    return json({ error: "Email or password is invalid." }, 401);
  }

  await clearLoginFailures(env, email);
  if (verified.upgradedUser) {
    await env.VAULT.put(userKey(verified.upgradedUser.id), JSON.stringify(verified.upgradedUser));
  }

  await recordUserActivity(env, verified.upgradedUser || user, {
    lastLoginAt: new Date().toISOString(),
  });
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

async function verifyCurrentPassword(request, env, user) {
  const body = await readJsonBody(request, MAX_AUTH_BYTES);
  if (body instanceof Response) return body;

  const authSecret = decodeAuthSecret(body.authSecret);
  if (!authSecret) {
    return json({ error: "Auth secret is invalid." }, 400);
  }

  const verified = await verifyAuthSecret(env, user, authSecret);
  if (!verified) {
    logSecurityEvent("reauth_failed", { userId: user.id });
    await recordAuditEvent(env, "reauth_failed", { userId: user.id });
    return json({ error: "Current password is invalid." }, 401);
  }

  if (verified.upgradedUser) {
    await env.VAULT.put(userKey(verified.upgradedUser.id), JSON.stringify(verified.upgradedUser));
  }

  logSecurityEvent("reauth_succeeded", { userId: user.id });
  return json({ ok: true });
}

export {
  changePassword,
  loginUser,
  logoutAllSessions,
  logoutUser,
  registerUser,
  verifyCurrentPassword,
};
