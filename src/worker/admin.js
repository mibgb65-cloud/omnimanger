import {
  AUDIT_INDEX_KEY,
  INVITE_INDEX_KEY,
  INVITE_TTL_SECONDS,
  MAX_AUTH_BYTES,
  REGISTRATION_SETTING_KEY,
  base64UrlEncode,
  getAdminEmail,
  inviteKey,
  json,
  logSecurityEvent,
  normalizeInviteToken,
  readJsonArray,
  readJsonBody,
} from "./core.js";

const AUDIT_EVENT_SCHEMA_VERSION = 1;

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
  logSecurityEvent("admin_registration_setting_changed", {
    registrationOpen: body.registrationOpen,
  });
  await recordAuditEvent(env, "admin_registration_setting_changed", {
    registrationOpen: body.registrationOpen,
  });
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
      schemaVersion: AUDIT_EVENT_SCHEMA_VERSION,
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
    schemaVersion: event.schemaVersion || AUDIT_EVENT_SCHEMA_VERSION,
    id: event.id,
    type: event.type,
    at: event.at,
    details: event.details || {},
  };
}

export {
  canUseInvite,
  consumeInvite,
  createInvite,
  getAdminSettings,
  getRegistrationOpen,
  listAuditEvents,
  listInvites,
  putAdminSettings,
  recordAuditEvent,
  revokeInvite,
};
