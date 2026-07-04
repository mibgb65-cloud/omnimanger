import {
  LOGIN_COOLDOWN_STEPS_SECONDS,
  LOGIN_COOLDOWN_THRESHOLD,
  LOGIN_FAILURE_TTL_SECONDS,
  base64UrlEncode,
  encoder,
  json,
} from "./core.js";

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

async function getLoginCooldown(env, email) {
  const record = await readLoginFailureRecord(env, email);
  const lockedUntil = Date.parse(record.lockedUntil || "");
  if (!Number.isFinite(lockedUntil) || lockedUntil <= Date.now()) return null;

  return {
    retryAfter: Math.max(1, Math.ceil((lockedUntil - Date.now()) / 1000)),
  };
}

async function recordLoginFailure(env, email) {
  const record = await readLoginFailureRecord(env, email);
  const failures = Number(record.failures || 0) + 1;
  const cooldownSeconds = loginCooldownSeconds(failures);
  const lockedUntil = cooldownSeconds
    ? new Date(Date.now() + cooldownSeconds * 1000).toISOString()
    : null;

  await env.VAULT.put(
    await loginFailureKey(email),
    JSON.stringify({
      failures,
      lockedUntil,
      updatedAt: new Date().toISOString(),
    }),
    { expirationTtl: LOGIN_FAILURE_TTL_SECONDS },
  );

  return { failures, retryAfter: cooldownSeconds };
}

async function clearLoginFailures(env, email) {
  await env.VAULT.delete(await loginFailureKey(email));
}

async function readLoginFailureRecord(env, email) {
  const raw = await env.VAULT.get(await loginFailureKey(email), "text");
  if (!raw) return {};

  try {
    const record = JSON.parse(raw);
    return record && typeof record === "object" ? record : {};
  } catch {
    return {};
  }
}

async function loginFailureKey(email) {
  return `login-failure:${await hashIdentifier(email)}`;
}

function loginCooldownSeconds(failures) {
  if (failures < LOGIN_COOLDOWN_THRESHOLD) return 0;
  const index = Math.min(
    failures - LOGIN_COOLDOWN_THRESHOLD,
    LOGIN_COOLDOWN_STEPS_SECONDS.length - 1,
  );
  return LOGIN_COOLDOWN_STEPS_SECONDS[index];
}

function loginCooldownResponse(retryAfter) {
  return json(
    {
      error: `Too many failed login attempts. Try again in ${retryAfter} seconds.`,
      retryAfter,
    },
    429,
    {
      "Retry-After": String(retryAfter),
    },
  );
}

async function hashIdentifier(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(String(value)));
  return base64UrlEncode(new Uint8Array(digest));
}

export {
  clearLoginFailures,
  enforceRateLimit,
  getLoginCooldown,
  loginCooldownResponse,
  recordLoginFailure,
};
