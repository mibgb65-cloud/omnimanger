import {
  MAX_VAULT_BYTES,
  isVaultEnvelope,
  json,
  logSecurityEvent,
  normalizeRevision,
  readJsonBody,
  recordUserActivity,
  vaultKey,
} from "./core.js";

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
  const baseRevision = isVaultEnvelope(body)
    ? request.headers.get("If-Match")
    : normalizeRevision(body?.baseRevision);

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

export { getVault, putVault };
