const MAX_BODY_BYTES = 1024 * 1024;
const VAULT_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{5,79}$/;

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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env, url);
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
        "Access-Control-Allow-Headers": "authorization, content-type",
        "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
        ...SECURITY_HEADERS,
      },
    });
  }

  if (!env.VAULT) {
    return json({ error: "KV binding VAULT is not configured." }, 500);
  }

  const match = url.pathname.match(/^\/api\/vault\/([^/]+)$/);
  if (!match) {
    return json({ error: "Not found." }, 404);
  }

  const vaultId = decodeURIComponent(match[1]);
  if (!isValidVaultId(vaultId)) {
    return json({ error: "Vault id must be 6-80 letters, numbers, dashes, or underscores." }, 400);
  }

  const vaultKey = `vault:${vaultId}`;
  const providedToken = getBearerToken(request);
  if (!providedToken) {
    return json({ error: "Unauthorized." }, 401);
  }

  if (request.method === "GET") {
    const stored = await env.VAULT.getWithMetadata(vaultKey, "text");
    if (!stored.value) {
      return json({ envelope: null, updatedAt: null });
    }

    if (!(await isAuthorized(stored.metadata, providedToken))) {
      return json({ error: "Unauthorized." }, 401);
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

  if (request.method === "PUT") {
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > MAX_BODY_BYTES) {
      return json({ error: "Vault payload is too large." }, 413);
    }

    const body = await request.text();
    if (body.length > MAX_BODY_BYTES) {
      return json({ error: "Vault payload is too large." }, 413);
    }

    let envelope;
    try {
      envelope = JSON.parse(body);
    } catch {
      return json({ error: "Body must be JSON." }, 400);
    }

    if (!isVaultEnvelope(envelope)) {
      return json({ error: "Body is not a valid encrypted vault envelope." }, 400);
    }

    const existing = await env.VAULT.getWithMetadata(vaultKey, "text");
    if (existing.value && !(await isAuthorized(existing.metadata, providedToken))) {
      return json({ error: "Unauthorized." }, 401);
    }

    const updatedAt = new Date().toISOString();
    const authHash = existing.metadata?.authHash || (await sha256Base64(providedToken));
    envelope.updatedAt = updatedAt;
    await env.VAULT.put(vaultKey, JSON.stringify(envelope), {
      metadata: { authHash, updatedAt },
    });

    return json({ ok: true, updatedAt });
  }

  return json({ error: "Not found." }, 404);
}

function getBearerToken(request) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) {
    return "";
  }

  return header.slice("Bearer ".length).trim();
}

async function isAuthorized(metadata, providedToken) {
  if (!metadata?.authHash) return false;
  const providedHash = await sha256Base64(providedToken);
  return timingSafeEqual(metadata.authHash, providedHash);
}

async function sha256Base64(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64(new Uint8Array(digest));
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

function isValidVaultId(vaultId) {
  return VAULT_ID_PATTERN.test(vaultId);
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
      typeof value.cipher.data === "string"
  );
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
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
