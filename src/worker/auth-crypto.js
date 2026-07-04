import {
  AUTH_VERIFIER_VERSION,
  base64ToBytes,
  bytesToBase64,
  encoder,
  timingSafeEqual,
} from "./core.js";

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
    return verifyCurrentAuthSecret(env, user, authSecret);
  }

  if (user.auth?.version === 2 && user.auth.name === "PBKDF2-SHA256") {
    return verifyLegacyPbkdf2Secret(env, user, authSecret);
  }

  return verifyLegacyShaSecret(env, user, authSecret);
}

async function verifyCurrentAuthSecret(env, user, authSecret) {
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

async function verifyLegacyPbkdf2Secret(env, user, authSecret) {
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

    return {
      upgradedUser: {
        ...user,
        auth: await makeAuthVerifier(env, authSecret, crypto.getRandomValues(new Uint8Array(16))),
        updatedAt: new Date().toISOString(),
      },
    };
  } catch {
    return null;
  }
}

async function verifyLegacyShaSecret(env, user, authSecret) {
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

function isBase64Field(value, minBytes, maxBytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  if (value.length % 4 !== 0) return false;

  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const decodedLength = Math.floor((value.length * 3) / 4) - padding;
  return decodedLength >= minBytes && decodedLength <= maxBytes;
}

export { decodeAuthSecret, hashAuthSecret, makeAuthVerifier, verifyAuthSecret };
