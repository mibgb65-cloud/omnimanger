import { webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const worker = (await import("../../src/index.js")).default;

class MemoryKV {
  constructor() {
    this.values = new Map();
    this.metadata = new Map();
  }

  async get(key) {
    return this.values.get(key) ?? null;
  }

  async getWithMetadata(key) {
    return {
      value: this.values.get(key) ?? null,
      metadata: this.metadata.get(key) ?? null,
    };
  }

  async put(key, value, options = {}) {
    this.values.set(key, value);
    this.metadata.set(key, options.metadata || null);
  }

  async delete(key) {
    this.values.delete(key);
    this.metadata.delete(key);
  }
}

function makeEnv() {
  return {
    VAULT: new MemoryKV(),
    SESSION_SECRET: "test-session-secret-that-is-long-enough",
    ADMIN_EMAIL: "admin@example.com",
    ASSETS: {
      fetch: async () => new Response("ok"),
    },
  };
}

function jsonRequest(path, body, { cookie = "", method = "POST" } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  return new Request(`https://vault.test${path}`, {
    method,
    headers,
    body: JSON.stringify(body),
  });
}

async function register(env, email, password, extra = {}) {
  const authSecret = await makeAuthSecret(email, password);
  return worker.fetch(jsonRequest("/api/auth/register", { email, authSecret, ...extra }), env);
}

async function makeAuthSecret(email, password) {
  const app = await import("../../public/app.js");
  return app.makeAuthSecret(email, password);
}

function sessionCookie(response) {
  return response.headers.get("set-cookie").split(";")[0];
}

function envelope(data = "Y2lwaGVydGV4dA==") {
  return {
    version: 1,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations: 310000,
      salt: "AAAAAAAAAAAAAAAAAAAAAA==",
    },
    cipher: {
      name: "AES-GCM",
      iv: "AAAAAAAAAAAAAAAA",
      data,
    },
  };
}

async function saveVault(env, cookie, body = {}) {
  return worker.fetch(
    jsonRequest(
      "/api/vault",
      {
        envelope: envelope(body.data),
        baseRevision: body.baseRevision ?? null,
      },
      { cookie, method: "PUT" },
    ),
    env,
  );
}

async function seedV2User(env, email, password) {
  const normalizedEmail = email.toLowerCase();
  const authSecret = await makeAuthSecret(normalizedEmail, password);
  const authSecretBytes = Uint8Array.from(Buffer.from(authSecret, "base64"));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", authSecretBytes, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 120000,
      hash: "SHA-256",
    },
    material,
    256,
  );
  const user = {
    id: crypto.randomUUID(),
    email: normalizedEmail,
    role: "admin",
    auth: {
      version: 2,
      name: "PBKDF2-SHA256",
      iterations: 120000,
      salt: Buffer.from(salt).toString("base64"),
      hash: Buffer.from(bits).toString("base64"),
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  await env.VAULT.put(`user:${user.id}`, JSON.stringify(user));
  await env.VAULT.put(`user-email:${normalizedEmail}`, user.id);
  return user;
}

export {
  envelope,
  jsonRequest,
  makeAuthSecret,
  makeEnv,
  register,
  saveVault,
  seedV2User,
  sessionCookie,
  worker,
};
