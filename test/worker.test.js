import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const worker = (await import("../src/index.js")).default;
const { makeAuthSecret } = await import("../public/app.js");

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
  const response = await worker.fetch(jsonRequest("/api/auth/register", { email, authSecret, ...extra }), env);
  return response;
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

test("admin can register while public registration is closed", async () => {
  const env = makeEnv();
  const response = await register(env, "ADMIN@example.com", "correct horse battery");
  assert.equal(response.status, 200);

  const cookie = sessionCookie(response);
  const me = await worker.fetch(
    new Request("https://vault.test/api/auth/me", {
      headers: { Cookie: cookie },
    }),
    env,
  );
  const data = await me.json();
  assert.equal(data.user.email, "admin@example.com");
  assert.equal(data.user.isAdmin, true);
});

test("admin invite allows one closed-registration signup", async () => {
  const env = makeEnv();
  const admin = await register(env, "admin@example.com", "correct horse battery");
  const cookie = sessionCookie(admin);

  const inviteResponse = await worker.fetch(
    new Request("https://vault.test/api/admin/invites", {
      method: "POST",
      headers: { Cookie: cookie },
    }),
    env,
  );
  assert.equal(inviteResponse.status, 200);
  const invite = await inviteResponse.json();
  assert.match(invite.token, /^[A-Za-z0-9_-]+$/);

  const user = await register(env, "user@example.com", "correct horse battery", { inviteToken: invite.token });
  assert.equal(user.status, 200);

  const reused = await register(env, "other@example.com", "correct horse battery", { inviteToken: invite.token });
  assert.equal(reused.status, 403);
});

test("vault PUT rejects stale revisions", async () => {
  const env = makeEnv();
  const registered = await register(env, "admin@example.com", "correct horse battery");
  const cookie = sessionCookie(registered);

  const first = await worker.fetch(
    jsonRequest("/api/vault", { envelope: envelope(), baseRevision: null }, { cookie, method: "PUT" }),
    env,
  );
  assert.equal(first.status, 200);
  const saved = await first.json();
  assert.ok(saved.revision);

  const stale = await worker.fetch(
    jsonRequest("/api/vault", { envelope: envelope("bmV3IGNpcGhlcg=="), baseRevision: "stale" }, { cookie, method: "PUT" }),
    env,
  );
  assert.equal(stale.status, 409);

  const current = await worker.fetch(
    new Request("https://vault.test/api/vault", {
      headers: { Cookie: cookie },
    }),
    env,
  );
  const data = await current.json();
  assert.equal(data.revision, saved.revision);
});

test("change password invalidates old login and accepts new login", async () => {
  const env = makeEnv();
  const oldPassword = "correct horse battery";
  const newPassword = "new correct horse battery";
  const registered = await register(env, "admin@example.com", oldPassword);
  const cookie = sessionCookie(registered);

  const authSecret = await makeAuthSecret("admin@example.com", oldPassword);
  const newAuthSecret = await makeAuthSecret("admin@example.com", newPassword);
  const changed = await worker.fetch(
    jsonRequest("/api/auth/change-password", { authSecret, newAuthSecret }, { cookie }),
    env,
  );
  assert.equal(changed.status, 200);

  const oldLogin = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret }),
    env,
  );
  assert.equal(oldLogin.status, 401);

  const newLogin = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: newAuthSecret }),
    env,
  );
  assert.equal(newLogin.status, 200);
});
