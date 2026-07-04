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

async function saveVault(env, cookie, body = {}) {
  const response = await worker.fetch(
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
  return response;
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

  const userId = await env.VAULT.get("user-email:admin@example.com");
  const storedUser = JSON.parse(await env.VAULT.get(`user:${userId}`));
  assert.equal(storedUser.auth.version, 3);
  assert.equal(storedUser.auth.name, "HMAC-SHA256");
  assert.equal(storedUser.auth.iterations, undefined);
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

test("admin can list revoke invites and inspect audit events", async () => {
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

  const listed = await worker.fetch(
    new Request("https://vault.test/api/admin/invites", {
      headers: { Cookie: cookie },
    }),
    env,
  );
  assert.equal(listed.status, 200);
  const listData = await listed.json();
  assert.equal(listData.invites[0].token, invite.token);
  assert.equal(listData.invites[0].status, "active");

  const revoked = await worker.fetch(
    jsonRequest("/api/admin/invites/revoke", { token: invite.token }, { cookie }),
    env,
  );
  assert.equal(revoked.status, 200);

  const afterRevoke = await worker.fetch(
    new Request("https://vault.test/api/admin/invites", {
      headers: { Cookie: cookie },
    }),
    env,
  );
  const afterRevokeData = await afterRevoke.json();
  assert.equal(afterRevokeData.invites[0].status, "revoked");

  const audit = await worker.fetch(
    new Request("https://vault.test/api/admin/audit", {
      headers: { Cookie: cookie },
    }),
    env,
  );
  assert.equal(audit.status, 200);
  const auditData = await audit.json();
  assert.ok(auditData.events.some((event) => event.type === "invite_created"));
  assert.ok(auditData.events.some((event) => event.type === "invite_revoked"));
});

test("vault PUT rejects stale revisions", async () => {
  const env = makeEnv();
  const registered = await register(env, "admin@example.com", "correct horse battery");
  const cookie = sessionCookie(registered);

  const first = await saveVault(env, cookie);
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
  const first = await saveVault(env, cookie);
  assert.equal(first.status, 200);
  const saved = await first.json();

  const authSecret = await makeAuthSecret("admin@example.com", oldPassword);
  const newAuthSecret = await makeAuthSecret("admin@example.com", newPassword);
  const changed = await worker.fetch(
    jsonRequest(
      "/api/auth/change-password",
      {
        authSecret,
        newAuthSecret,
        envelope: envelope("bmV3LXBhc3N3b3JkLWNpcGhlcg=="),
        baseRevision: saved.revision,
      },
      { cookie },
    ),
    env,
  );
  assert.equal(changed.status, 200);
  const changedData = await changed.json();
  assert.ok(changedData.revision);

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

  const current = await worker.fetch(
    new Request("https://vault.test/api/vault", {
      headers: { Cookie: cookie },
    }),
    env,
  );
  const vault = await current.json();
  assert.equal(vault.revision, changedData.revision);
  assert.equal(vault.envelope.cipher.data, "bmV3LXBhc3N3b3JkLWNpcGhlcg==");
});

test("logout all revokes existing session cookies", async () => {
  const env = makeEnv();
  const password = "correct horse battery";
  const registered = await register(env, "admin@example.com", password);
  const firstCookie = sessionCookie(registered);
  const authSecret = await makeAuthSecret("admin@example.com", password);
  const secondLogin = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret }),
    env,
  );
  assert.equal(secondLogin.status, 200);
  const secondCookie = sessionCookie(secondLogin);

  const revoked = await worker.fetch(
    new Request("https://vault.test/api/auth/logout-all", {
      method: "POST",
      headers: { Cookie: secondCookie },
    }),
    env,
  );
  assert.equal(revoked.status, 200);

  const staleVault = await worker.fetch(
    new Request("https://vault.test/api/vault", {
      headers: { Cookie: firstCookie },
    }),
    env,
  );
  assert.equal(staleVault.status, 401);
});

test("change password rejects stale revisions without changing login secret", async () => {
  const env = makeEnv();
  const oldPassword = "correct horse battery";
  const newPassword = "new correct horse battery";
  const registered = await register(env, "admin@example.com", oldPassword);
  const cookie = sessionCookie(registered);

  const first = await saveVault(env, cookie);
  assert.equal(first.status, 200);
  const firstSaved = await first.json();

  const second = await saveVault(env, cookie, {
    data: "c2Vjb25kLWNpcGhlcg==",
    baseRevision: firstSaved.revision,
  });
  assert.equal(second.status, 200);

  const authSecret = await makeAuthSecret("admin@example.com", oldPassword);
  const newAuthSecret = await makeAuthSecret("admin@example.com", newPassword);
  const stale = await worker.fetch(
    jsonRequest(
      "/api/auth/change-password",
      {
        authSecret,
        newAuthSecret,
        envelope: envelope("c3RhbGUtY2lwaGVy"),
        baseRevision: firstSaved.revision,
      },
      { cookie },
    ),
    env,
  );
  assert.equal(stale.status, 409);

  const oldLogin = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret }),
    env,
  );
  assert.equal(oldLogin.status, 200);

  const newLogin = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: newAuthSecret }),
    env,
  );
  assert.equal(newLogin.status, 401);
});

test("login failures trigger cooldown and successful login clears failures", async () => {
  const env = makeEnv();
  const password = "correct horse battery";
  await register(env, "admin@example.com", password);
  const correctAuthSecret = await makeAuthSecret("admin@example.com", password);
  const wrongAuthSecret = await makeAuthSecret("admin@example.com", "wrong horse battery");

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const failed = await worker.fetch(
      jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: wrongAuthSecret }),
      env,
    );
    assert.equal(failed.status, 401);
  }

  const cleared = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: correctAuthSecret }),
    env,
  );
  assert.equal(cleared.status, 200);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const failed = await worker.fetch(
      jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: wrongAuthSecret }),
      env,
    );
    assert.equal(failed.status, 401);
  }

  const locked = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: wrongAuthSecret }),
    env,
  );
  assert.equal(locked.status, 429);
  assert.equal(locked.headers.get("Retry-After"), "30");
  const data = await locked.json();
  assert.equal(data.retryAfter, 30);

  const stillLocked = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret: correctAuthSecret }),
    env,
  );
  assert.equal(stillLocked.status, 429);
});

test("legacy v2 auth verifier upgrades after successful login", async () => {
  const env = makeEnv();
  await seedV2User(env, "admin@example.com", "correct horse battery");
  const authSecret = await makeAuthSecret("admin@example.com", "correct horse battery");

  const response = await worker.fetch(
    jsonRequest("/api/auth/login", { email: "admin@example.com", authSecret }),
    env,
  );
  assert.equal(response.status, 200);

  const userId = await env.VAULT.get("user-email:admin@example.com");
  const storedUser = JSON.parse(await env.VAULT.get(`user:${userId}`));
  assert.equal(storedUser.auth.version, 3);
  assert.equal(storedUser.auth.name, "HMAC-SHA256");
  assert.equal(storedUser.auth.iterations, undefined);
});
