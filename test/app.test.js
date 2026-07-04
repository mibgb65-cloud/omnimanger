import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const {
  base32ToBytes,
  generatePassword,
  generateTotp,
  isVaultEnvelope,
  normalizeEmail,
  parseTotpInput,
  scorePassword,
} = await import("../public/app.js");

test("base32 and TOTP follow the RFC 6238 SHA-1 vector truncated to 6 digits", async () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(new TextDecoder().decode(base32ToBytes(secret)), "12345678901234567890");
  assert.equal(await generateTotp(secret, 59_000), "287082");
});

test("otpauth URI parser extracts issuer and secret", () => {
  const parsed = parseTotpInput(
    "otpauth://totp/Example:alice@example.com?secret=abcd efgh&issuer=Example",
  );
  assert.equal(parsed.secret, "ABCDEFGH");
  assert.equal(parsed.label, "Example");
});

test("password generator creates a strong mixed password", () => {
  const password = generatePassword(24);
  assert.equal(password.length, 24);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /\d/);
  assert.match(password, /[^A-Za-z0-9]/);
  assert.equal(scorePassword(password).level, "strong");
});

test("email normalization and envelope validation are deterministic", () => {
  assert.equal(normalizeEmail("  USER@Example.COM "), "user@example.com");
  assert.equal(
    isVaultEnvelope({
      version: 1,
      kdf: {
        name: "PBKDF2-SHA256",
        iterations: 310000,
        salt: "AAAAAAAAAAAAAAAAAAAAAA==",
      },
      cipher: {
        name: "AES-GCM",
        iv: "AAAAAAAAAAAAAAAA",
        data: "Y2lwaGVy",
      },
    }),
    true,
  );
  assert.equal(isVaultEnvelope({ version: 1 }), false);
});
