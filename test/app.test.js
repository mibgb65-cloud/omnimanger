import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const {
  analyzeVaultSecurity,
  base32ToBytes,
  generatePassword,
  generateTotp,
  getVaultTags,
  isVaultEnvelope,
  normalizeEmail,
  normalizePasswordLength,
  normalizePasswordOptions,
  parseEntryTags,
  parseTotpInput,
  scorePassword,
  summarizeImportDiff,
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

test("password generator supports safer UI options", () => {
  assert.equal(normalizePasswordLength(4), 12);
  assert.equal(normalizePasswordLength(128), 64);
  assert.deepEqual(normalizePasswordOptions({ length: 18, symbols: false, readable: true }), {
    length: 18,
    symbols: false,
    readable: true,
  });

  const password = generatePassword({ length: 18, symbols: false, readable: true });
  assert.equal(password.length, 18);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /\d/);
  assert.doesNotMatch(password, /[^A-Za-z0-9]/);
  assert.doesNotMatch(password, /[IOl01]/);
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

test("tag and security analysis helpers summarize vault issues", () => {
  const vault = {
    entries: [
      { id: "1", name: "Main", login: "main@example.com", tags: "work, google", password: "abc", totpSecret: "", recoveryCodes: "" },
      { id: "2", name: "Backup", login: "backup@example.com", tags: "work personal", password: "abc", totpSecret: "JBSWY3DPEHPK3PXP", recoveryCodes: "123" },
      { id: "3", name: "Empty", login: "", tags: "", password: "", totpSecret: "", recoveryCodes: "" },
    ],
  };

  assert.deepEqual(parseEntryTags("work, personal  google"), ["work", "personal", "google"]);
  assert.deepEqual(getVaultTags(vault), ["google", "personal", "work"]);

  const report = analyzeVaultSecurity(vault);
  assert.equal(report.totalEntries, 3);
  assert.equal(report.emptyPasswords.length, 1);
  assert.equal(report.weakPasswords.length, 2);
  assert.equal(report.duplicatePasswordGroups.length, 1);
  assert.equal(report.missingTotp.length, 2);
  assert.equal(report.missingRecovery.length, 2);
});

test("import diff summarizes added matched and removed accounts", () => {
  const current = {
    entries: [
      { id: "1", name: "Main", login: "main@example.com" },
      { id: "2", name: "Old", login: "" },
    ],
  };
  const incoming = {
    entries: [
      { id: "3", name: "Main copy", login: "main@example.com" },
      { id: "4", name: "New", login: "new@example.com" },
    ],
  };

  assert.deepEqual(summarizeImportDiff(current, incoming), {
    currentTotal: 2,
    incomingTotal: 2,
    added: 1,
    matched: 1,
    removed: 1,
  });
});
