import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const {
  addPasswordHistoryEntry,
  analyzeVaultSecurity,
  base32ToBytes,
  entryHasRisk,
  entryMatchesSearch,
  formatImportConfirmation,
  formatMasterPasswordStrength,
  generatePassword,
  generateTotp,
  getEntryRiskScore,
  getRiskEntryCount,
  getVaultHealth,
  getVaultOverview,
  getVaultTags,
  isBackupStale,
  isVaultEnvelope,
  makeAuthSecret,
  mergeImportedVault,
  normalizeCustomFields,
  normalizeEmail,
  normalizeVault,
  normalizePasswordLength,
  normalizePasswordHistory,
  normalizePasswordOptions,
  parseSearchQuery,
  parseEntryTags,
  parseExternalVaultImport,
  parseTotpInput,
  scorePassword,
  summarizeBackupVerification,
  summarizeImportDiff,
  updateVaultTag,
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
      schemaVersion: 1,
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
  assert.equal(
    isVaultEnvelope({
      schemaVersion: 99,
      version: 1,
      kdf: { name: "PBKDF2-SHA256", iterations: 310000, salt: "AAAAAAAAAAAAAAAAAAAAAA==" },
      cipher: { name: "AES-GCM", iv: "AAAAAAAAAAAAAAAA", data: "Y2lwaGVy" },
    }),
    false,
  );
});

test("auth secret derivation and vault normalization are shared runtime contracts", async () => {
  const authSecret = await makeAuthSecret("  USER@Example.COM ", "correct horse battery");
  assert.equal(authSecret, await makeAuthSecret("user@example.com", "correct horse battery"));
  assert.notEqual(authSecret, await makeAuthSecret("user@example.com", "different horse battery"));
  assert.match(authSecret, /^[A-Za-z0-9+/]+={0,2}$/);
  assert.throws(() => normalizeVault(null), /保险箱内容无效/);
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

test("tag manager helpers rename merge and delete tags", () => {
  const vault = {
    entries: [
      { id: "1", name: "Main", tags: "work google" },
      { id: "2", name: "Backup", tags: "work personal" },
      { id: "3", name: "Solo", tags: "personal" },
    ],
  };

  assert.deepEqual(updateVaultTag(vault, "work", "personal"), { changed: 2 });
  assert.deepEqual(vault.entries.map((entry) => entry.tags), ["personal google", "personal", "personal"]);

  assert.deepEqual(updateVaultTag(vault, "google", ""), { changed: 1 });
  assert.deepEqual(vault.entries.map((entry) => entry.tags), ["personal", "personal", "personal"]);

  assert.deepEqual(updateVaultTag(vault, "missing", "x"), { changed: 0 });
});

test("custom fields normalize and participate in search", () => {
  const fields = normalizeCustomFields([
    { name: "会员号", value: 0 },
    { label: "API Key", value: "secret-token" },
    { label: " ", value: "" },
  ]);
  assert.equal(fields.length, 2);
  assert.equal(fields[0].label, "会员号");
  assert.equal(fields[0].value, "0");

  const vault = {
    entries: [
      {
        id: "1",
        name: "Internal Portal",
        login: "ops@example.com",
        password: "Stronger-Password-2026!",
        customFields: fields,
      },
    ],
  };
  assert.equal(entryMatchesSearch(vault.entries[0], "secret-token", vault), true);
  assert.equal(entryMatchesSearch(vault.entries[0], "has:custom", vault), true);
  assert.equal(entryMatchesSearch(vault.entries[0], "missing:custom", vault), false);
  assert.equal(normalizeVault(vault).entries[0].customFields.length, 2);
});

test("favorite and last used metadata normalize and search", () => {
  const vault = normalizeVault({
    entries: [
      {
        name: "Pinned",
        favorite: true,
        lastUsedAt: "2026-07-05T08:00:00.000Z",
      },
      { name: "Regular" },
    ],
  });

  assert.equal(vault.entries[0].favorite, true);
  assert.equal(vault.entries[0].lastUsedAt, "2026-07-05T08:00:00.000Z");
  assert.equal(vault.entries[1].favorite, false);
  assert.equal(entryMatchesSearch(vault.entries[0], "has:favorite", vault), true);
  assert.equal(entryMatchesSearch(vault.entries[1], "missing:favorite", vault), true);
});

test("password history keeps recent unique old passwords", () => {
  let history = [];
  for (let index = 1; index <= 6; index += 1) {
    history = addPasswordHistoryEntry(history, `old-pass-${index}`, `2026-07-0${index}T00:00:00.000Z`);
  }

  assert.equal(history.length, 5);
  assert.deepEqual(
    history.map((item) => item.password),
    ["old-pass-6", "old-pass-5", "old-pass-4", "old-pass-3", "old-pass-2"],
  );

  history = addPasswordHistoryEntry(history, "old-pass-4", "2026-07-07T00:00:00.000Z");
  assert.deepEqual(
    history.map((item) => item.password),
    ["old-pass-4", "old-pass-6", "old-pass-5", "old-pass-3", "old-pass-2"],
  );
  assert.equal(normalizePasswordHistory([{ password: "" }, { password: "  kept  " }]).length, 1);
  assert.equal(normalizeVault({ entries: [{ name: "A", passwordHistory: history }] }).entries[0].passwordHistory.length, 5);
});

test("advanced search filters by tags fields risk and missing secrets", () => {
  const vault = {
    entries: [
      {
        id: "1",
        name: "Google Main",
        login: "main@gmail.com",
        tags: "work google",
        password: "Stronger-Password-2026!",
        totpSecret: "JBSWY3DPEHPK3PXP",
        recoveryCodes: "123",
      },
      { id: "2", name: "Old Mail", login: "old@example.com", tags: "personal", password: "abc", totpSecret: "", recoveryCodes: "" },
    ],
  };

  const parsed = parseSearchQuery("tag:work login:gmail has:2fa google");
  assert.deepEqual(parsed.tags, ["work"]);
  assert.equal(entryMatchesSearch(vault.entries[0], parsed, vault), true);
  assert.equal(entryMatchesSearch(vault.entries[1], parsed, vault), false);
  assert.equal(entryMatchesSearch(vault.entries[1], "risk:true missing:recovery", vault), true);
  assert.equal(entryMatchesSearch(vault.entries[0], "risk:false has:recovery", vault), true);
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

test("backup verification summary reports diff and timestamps", () => {
  const current = {
    entries: [
      { id: "1", name: "Main", login: "main@example.com" },
      { id: "2", name: "Old", login: "" },
    ],
  };
  const backup = {
    updatedAt: "2026-07-02T11:00:00.000Z",
    entries: [
      { id: "3", name: "Main copy", login: "main@example.com" },
      { id: "4", name: "Backup only", login: "backup@example.com" },
    ],
  };

  assert.deepEqual(summarizeBackupVerification(current, backup), {
    currentTotal: 2,
    incomingTotal: 2,
    added: 1,
    matched: 1,
    removed: 1,
    backupUpdatedAt: "2026-07-02T11:00:00.000Z",
    addedEntries: ["Backup only"],
    matchedEntries: ["Main copy"],
    removedEntries: ["Old"],
  });
});

test("import confirmation text makes merge and replace consequences explicit", () => {
  const diff = { currentTotal: 3, incomingTotal: 2, added: 1, matched: 1, removed: 2 };

  assert.match(formatImportConfirmation("backup.json", diff, "merge"), /当前独有 2 个会保留/);
  assert.match(formatImportConfirmation("backup.json", diff, "replace"), /当前 3 个账号会被替换/);
});

test("merge import keeps current unmatched accounts", () => {
  const current = {
    createdAt: "2026-01-01T00:00:00.000Z",
    entries: [
      { id: "1", name: "Main local", login: "main@example.com", password: "old password" },
      { id: "2", name: "Local only", login: "local@example.com", password: "local password" },
    ],
  };
  const incoming = {
    entries: [
      { id: "3", name: "Main backup", login: "main@example.com", password: "backup password" },
      { id: "4", name: "Backup only", login: "backup@example.com", password: "backup only password" },
    ],
  };

  const merged = mergeImportedVault(current, incoming);
  assert.deepEqual(
    merged.entries.map((entry) => entry.name),
    ["Main backup", "Backup only", "Local only"],
  );
  assert.equal(merged.entries.find((entry) => entry.login === "main@example.com").password, "backup password");
});

test("external import parses Bitwarden CSV exports", () => {
  const csv = [
    "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp",
    'Work,,login,GitHub,"Main account",,https://github.com,alice@example.com,S3cret!,"otpauth://totp/GitHub:alice?secret=abcd efgh&issuer=GitHub"',
  ].join("\n");

  const vault = parseExternalVaultImport(csv, "bitwarden.csv");
  assert.equal(vault.importSource, "bitwarden");
  assert.equal(vault.entries.length, 1);
  assert.equal(vault.entries[0].name, "GitHub");
  assert.equal(vault.entries[0].login, "alice@example.com");
  assert.equal(vault.entries[0].password, "S3cret!");
  assert.equal(vault.entries[0].totpSecret, "ABCDEFGH");
  assert.match(vault.entries[0].tags, /imported/);
  assert.match(vault.entries[0].notes, /https:\/\/github.com/);
});

test("external import parses browser CSV exports", () => {
  const csv = [
    "name,url,username,password,note",
    "Example,https://example.com,me@example.com,browser-pass,from chrome",
  ].join("\n");

  const vault = parseExternalVaultImport(csv, "Chrome Passwords.csv");
  assert.equal(vault.importSource, "browser");
  assert.equal(vault.entries[0].name, "Example");
  assert.equal(vault.entries[0].login, "me@example.com");
  assert.equal(vault.entries[0].password, "browser-pass");
  assert.match(vault.entries[0].notes, /from chrome/);
  assert.match(vault.entries[0].notes, /https:\/\/example.com/);
});

test("external import parses Bitwarden and 1Password JSON exports", () => {
  const bitwarden = parseExternalVaultImport(
    JSON.stringify({
      items: [
        {
          name: "Mail",
          notes: "primary mailbox",
          fields: [{ name: "recovery", value: "offline code" }],
          login: {
            username: "mail@example.com",
            password: "mail-pass",
            totp: "JBSWY3DPEHPK3PXP",
            uris: [{ uri: "https://mail.example.com" }],
          },
        },
      ],
    }),
    "bitwarden.json",
  );
  assert.equal(bitwarden.importSource, "bitwarden");
  assert.deepEqual(bitwarden.entries[0].customFields.map((field) => [field.label, field.value]), [
    ["recovery", "offline code"],
  ]);

  const onePassword = parseExternalVaultImport(
    JSON.stringify({
      accounts: [
        {
          vaults: [
            {
              items: [
                {
                  overview: { title: "AWS", urls: [{ url: "https://aws.amazon.com" }] },
                  details: {
                    notesPlain: "root account",
                    loginFields: [
                      { designation: "username", value: "root@example.com" },
                      { designation: "password", value: { concealed: "aws-pass" } },
                    ],
                    sections: [
                      { fields: [{ label: "one-time password", value: "otpauth://totp/AWS?secret=jbsw y3dp" }] },
                    ],
                  },
                },
              ],
            },
          ],
        },
      ],
    }),
    "1password.json",
  );
  assert.equal(onePassword.importSource, "1password");
  assert.equal(onePassword.entries[0].name, "AWS");
  assert.equal(onePassword.entries[0].login, "root@example.com");
  assert.equal(onePassword.entries[0].password, "aws-pass");
  assert.equal(onePassword.entries[0].totpSecret, "JBSWY3DP");
  assert.equal(onePassword.entries[0].customFields.length, 0);
});

test("external import rejects files without account fields", () => {
  assert.throws(() => parseExternalVaultImport("folder\nWork", "unknown.csv"), /没有找到可导入的账号/);
});

test("entry risk score prioritizes missing and duplicated secrets", () => {
  const vault = {
    entries: [
      {
        id: "safe",
        name: "Safe",
        password: "Stronger-Password-2026!",
        totpSecret: "JBSWY3DPEHPK3PXP",
        recoveryCodes: "123456",
      },
      { id: "risky", name: "Risky", password: "", totpSecret: "", recoveryCodes: "" },
      { id: "duplicate", name: "Duplicate", password: "abc", totpSecret: "", recoveryCodes: "" },
      { id: "duplicate-2", name: "Duplicate 2", password: "abc", totpSecret: "JBSWY3DPEHPK3PXP", recoveryCodes: "" },
    ],
  };

  assert.ok(getEntryRiskScore(vault.entries[1], vault) > getEntryRiskScore(vault.entries[0], vault));
  assert.ok(getEntryRiskScore(vault.entries[2], vault) > getEntryRiskScore(vault.entries[0], vault));
  assert.equal(entryHasRisk(vault.entries[0], vault), false);
  assert.equal(entryHasRisk(vault.entries[1], vault), true);
  assert.equal(getRiskEntryCount(vault), 3);
});

test("vault overview summarizes counts backup and local status", () => {
  const vault = {
    entries: [
      {
        id: "safe",
        name: "Safe",
        password: "Stronger-Password-2026!",
        totpSecret: "JBSWY3DPEHPK3PXP",
        recoveryCodes: "123456",
      },
      { id: "risky", name: "Risky", password: "", totpSecret: "", recoveryCodes: "" },
    ],
  };

  const overview = getVaultOverview(vault, new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), true, 15);
  assert.equal(overview.totalEntries, 2);
  assert.equal(overview.riskEntries, 1);
  assert.equal(overview.backupStale, false);
  assert.equal(overview.localCacheLabel, "已关闭");
  assert.equal(overview.autoLockLabel, "15 分钟");
  assert.equal(overview.health.score < 100, true);

  const health = getVaultHealth(vault, "");
  assert.equal(health.reasons.some((reason) => reason.includes("备份")), true);
  assert.equal(["warning", "danger"].includes(health.level), true);
});

test("master password strength copy gives actionable feedback", () => {
  assert.match(formatMasterPasswordStrength("short"), /弱密码/);
  assert.match(formatMasterPasswordStrength("LongerPassphrase2026!"), /强密码/);
});

test("backup stale helper flags missing or old exports", () => {
  assert.equal(isBackupStale(""), true);
  assert.equal(isBackupStale(new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString()), true);
  assert.equal(isBackupStale(new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString()), false);
});
