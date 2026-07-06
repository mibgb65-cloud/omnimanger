import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const { getVaultOverview, normalizeVault } = await import("../public/app.js");

test("vault metadata keeps backend backup timestamp and empty state", () => {
  const recentBackupAt = "2026-07-06T10:00:00.000Z";
  const normalized = normalizeVault({ lastBackupAt: recentBackupAt, entries: [] });
  const overview = getVaultOverview(normalized);

  assert.equal(normalized.lastBackupAt, recentBackupAt);
  assert.equal(normalizeVault({ lastBackupAt: "not-a-date", entries: [] }).lastBackupAt, "");
  assert.equal(overview.totalEntries, 0);
  assert.equal(overview.riskEntries, 0);
  assert.equal(overview.backupStale, false);
  assert.equal(overview.health.level, "empty");
});
