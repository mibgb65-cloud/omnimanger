import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

const { deleteTrashEntry, getTrashEntries, mergeImportedVault, moveEntryToTrash, normalizeVault, restoreTrashEntry } = await import(
  "../public/app.js"
);

test("vault trash keeps deleted entries recoverable", () => {
  const vault = normalizeVault({
    entries: [
      { id: "1", name: "Main", login: "main@example.com", password: "secret" },
      { id: "2", name: "Other", login: "other@example.com" },
    ],
  });

  const trashed = moveEntryToTrash(vault, "1", "2026-07-05T00:00:00.000Z");
  assert.equal(trashed.name, "Main");
  assert.equal(vault.entries.length, 1);
  assert.equal(getTrashEntries(vault).length, 1);
  assert.equal(getTrashEntries(vault)[0].deletedAt, "2026-07-05T00:00:00.000Z");

  const restored = restoreTrashEntry(vault, "1", "2026-07-06T00:00:00.000Z");
  assert.equal(restored.name, "Main");
  assert.equal(vault.entries[0].id, "1");
  assert.equal(vault.entries[0].updatedAt, "2026-07-06T00:00:00.000Z");
  assert.equal(getTrashEntries(vault).length, 0);
});

test("trash entries normalize and survive merge imports", () => {
  const current = normalizeVault({
    entries: [{ id: "1", name: "Current", login: "current@example.com" }],
    trash: [{ id: "2", name: "Deleted", login: "old@example.com", deletedAt: "2026-07-01T00:00:00.000Z" }],
  });
  const incoming = normalizeVault({
    entries: [{ id: "3", name: "Incoming", login: "incoming@example.com" }],
    trash: [{ id: "4", name: "Backup deleted", login: "backup@example.com", deletedAt: "2026-07-02T00:00:00.000Z" }],
  });

  const merged = mergeImportedVault(current, incoming);
  assert.deepEqual(getTrashEntries(merged).map((entry) => entry.name), ["Backup deleted", "Deleted"]);
  assert.equal(deleteTrashEntry(merged, "2").name, "Deleted");
  assert.deepEqual(getTrashEntries(merged).map((entry) => entry.name), ["Backup deleted"]);
});
