import assert from "node:assert/strict";
import test from "node:test";

const { getBackupVerificationHealth } = await import("../public/app.js");

test("backup verification health flags stale and incomplete recovery points", () => {
  const now = Date.parse("2026-07-05T00:00:00.000Z");
  const healthy = getBackupVerificationHealth(
    {
      currentTotal: 2,
      incomingTotal: 2,
      added: 0,
      matched: 2,
      removed: 0,
      backupUpdatedAt: "2026-07-04T00:00:00.000Z",
    },
    now,
  );
  assert.equal(healthy.level, "good");
  assert.equal(healthy.countMatches, true);
  assert.equal(healthy.stale, false);

  const missingCurrent = getBackupVerificationHealth({ currentTotal: 2, incomingTotal: 1, removed: 1 }, now);
  assert.equal(missingCurrent.level, "warning");
  assert.equal(missingCurrent.missingCurrent, 1);
  assert.match(missingCurrent.details.join(" "), /缺少当前 1 个账号/);

  const stale = getBackupVerificationHealth(
    { currentTotal: 1, incomingTotal: 1, backupUpdatedAt: "2026-06-01T00:00:00.000Z" },
    now,
  );
  assert.equal(stale.level, "warning");
  assert.equal(stale.stale, true);

  const empty = getBackupVerificationHealth(
    { currentTotal: 1, incomingTotal: 0, backupUpdatedAt: "2026-07-04T00:00:00.000Z" },
    now,
  );
  assert.equal(empty.level, "danger");
});
