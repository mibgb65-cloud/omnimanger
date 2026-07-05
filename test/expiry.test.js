import assert from "node:assert/strict";
import test from "node:test";

const { getEntryExpiryStatus, getVaultExpiryReport, normalizeExpiryDate } = await import("../public/app/expiry.js");

test("entry expiry status reports expired and upcoming rotation dates", () => {
  const now = Date.parse("2026-07-05T10:00:00.000Z");

  assert.equal(normalizeExpiryDate("2026-07-10"), "2026-07-10");
  assert.equal(normalizeExpiryDate("07/10/2026"), "");
  assert.equal(getEntryExpiryStatus({}, now).state, "none");
  assert.deepEqual(getEntryExpiryStatus({ passwordExpiresAt: "2026-07-04" }, now), {
    state: "expired",
    expiresAt: "2026-07-04",
    daysRemaining: -1,
    label: "密码已过期 1 天",
  });
  assert.equal(getEntryExpiryStatus({ passwordExpiresAt: "2026-07-10" }, now).state, "soon");
  assert.equal(getEntryExpiryStatus({ passwordExpiresAt: "2026-08-10" }, now).state, "scheduled");
});

test("vault expiry report separates expired and soon entries", () => {
  const report = getVaultExpiryReport(
    {
      entries: [
        { id: "1", name: "Old", passwordExpiresAt: "2026-07-01" },
        { id: "2", name: "Soon", passwordExpiresAt: "2026-07-12" },
        { id: "3", name: "Later", passwordExpiresAt: "2026-08-12" },
      ],
    },
    Date.parse("2026-07-05T00:00:00.000Z"),
  );

  assert.deepEqual(report.expired.map((entry) => entry.name), ["Old"]);
  assert.deepEqual(report.expiringSoon.map((entry) => entry.name), ["Soon"]);
});
