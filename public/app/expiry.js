const EXPIRY_SOON_DAYS = 14;

function normalizeExpiryDate(value) {
  const text = String(value || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return "";
  const date = new Date(`${text}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === text ? text : "";
}

function getEntryExpiryStatus(entry, now = Date.now()) {
  const expiresAt = normalizeExpiryDate(entry?.passwordExpiresAt);
  if (!expiresAt) return { state: "none", expiresAt: "", daysRemaining: null, label: "未设置轮换提醒" };
  const daysRemaining = dayNumber(Date.parse(`${expiresAt}T00:00:00.000Z`)) - dayNumber(now);
  if (daysRemaining < 0) return { state: "expired", expiresAt, daysRemaining, label: `密码已过期 ${Math.abs(daysRemaining)} 天` };
  if (daysRemaining === 0) return { state: "soon", expiresAt, daysRemaining, label: "密码今天到期" };
  if (daysRemaining <= EXPIRY_SOON_DAYS) return { state: "soon", expiresAt, daysRemaining, label: `密码 ${daysRemaining} 天后到期` };
  return { state: "scheduled", expiresAt, daysRemaining, label: `密码 ${daysRemaining} 天后到期` };
}

function getVaultExpiryReport(vault, now = Date.now()) {
  const entries = Array.isArray(vault?.entries) ? vault.entries : [];
  const withStatus = entries.map((entry) => ({ entry, status: getEntryExpiryStatus(entry, now) }));
  return {
    expired: withStatus.filter((item) => item.status.state === "expired").map((item) => item.entry),
    expiringSoon: withStatus.filter((item) => item.status.state === "soon").map((item) => item.entry),
  };
}

function dayNumber(timestamp) {
  return Math.floor(timestamp / 86_400_000);
}

export { getEntryExpiryStatus, getVaultExpiryReport, normalizeExpiryDate };
