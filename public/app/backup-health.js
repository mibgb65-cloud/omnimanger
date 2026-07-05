const BACKUP_HEALTH_STALE_DAYS = 7;
const BACKUP_HEALTH_STALE_MS = BACKUP_HEALTH_STALE_DAYS * 24 * 60 * 60 * 1000;

function getBackupVerificationHealth(summary, now = Date.now()) {
  const currentTotal = toCount(summary?.currentTotal);
  const incomingTotal = toCount(summary?.incomingTotal);
  const added = toCount(summary?.added);
  const matched = toCount(summary?.matched);
  const removed = toCount(summary?.removed);
  const details = [];
  const actions = [];
  let level = "good";

  if (incomingTotal <= 0 && currentTotal > 0) {
    level = "danger";
    details.push("备份里没有可恢复账号。");
    actions.push("重新导出当前保险箱备份。");
  }

  if (removed > 0) {
    level = escalateBackupHealth(level, "warning");
    details.push(`备份缺少当前 ${removed} 个账号。`);
    actions.push("导入前确认这些账号是否仍需要保留。");
  }

  if (currentTotal === incomingTotal) {
    details.push(`账号数量一致，当前和备份都是 ${incomingTotal} 个。`);
  } else {
    level = escalateBackupHealth(level, "warning");
    const diff = Math.abs(incomingTotal - currentTotal);
    details.push(incomingTotal > currentTotal ? `备份比当前多 ${diff} 个账号。` : `备份比当前少 ${diff} 个账号。`);
  }

  if (added > 0) details.push(`备份额外包含 ${added} 个当前没有的账号。`);
  if (matched > 0) details.push(`有 ${matched} 个账号与当前保险箱重名。`);

  const staleState = getBackupTimestampState(summary?.backupUpdatedAt, now);
  if (staleState === "missing") {
    level = escalateBackupHealth(level, "warning");
    details.push("备份更新时间未知。");
    actions.push("建议重新导出一份带有明确时间的备份。");
  } else if (staleState === "stale") {
    level = escalateBackupHealth(level, "warning");
    details.push(`备份更新时间已超过 ${BACKUP_HEALTH_STALE_DAYS} 天。`);
    actions.push("建议导出一份最新备份。");
  }

  if (!details.length) details.push("备份能解密，账号数量和当前保险箱一致。");
  if (!actions.length) actions.push("可以作为当前恢复点保存。");

  return {
    level,
    title: backupHealthTitle(level),
    details: uniqueBackupHealthLines(details),
    actions: uniqueBackupHealthLines(actions),
    stale: staleState !== "fresh",
    countMatches: currentTotal === incomingTotal,
    missingCurrent: removed,
  };
}

function getBackupTimestampState(value, now) {
  if (!value) return "missing";
  const time = Date.parse(value);
  if (Number.isNaN(time)) return "missing";
  return now - time > BACKUP_HEALTH_STALE_MS ? "stale" : "fresh";
}

function toCount(value) {
  const count = Number(value);
  return Number.isFinite(count) ? Math.max(0, Math.round(count)) : 0;
}

function escalateBackupHealth(current, next) {
  const rank = { good: 0, warning: 1, danger: 2 };
  return rank[next] > rank[current] ? next : current;
}

function backupHealthTitle(level) {
  if (level === "danger") return "备份不可作为完整恢复点";
  if (level === "warning") return "备份需要复核";
  return "备份健康";
}

function uniqueBackupHealthLines(lines) {
  return Array.from(new Set(lines.filter(Boolean)));
}

export { getBackupVerificationHealth };
