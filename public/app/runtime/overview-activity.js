async function generateAndCopyPassword() {
  fillGeneratedPassword();
  await copyInputValue("entryPassword", els.generateCopyPasswordButton);
}

function updatePasswordStatus() {
  if (!hasDocument || !els.passwordStrength) return;
  const entry = getSelectedEntry();
  const password = entry?.password || els.entryPassword?.value || "";
  if (!password) {
    els.passwordStrength.textContent = "未填写密码";
    els.passwordStrength.dataset.level = "empty";
    updatePasswordExpiryStatus(entry);
    return;
  }

  const strength = scorePassword(password);
  const duplicateCount = state.vault
    ? state.vault.entries.filter((item) => item.id !== entry?.id && item.password && item.password === password).length
    : 0;
  const duplicateText = duplicateCount ? `，与 ${duplicateCount} 个账号重复` : "";
  els.passwordStrength.textContent = `${strength.label}${duplicateText}`;
  els.passwordStrength.dataset.level = duplicateCount ? "duplicate" : strength.level;
  updatePasswordExpiryStatus(entry);
}

function updatePasswordExpiryStatus(entry) {
  if (!els.passwordExpiryStatus) return;
  const status = getEntryExpiryStatus(entry);
  els.passwordExpiryStatus.textContent = status.label;
  els.passwordExpiryStatus.dataset.level = status.state === "expired" ? "weak" : status.state === "soon" ? "medium" : status.state === "scheduled" ? "strong" : "empty";
}

function addEntryFromOverview() {
  showAppPage("vault");
  addEntry();
}

function showRiskAccountsFromOverview() {
  if (!state.vault) return;
  state.securityFilterIds = null;
  state.securityFilterLabel = "";
  state.riskOnly = true;
  state.selectedTag = "";
  state.entrySort = "risk";
  els.riskOnlyToggle.checked = true;
  els.entrySortSelect.value = "risk";
  els.searchInput.value = "";
  showAppPage("vault");
  renderEntries();
  setMobileVaultPanel("list");
}

function renderOverview() {
  if (!hasDocument || !els.overviewAccountCount || !state.vault) return;
  const overview = getVaultOverview(state.vault, getLastBackupAt(), state.cacheDisabled, state.autoLockMinutes);

  els.overviewAccountCount.textContent = String(overview.totalEntries);
  els.overviewRiskCount.textContent = String(overview.riskEntries);
  els.overviewRiskButton.dataset.state = overview.riskEntries ? "warning" : "ok";
  els.overviewHealthScore.textContent = String(overview.health.score);
  els.overviewHealthLabel.textContent = overview.health.label;
  els.overviewHealthBar.style.width = `${overview.health.score}%`;
  els.overviewHealthScore.closest(".health-score").dataset.level = overview.health.level;
  els.overviewAutoLockStatus.textContent = overview.autoLockLabel;
  els.overviewLocalStatus.textContent = overview.localCacheLabel;
  els.overviewBackupDetail.textContent = overview.backupDetail;
  renderOverviewRiskList();
  renderOverviewActivity();
}

function renderOverviewRiskList() {
  if (!hasDocument || !els.overviewRiskList || !state.vault) return;
  els.overviewRiskList.textContent = "";
  const riskEntries = state.vault.entries
    .filter((entry) => entryHasRisk(entry, state.vault))
    .sort((a, b) => getEntryRiskScore(b, state.vault) - getEntryRiskScore(a, state.vault))
    .slice(0, 4);

  if (!riskEntries.length) {
    const empty = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    empty.className = "overview-empty";
    title.textContent = "当前没有明显风险";
    detail.textContent = "安全中心仍可查看完整检查结果。";
    empty.append(title, detail);
    els.overviewRiskList.append(empty);
    return;
  }

  for (const entry of riskEntries) {
    const item = document.createElement("button");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    item.type = "button";
    item.className = "overview-risk-item";
    title.textContent = entry.name || entry.login || "未命名账号";
    detail.textContent = getEntryRiskSummary(entry);
    item.append(title, detail);
    item.addEventListener("click", () => openOverviewRiskEntry(entry.id));
    els.overviewRiskList.append(item);
  }
}

function renderOverviewActivity() {
  if (!hasDocument || !els.overviewActivityList) return;
  els.overviewActivityList.textContent = "";
  const events = state.activityLog.slice(0, 6);

  if (!events.length) {
    const empty = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    empty.className = "activity-item";
    title.textContent = "还没有本地活动";
    detail.textContent = "新增、导入、导出等操作会显示在这里。";
    empty.append(title, detail);
    els.overviewActivityList.append(empty);
    return;
  }

  for (const event of events) {
    const item = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    item.className = "activity-item";
    title.textContent = activityTitle(event.type);
    detail.textContent = [event.detail, formatDateTime(event.at)].filter(Boolean).join(" / ");
    item.append(title, detail);
    els.overviewActivityList.append(item);
  }
}

function recordActivity(type, detail = "") {
  if (!state.user?.id) return;
  const event = {
    type,
    detail: sanitizeActivityDetail(detail),
    at: new Date().toISOString(),
  };
  state.activityLog = [event, ...state.activityLog].slice(0, ACTIVITY_LIMIT);
  localStorage.setItem(getActivityKey(state.user.id), JSON.stringify(state.activityLog));
  renderOverviewActivity();
}

function loadActivityLog() {
  if (!state.user?.id) {
    state.activityLog = [];
    return;
  }

  try {
    const events = JSON.parse(localStorage.getItem(getActivityKey(state.user.id)) || "[]");
    state.activityLog = Array.isArray(events) ? events.slice(0, ACTIVITY_LIMIT).map(normalizeActivityEvent).filter(Boolean) : [];
  } catch {
    state.activityLog = [];
  }
}

function normalizeActivityEvent(event) {
  if (!event || typeof event !== "object" || !event.type || !event.at) return null;
  return {
    type: String(event.type),
    detail: sanitizeActivityDetail(event.detail || ""),
    at: String(event.at),
  };
}

function sanitizeActivityDetail(detail) {
  return String(detail || "").replace(/\s+/g, " ").trim().slice(0, 80);
}

function getActivityKey(userId) {
  return `account-secret-vault.activity.${userId}`;
}

function activityTitle(type) {
  return (
    {
      add_entry: "新增账号",
      delete_entry: "删除账号",
      restore_entry: "恢复账号",
      purge_entry: "永久删除账号",
      favorite_entry: "收藏账号",
      unfavorite_entry: "取消收藏",
      manage_tags: "管理标签",
      generate_password: "生成密码",
      export_backup: "导出备份",
      verify_backup: "验证备份",
      import_backup: "导入备份",
      pull_remote: "拉取远端",
      restore_password: "恢复旧密码",
      change_password: "修改主密码",
      logout_all: "退出所有设备",
    }[type] || "保险箱操作"
  );
}

function openOverviewRiskEntry(entryId) {
  showAppPage("vault");
  state.riskOnly = false;
  state.securityFilterIds = null;
  state.securityFilterLabel = "";
  els.riskOnlyToggle.checked = false;
  selectEntry(entryId, { openDetail: true });
}

function getEntryRiskSummary(entry) {
  const parts = [];
  const password = String(entry.password || "");
  if (!password) {
    parts.push("缺少密码");
  } else if (scorePassword(password).level === "weak") {
    parts.push("弱密码");
  }
  if (!String(entry.totpSecret || "").trim()) parts.push("缺少 2FA");
  if (!String(entry.recoveryCodes || "").trim()) parts.push("缺少恢复码");
  return parts.join(" / ") || "需要检查";
}

