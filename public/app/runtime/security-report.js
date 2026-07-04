function renderSecurityCheck() {
  if (!hasDocument || !els.securitySummary || !state.vault) return;
  const report = analyzeVaultSecurity(state.vault);
  renderSecurityHealth(getVaultHealth(state.vault, getLastBackupAt()));
  els.securitySummary.textContent = "";
  els.securityCheckList.textContent = "";

  for (const stat of [
    { label: "账号", value: report.totalEntries },
    { label: "问题", value: report.totalIssues },
    { label: "弱密码", value: report.weakPasswords.length },
    { label: "重复密码", value: report.duplicatePasswordGroups.length },
  ]) {
    const item = document.createElement("div");
    const value = document.createElement("strong");
    const label = document.createElement("span");
    item.className = "security-stat";
    value.textContent = String(stat.value);
    label.textContent = stat.label;
    item.append(value, label);
    els.securitySummary.append(item);
  }

  const checks = securityReportItems(report);
  if (!checks.length) {
    const item = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    item.className = "security-check-item";
    title.textContent = "当前没有明显风险";
    detail.textContent = "没有发现弱密码、重复密码或缺失 2FA/恢复码的账号。";
    item.append(title, detail);
    els.securityCheckList.append(item);
    return;
  }

  for (const check of checks) {
    const item = document.createElement(check.entryIds?.length ? "button" : "div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    item.className = "security-check-item";
    item.dataset.tone = check.tone;
    if (check.entryIds?.length) {
      item.type = "button";
      item.addEventListener("click", () => applySecurityFilter(check));
    }
    title.textContent = check.title;
    detail.textContent = check.detail;
    item.append(title, detail);
    els.securityCheckList.append(item);
  }
}

function renderSecurityHealth(health) {
  if (!els.securityHealth) return;
  els.securityHealth.textContent = "";
  els.securityHealth.dataset.level = health.level;

  const score = document.createElement("strong");
  const copy = document.createElement("div");
  const label = document.createElement("span");
  const detail = document.createElement("small");
  const meter = document.createElement("div");
  const bar = document.createElement("span");

  score.textContent = String(health.score);
  label.textContent = health.label;
  detail.textContent = health.reasons.length ? health.reasons.slice(0, 4).join(" / ") : "当前没有明显扣分项。";
  meter.className = "health-meter";
  bar.style.width = `${health.score}%`;
  meter.append(bar);
  copy.append(label, detail, meter);
  els.securityHealth.append(score, copy);
}

function securityReportItems(report) {
  const items = [];
  if (report.emptyPasswords.length) {
    items.push({
      tone: "danger",
      title: `${report.emptyPasswords.length} 个账号缺少密码`,
      detail: entryNames(report.emptyPasswords),
      entryIds: report.emptyPasswords.map((entry) => entry.id),
    });
  }
  if (report.weakPasswords.length) {
    items.push({
      tone: "warning",
      title: `${report.weakPasswords.length} 个账号使用弱密码`,
      detail: entryNames(report.weakPasswords),
      entryIds: report.weakPasswords.map((entry) => entry.id),
    });
  }
  if (report.duplicatePasswordGroups.length) {
    items.push({
      tone: "danger",
      title: `${report.duplicatePasswordGroups.length} 组重复密码`,
      detail: report.duplicatePasswordGroups.map((group) => entryNames(group.entries)).join("；"),
      entryIds: report.duplicatePasswordGroups.flatMap((group) => group.entries.map((entry) => entry.id)),
    });
  }
  if (report.missingTotp.length) {
    items.push({
      tone: "warning",
      title: `${report.missingTotp.length} 个账号缺少 2FA`,
      detail: entryNames(report.missingTotp),
      entryIds: report.missingTotp.map((entry) => entry.id),
    });
  }
  if (report.missingRecovery.length) {
    items.push({
      tone: "warning",
      title: `${report.missingRecovery.length} 个账号缺少恢复码`,
      detail: entryNames(report.missingRecovery),
      entryIds: report.missingRecovery.map((entry) => entry.id),
    });
  }
  return items;
}

function applySecurityFilter(check) {
  const entryIds = Array.isArray(check?.entryIds) ? check.entryIds : [];
  const firstEntryId = entryIds.find((entryId) => state.vault?.entries.some((entry) => entry.id === entryId));
  if (!firstEntryId) return;

  state.securityFilterIds = new Set(entryIds);
  state.securityFilterLabel = check.title || "安全检查筛选";
  state.riskOnly = true;
  state.selectedTag = "";
  state.entrySort = "risk";
  els.riskOnlyToggle.checked = true;
  els.entrySortSelect.value = "risk";
  els.searchInput.value = "";
  navigateToAppPage("vault");
  renderEntries();
  selectEntry(firstEntryId, { openDetail: false });
  setMobileVaultPanel("list");
  window.setTimeout(() => {
    const item = Array.from(els.entryList.querySelectorAll(".entry-item")).find((entryItem) => entryItem.dataset.id === firstEntryId);
    item?.scrollIntoView({ block: "nearest" });
    item?.focus();
  }, 0);
}

function clearSecurityFilter() {
  state.securityFilterIds = null;
  state.securityFilterLabel = "";
  renderEntries();
  setMobileVaultPanel("list");
}

function entryNames(entries) {
  return entries.map((entry) => entry.name || entry.login || "未命名账号").join("、");
}


