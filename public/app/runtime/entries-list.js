function clearAppHash() {
  if (!location.hash) return;
  history.replaceState(null, "", `${location.pathname}${location.search}`);
}

function lockIfHiddenTooLong() {
  if (document.visibilityState !== "hidden" || !state.vault || state.autoLockMinutes <= 0) return;
  const hiddenAt = Number(sessionStorage.getItem("vault.hidden-at") || "0");
  if (!hiddenAt) {
    sessionStorage.setItem("vault.hidden-at", String(Date.now()));
    return;
  }
  if (Date.now() - hiddenAt > state.autoLockMinutes * 60 * 1000) {
    sessionStorage.removeItem("vault.hidden-at");
    lockVault();
  }
}

function lockIfIdleTooLong() {
  if (!state.vault || state.autoLockMinutes <= 0) return;
  if (Date.now() - state.lastActivityAt > state.autoLockMinutes * 60 * 1000) {
    lockVault();
  }
}

function renderEntries() {
  if (!state.vault) return;

  els.entryList.textContent = "";
  renderTagFilters();
  renderTagManager();
  renderOverview();
  renderSecurityCheck();
  renderRiskFilterState();
  renderSecurityFilterNotice();
  const entries = getFilteredEntries();
  const query = els.searchInput.value.trim().toLowerCase();

  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    const title = document.createElement("strong");
    const hint = document.createElement("span");
    icon.classList.add("icon");
    icon.setAttribute("aria-hidden", "true");
    icon.setAttribute("focusable", "false");
    use.setAttribute("href", state.riskOnly ? "/icons.svg#icon-check-circle" : "/icons.svg#icon-search");
    icon.append(use);
    title.textContent = getEmptyListTitle(query);
    hint.textContent = getEmptyListHint(query);
    empty.append(icon, title, hint);
    els.entryList.append(empty);
    return;
  }

  for (const entry of entries) {
    const item = els.entryTemplate.content.firstElementChild.cloneNode(true);
    item.dataset.id = entry.id;
    item.setAttribute("role", "option");
    item.setAttribute("aria-selected", entry.id === state.selectedId ? "true" : "false");
    item.classList.toggle("active", entry.id === state.selectedId);
    item.querySelector("strong").textContent = entry.name || "未命名账号";
    item.querySelector(".entry-meta").textContent = formatEntryMeta(entry);
    renderEntryBadges(item.querySelector(".entry-badges"), entry);
    initDecorativeIcons(item);
    item.addEventListener("click", () => selectEntry(entry.id, { openDetail: true }));
    els.entryList.append(item);
  }
}

function getFilteredEntries() {
  if (!state.vault) return [];
  const search = parseSearchQuery(els.searchInput.value);
  const entries = state.vault.entries.filter((entry) => {
    const tags = parseEntryTags(entry.tags);
    if (state.selectedTag && !tags.includes(state.selectedTag)) return false;
    if (state.securityFilterIds && !state.securityFilterIds.has(entry.id)) return false;
    if (state.riskOnly && !entryHasRisk(entry, state.vault)) return false;
    return entryMatchesSearch(entry, search, state.vault);
  });
  return sortEntries(entries, state.entrySort, state.vault);
}

function getEmptyListTitle(query) {
  if (state.securityFilterIds && query) return "没有匹配的筛选账号";
  if (state.securityFilterIds) return "这个筛选没有账号";
  if (state.riskOnly && query) return "没有匹配的风险账号";
  if (state.riskOnly) return "没有风险账号";
  return query ? "没有匹配账号" : "还没有账号";
}

function getEmptyListHint(query) {
  if (state.securityFilterIds && query) return "清空搜索或关闭安全检查筛选";
  if (state.securityFilterIds) return "这个安全检查项暂时没有可显示账号";
  if (state.riskOnly && query) return "清空搜索或关闭只看风险";
  if (state.riskOnly) return "弱密码、重复密码、缺少 2FA 或恢复码会显示在这里";
  return query ? "换个关键词试试" : "点击右上角新增账号";
}

function renderRiskFilterState() {
  if (!els.riskFilterCount || !state.vault) return;
  const count = getRiskEntryCount(state.vault);
  els.riskFilterCount.textContent = `${count} 个`;
  els.riskFilterCount.dataset.state = count ? "warning" : "ok";
}

function renderSecurityFilterNotice() {
  if (!els.securityFilterNotice) return;
  const active = Boolean(state.securityFilterIds);
  els.securityFilterNotice.classList.toggle("hidden", !active);
  if (active) {
    els.securityFilterLabel.textContent = state.securityFilterLabel || "安全检查筛选";
  }
}

function sortEntries(entries, sortMode, vault) {
  const sorted = [...entries];
  if (sortMode === "favorite") {
    return sorted.sort((a, b) => {
      const favoriteDiff = Number(Boolean(b.favorite)) - Number(Boolean(a.favorite));
      if (favoriteDiff) return favoriteDiff;
      return compareUpdatedDesc(a, b);
    });
  }

  if (sortMode === "used") {
    return sorted.sort((a, b) => {
      const usedDiff = dateValue(b.lastUsedAt) - dateValue(a.lastUsedAt);
      if (usedDiff) return usedDiff;
      return compareUpdatedDesc(a, b);
    });
  }

  if (sortMode === "risk") {
    return sorted.sort((a, b) => {
      const riskDiff = getEntryRiskScore(b, vault) - getEntryRiskScore(a, vault);
      if (riskDiff) return riskDiff;
      return compareUpdatedDesc(a, b);
    });
  }

  if (sortMode === "name") {
    return sorted.sort((a, b) => entryDisplayName(a).localeCompare(entryDisplayName(b)));
  }

  return sorted.sort(compareUpdatedDesc);
}

function compareUpdatedDesc(a, b) {
  return dateValue(b.updatedAt || b.createdAt) - dateValue(a.updatedAt || a.createdAt);
}

