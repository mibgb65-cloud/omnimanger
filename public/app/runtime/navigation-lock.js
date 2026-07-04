function getAvailableAppNavButtons() {
  return Array.from(els.appNav.querySelectorAll("button[data-app-page]:not(.hidden)"));
}

function handleAuthModeKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const nextMode = event.key === "ArrowLeft" || event.key === "Home" ? "login" : "register";
  setAuthMode(nextMode);
  (nextMode === "login" ? els.loginModeButton : els.registerButton).focus();
}

function handleSettingsTabClick(event) {
  const button = event.target.closest("button[data-settings-tab]");
  if (!button) return;
  showSettingsSection(button.dataset.settingsTab);
}

function handleSettingsTabKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = getAvailableSettingsTabs();
  if (!tabs.length) return;
  event.preventDefault();
  const currentIndex = Math.max(0, tabs.findIndex((button) => button.dataset.active === "true"));
  let nextIndex = currentIndex;
  if (event.key === "ArrowLeft") nextIndex = Math.max(0, currentIndex - 1);
  if (event.key === "ArrowRight") nextIndex = Math.min(tabs.length - 1, currentIndex + 1);
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = tabs.length - 1;
  showSettingsSection(tabs[nextIndex].dataset.settingsTab);
  tabs[nextIndex].focus();
}

function getAvailableSettingsTabs() {
  return Array.from(els.settingsTabs.querySelectorAll("button[data-settings-tab]:not(.hidden)"));
}

function showSettingsSection(section) {
  const nextSection = section === "admin" && state.user?.isAdmin ? "admin" : "security";
  state.settingsSection = nextSection;

  for (const button of els.settingsTabs.querySelectorAll("button[data-settings-tab]")) {
    const active = button.dataset.settingsTab === nextSection;
    button.dataset.active = active ? "true" : "false";
    button.setAttribute("aria-selected", active ? "true" : "false");
    button.tabIndex = active ? 0 : -1;
  }

  for (const panel of els.settingsView.querySelectorAll("[data-settings-section]")) {
    panel.classList.toggle("hidden", panel.dataset.settingsSection !== nextSection);
  }
}

function handleDetailTabClick(event) {
  const button = event.target.closest("button[data-detail-tab]");
  if (!button) return;
  showDetailSection(button.dataset.detailTab);
}

function handleDetailTabKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = getDetailTabs();
  if (!tabs.length) return;
  event.preventDefault();
  const currentIndex = Math.max(0, tabs.findIndex((button) => button.dataset.active === "true"));
  let nextIndex = currentIndex;
  if (event.key === "ArrowLeft") nextIndex = Math.max(0, currentIndex - 1);
  if (event.key === "ArrowRight") nextIndex = Math.min(tabs.length - 1, currentIndex + 1);
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = tabs.length - 1;
  showDetailSection(tabs[nextIndex].dataset.detailTab);
  tabs[nextIndex].focus();
}

function getDetailTabs() {
  return Array.from(els.detailTabs.querySelectorAll("button[data-detail-tab]"));
}

function showDetailSection(section) {
  const nextSection = DETAIL_SECTIONS.includes(section) ? section : "identity";
  state.detailSection = nextSection;

  for (const button of getDetailTabs()) {
    const active = button.dataset.detailTab === nextSection;
    button.dataset.active = active ? "true" : "false";
    button.setAttribute("aria-selected", active ? "true" : "false");
    button.tabIndex = active ? 0 : -1;
  }

  for (const panel of els.entryForm.querySelectorAll("[data-detail-section]")) {
    panel.classList.toggle("hidden", panel.dataset.detailSection !== nextSection);
  }
}

function handleEntryListKeydown(event) {
  if (!["ArrowDown", "ArrowUp", "Home", "End", "Enter"].includes(event.key)) return;
  const entries = getFilteredEntries();
  if (!entries.length) return;
  event.preventDefault();

  const currentIndex = Math.max(0, entries.findIndex((entry) => entry.id === state.selectedId));
  let nextIndex = currentIndex;
  if (event.key === "ArrowDown") nextIndex = Math.min(entries.length - 1, currentIndex + 1);
  if (event.key === "ArrowUp") nextIndex = Math.max(0, currentIndex - 1);
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = entries.length - 1;
  if (event.key === "Enter") {
    setMobileVaultPanel("detail");
    return;
  }

  selectEntry(entries[nextIndex].id, { openDetail: false });
  focusEntryButton(entries[nextIndex].id);
}

function focusEntryButton(id) {
  const button = Array.from(els.entryList.querySelectorAll("button[data-id]")).find((item) => item.dataset.id === id);
  button?.focus();
}

function handleGlobalKeydown(event) {
  if (!state.vault || event.defaultPrevented) return;
  const key = event.key.toLowerCase();

  if ((event.ctrlKey || event.metaKey) && key === "s") {
    event.preventDefault();
    saveVaultNow(true);
    return;
  }

  if (event.key === "/" && !isTextInput(event.target)) {
    event.preventDefault();
    showAppPage("vault");
    setMobileVaultPanel("list");
    els.searchInput.focus();
    return;
  }

  if (event.key === "Escape" && state.appPage === "vault" && state.mobilePanel === "detail") {
    setMobileVaultPanel("list");
  }
}

function isTextInput(target) {
  return ["INPUT", "TEXTAREA", "SELECT"].includes(target?.tagName) || target?.isContentEditable;
}

async function logoutVault() {
  clearTimeout(state.saveTimer);
  if (state.vault && state.key) {
    const saved = await saveVaultNow(false);
    if (
      !saved &&
      state.dirty &&
      !(await confirmDialog("保险箱尚未同步到 Cloudflare，仍要退出？本地加密副本会尽量保留。", {
        title: "退出保险箱",
        confirmLabel: "仍要退出",
        danger: true,
      }))
    ) {
      return;
    }
  }

  try {
    await apiPost("/api/auth/logout", null);
  } catch {
    // Locking local state is still useful even if the network request fails.
  }

  lockVault();
}

async function logoutAllSessions() {
  if (!state.user) return;
  const confirmed = await confirmDialog("这会让其他浏览器和设备上的登录状态失效，本机也会退出；不会删除保险箱数据。继续？", {
    title: "退出所有设备",
    confirmLabel: "退出所有设备",
    danger: true,
  });
  if (!confirmed) return;
  if (
    !(await requireCurrentPassword("重新输入当前主密码，确认退出所有设备。", {
      title: "验证主密码",
      confirmLabel: "确认退出",
    }))
  ) {
    return;
  }

  try {
    await apiPost("/api/auth/logout-all", null, "无法退出所有设备。");
    recordActivity("logout_all", "当前账号");
    showToast("已退出所有设备", { tone: "success" });
    lockVault();
  } catch (error) {
    showToast("退出所有设备失败", { message: error.message || "请稍后重试。", tone: "danger" });
  }
}

function lockVault() {
  state.user = null;
  state.vault = null;
  state.key = null;
  state.salt = null;
  state.selectedId = null;
  state.dirty = false;
  state.remoteRevision = null;
  state.passwordVisible = false;
  state.totpVisible = false;
  state.backupReminderShown = false;
  state.activityLog = [];
  state.lastBackupVerification = null;
  clearTimeout(state.clipboardClearTimer);
  clearTimeout(state.passwordRevealTimer);
  clearTimeout(state.totpRevealTimer);

  els.entryForm.reset();
  resetSecretVisibility();
  els.adminPanel.classList.add("hidden");
  els.adminSettingsTab.classList.add("hidden");
  els.entryList.textContent = "";
  els.lockedView.classList.remove("hidden");
  els.appNav.classList.add("hidden");
  els.overviewView.classList.add("hidden");
  els.vaultView.classList.add("hidden");
  els.securityView.classList.add("hidden");
  els.backupView.classList.add("hidden");
  els.settingsView.classList.add("hidden");
  clearAppHash();
  setInlineLabel(els.lockStatus, "Locked");
  setInlineIcon(els.lockStatus, "icon-lock");
  setInlineLabel(els.syncStatus, "Signed out");
  els.syncStatus.classList.add("neutral");
  els.sessionStatus.classList.add("hidden");
  setSaveStatus("未解锁", "locked");
  els.totpCode.textContent = "------";
  els.totpTimerBar.style.width = "0";
  updatePasswordStatus();
  updateLocalCacheDetail();
}

