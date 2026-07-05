function initTheme() {
  const savedTheme = localStorage.getItem(THEME_KEY);
  const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  setTheme(savedTheme || (systemDark ? "dark" : "light"), false);
}

function toggleTheme() {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  setTheme(nextTheme, true);
}

function setTheme(theme, animate) {
  if (animate) {
    document.documentElement.classList.add("theme-transition");
    window.setTimeout(() => document.documentElement.classList.remove("theme-transition"), 220);
  }

  document.documentElement.dataset.theme = theme;
  document.body.dataset.theme = theme;
  localStorage.setItem(THEME_KEY, theme);
  setInlineLabel(els.themeToggleButton, theme === "dark" ? "浅色" : "深色");
  setInlineIcon(els.themeToggleButton, theme === "dark" ? "icon-sun" : "icon-moon");
}

function initSecurityPreferences() {
  const savedAutoLock = Number(localStorage.getItem(AUTO_LOCK_KEY) || "5");
  state.autoLockMinutes = Number.isFinite(savedAutoLock) ? savedAutoLock : 5;
  els.autoLockSelect.value = String(state.autoLockMinutes);

  state.cacheDisabled = localStorage.getItem(CACHE_DISABLED_KEY) === "true";
  els.localCacheToggle.checked = !state.cacheDisabled;
  updateSessionStatus();
  updateLocalCacheDetail();
}

function initDataPreferences() {
  const savedImportMode = localStorage.getItem(IMPORT_MODE_KEY);
  state.importMode = savedImportMode === "replace" ? "replace" : "merge";
  els.importModeSelect.value = state.importMode;

  const savedEntrySort = localStorage.getItem(ENTRY_SORT_KEY);
  state.entrySort = normalizeEntrySort(savedEntrySort);
  els.entrySortSelect.value = state.entrySort;
}

function saveImportModePreference() {
  state.importMode = els.importModeSelect.value === "replace" ? "replace" : "merge";
  localStorage.setItem(IMPORT_MODE_KEY, state.importMode);
  renderBackupWizard();
}

function saveEntrySortPreference() {
  state.entrySort = normalizeEntrySort(els.entrySortSelect.value);
  localStorage.setItem(ENTRY_SORT_KEY, state.entrySort);
  renderEntries();
}

function normalizeEntrySort(value) {
  return ["updated", "favorite", "used", "risk", "name"].includes(value) ? value : "updated";
}

function toggleRiskOnlyFilter() {
  state.riskOnly = els.riskOnlyToggle.checked;
  if (!state.riskOnly) {
    state.securityFilterIds = null;
    state.securityFilterLabel = "";
  }
  renderEntries();
  setMobileVaultPanel("list");
}

function initPasswordGeneratorOptions() {
  let options = {};
  try {
    options = JSON.parse(localStorage.getItem(PASSWORD_OPTIONS_KEY) || "{}");
  } catch {
    options = {};
  }

  els.passwordLengthInput.value = String(normalizePasswordLength(options.length));
  els.passwordSymbolsToggle.checked = options.symbols !== false;
  els.passwordReadableToggle.checked = options.readable !== false;
}

function savePasswordGeneratorOptions() {
  const options = getPasswordGeneratorOptions();
  localStorage.setItem(PASSWORD_OPTIONS_KEY, JSON.stringify(options));
  els.passwordLengthInput.value = String(options.length);
}

function getPasswordGeneratorOptions() {
  return {
    length: normalizePasswordLength(els.passwordLengthInput.value),
    symbols: els.passwordSymbolsToggle.checked,
    readable: els.passwordReadableToggle.checked,
  };
}

function initConnectivity() {
  state.online = navigator.onLine !== false;
  window.addEventListener("online", () => {
    state.online = true;
    if (state.vault) {
      setSaveStatus(state.dirty ? "已联网，仍有未保存修改" : "已联网", state.dirty ? "dirty" : "synced");
      showToast("网络已恢复", { tone: "success" });
    }
    updateBusyControls();
  });
  window.addEventListener("offline", () => {
    state.online = false;
    if (state.vault) {
      setSaveStatus("离线：仅保存到本机", "offline");
      showToast("当前离线", { message: "远端保存和拉取会暂时不可用。", tone: "warning" });
    }
    updateBusyControls();
  });
}

function saveAutoLockPreference() {
  const minutes = Number(els.autoLockSelect.value);
  state.autoLockMinutes = Number.isFinite(minutes) ? minutes : 5;
  localStorage.setItem(AUTO_LOCK_KEY, String(state.autoLockMinutes));
  markActivity();
  updateSessionStatus();
  renderOverview();
  showToast("自动锁定已更新", { message: state.autoLockMinutes ? `${state.autoLockMinutes} 分钟` : "已关闭" });
}

function saveLocalCachePreference() {
  state.cacheDisabled = !els.localCacheToggle.checked;
  localStorage.setItem(CACHE_DISABLED_KEY, state.cacheDisabled ? "true" : "false");
  if (state.cacheDisabled && state.user) {
    localStorage.removeItem(getStorageKey(state.user.id));
    setSaveStatus("本地缓存已关闭", "synced");
    showToast("本地缓存已关闭");
  } else if (state.user && state.vault && state.key) {
    showToast("本地缓存已开启");
    saveVaultNow(false);
  }
  updateLocalCacheDetail();
  renderOverview();
}

function updateLocalCacheDetail() {
  if (!hasDocument || !els.localCacheDetail) return;
  if (!state.user) {
    els.localCacheDetail.textContent = "解锁后会显示本机加密副本状态。";
    return;
  }
  if (state.cacheDisabled) {
    els.localCacheDetail.textContent = "本机不会保存保险箱副本；刷新后需要从 Cloudflare 读取。";
    return;
  }

  const envelope = readLocalEnvelope();
  const updatedAt = formatDateTime(envelope?.updatedAt || "");
  els.localCacheDetail.textContent = updatedAt
    ? `本机保存了加密副本，最近更新 ${updatedAt}。`
    : "本机暂未保存加密副本。";
}

function updateMasterPasswordStrength() {
  if (!hasDocument || !els.masterPasswordStrength) return;
  const isRegister = state.authMode === "register";
  els.masterPasswordStrength.classList.toggle("hidden", !isRegister);
  if (!isRegister) {
    els.masterPasswordStrength.textContent = "";
    els.masterPasswordStrength.dataset.level = "empty";
    return;
  }

  const password = els.loginPassword.value;
  if (!password) {
    els.masterPasswordStrength.textContent = "主密码强度会在输入后显示。";
    els.masterPasswordStrength.dataset.level = "empty";
    return;
  }

  const strength = scorePassword(password);
  els.masterPasswordStrength.textContent = formatMasterPasswordStrength(password);
  els.masterPasswordStrength.dataset.level = strength.level;
}

function markActivity() {
  state.lastActivityAt = Date.now();
}

function updateSessionStatus() {
  if (!hasDocument || !els.sessionStatus) return;
  const label = state.autoLockMinutes > 0 ? `自动锁定 ${state.autoLockMinutes} 分钟` : "自动锁定关闭";
  setInlineLabel(els.sessionStatus, label);
  setInlineIcon(els.sessionStatus, state.autoLockMinutes > 0 ? "icon-clock" : "icon-unlock");
}

function setAuthMode(mode) {
  const isRegister = mode === "register";
  state.authMode = isRegister ? "register" : "login";

  setHeadingText(els.unlockTitle, isRegister ? "注册" : "登录");
  setInlineIcon(els.unlockTitle, isRegister ? "icon-user-plus" : "icon-lock");
  setInlineLabel(els.unlockSubmitButton, isRegister ? "注册" : "登录");
  setInlineIcon(els.unlockSubmitButton, isRegister ? "icon-user-plus" : "icon-log-in");
  els.loginPassword.autocomplete = isRegister ? "new-password" : "current-password";
  els.inviteTokenRow.classList.toggle("hidden", !isRegister);

  els.loginModeButton.dataset.active = isRegister ? "false" : "true";
  els.registerButton.dataset.active = isRegister ? "true" : "false";
  els.loginModeButton.setAttribute("aria-selected", isRegister ? "false" : "true");
  els.registerButton.setAttribute("aria-selected", isRegister ? "true" : "false");
  els.loginModeButton.tabIndex = isRegister ? -1 : 0;
  els.registerButton.tabIndex = isRegister ? 0 : -1;
  updateMasterPasswordStrength();
  setUnlockMessage("");
}

async function authenticate(mode) {
  if (state.authenticating) return;

  const email = normalizeEmail(els.loginEmail.value);
  const password = els.loginPassword.value;

  if (!email || !email.includes("@")) {
    setUnlockMessage("请输入有效邮箱。");
    return;
  }

  if (password.length < 10) {
    setUnlockMessage("密码至少需要 10 个字符。");
    return;
  }

  state.authenticating = true;
  setAuthButtonsDisabled(true);
  setUnlockMessage(mode === "register" ? "正在注册…" : "正在登录…");

  try {
    const authSecret = await makeAuthSecret(email, password);
    const payload = { email, authSecret };
    if (mode === "register") {
      payload.inviteToken = els.inviteToken.value.trim();
    }
    const data = await postJson(`/api/auth/${mode}`, payload);
    state.user = data.user;
    localStorage.setItem(LAST_EMAIL_KEY, email);

    const selected = await loadBestEnvelope();
    if (selected.envelope) {
      await openEnvelope(password, selected.envelope);
      state.remoteRevision = selected.remoteRevision;
    } else {
      await createEmptyVault(password);
      state.remoteRevision = null;
    }

    showVault();
    renderEntries();
    selectEntry(state.vault.entries[0]?.id || null, { openDetail: false });
    setMobileVaultPanel("list");
    if (selected.source === "local") {
      state.dirty = true;
      setSaveStatus("本地版本较新，尚未同步", "dirty");
      showToast("本地版本较新", { message: "已先打开本地副本，保存后会同步到 Cloudflare。", tone: "warning" });
    } else {
      await saveVaultNow(false);
    }
    els.loginPassword.value = "";
    setUnlockMessage("");
  } catch (error) {
    state.key = null;
    setUnlockMessage(formatAuthError(error));
  } finally {
    state.authenticating = false;
    setAuthButtonsDisabled(false);
  }
}

