const STORAGE_PREFIX = "account-secret-vault.envelope.";
const LAST_EMAIL_KEY = "account-secret-vault.last-email";
const THEME_KEY = "account-secret-vault.theme";
const AUTO_LOCK_KEY = "account-secret-vault.auto-lock-minutes";
const CACHE_DISABLED_KEY = "account-secret-vault.cache-disabled";
const KDF_ITERATIONS = 310000;
const AUTH_KDF_ITERATIONS = 120000;
const CLIPBOARD_CLEAR_MS = 30_000;
const GENERATED_PASSWORD_LENGTH = 20;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hasDocument = typeof document !== "undefined";

const state = {
  user: null,
  vault: null,
  key: null,
  salt: null,
  iterations: KDF_ITERATIONS,
  selectedId: null,
  saveTimer: null,
  saving: false,
  pulling: false,
  authenticating: false,
  dirty: false,
  remoteRevision: null,
  lastActivityAt: Date.now(),
  autoLockMinutes: 5,
  cacheDisabled: false,
  clipboardClearTimer: null,
  passwordVisible: false,
  totpVisible: false,
};

const $ = (id) => (hasDocument ? document.getElementById(id) : null);

const els = hasDocument
  ? {
      lockedView: $("lockedView"),
      vaultView: $("vaultView"),
      unlockForm: $("unlockForm"),
      loginEmail: $("loginEmail"),
      loginPassword: $("loginPassword"),
      inviteToken: $("inviteToken"),
      registerButton: $("registerButton"),
      themeToggleButton: $("themeToggleButton"),
      adminPanel: $("adminPanel"),
      adminSettingsStatus: $("adminSettingsStatus"),
      registrationOpenToggle: $("registrationOpenToggle"),
      createInviteButton: $("createInviteButton"),
      inviteLink: $("inviteLink"),
      unlockMessage: $("unlockMessage"),
      lockStatus: $("lockStatus"),
      syncStatus: $("syncStatus"),
      saveStatus: $("saveStatus"),
      searchInput: $("searchInput"),
      addEntryButton: $("addEntryButton"),
      entryList: $("entryList"),
      entryTemplate: $("entryTemplate"),
      entryForm: $("entryForm"),
      entryName: $("entryName"),
      entryLogin: $("entryLogin"),
      entryBackupEmail: $("entryBackupEmail"),
      entryBackupPhone: $("entryBackupPhone"),
      entryTags: $("entryTags"),
      entryPassword: $("entryPassword"),
      passwordStrength: $("passwordStrength"),
      generatePasswordButton: $("generatePasswordButton"),
      entryTotpSecret: $("entryTotpSecret"),
      entryRecoveryCodes: $("entryRecoveryCodes"),
      entryNotes: $("entryNotes"),
      togglePasswordButton: $("togglePasswordButton"),
      toggleTotpButton: $("toggleTotpButton"),
      deleteEntryButton: $("deleteEntryButton"),
      importFileInput: $("importFileInput"),
      importButton: $("importButton"),
      exportButton: $("exportButton"),
      changePasswordButton: $("changePasswordButton"),
      autoLockSelect: $("autoLockSelect"),
      localCacheToggle: $("localCacheToggle"),
      pullButton: $("pullButton"),
      saveButton: $("saveButton"),
      lockButton: $("lockButton"),
      totpCode: $("totpCode"),
      totpTimerBar: $("totpTimerBar"),
    }
  : {};

if (hasDocument) {
  init();
}

function init() {
  initDecorativeIcons();
  initTheme();
  initSecurityPreferences();
  els.loginEmail.value = localStorage.getItem(LAST_EMAIL_KEY) || "";
  els.inviteToken.value = new URLSearchParams(location.search).get("invite") || "";

  els.themeToggleButton.addEventListener("click", toggleTheme);
  els.registrationOpenToggle.addEventListener("change", saveAdminSettings);
  els.createInviteButton.addEventListener("click", createInvite);
  els.unlockForm.addEventListener("submit", (event) => {
    event.preventDefault();
    authenticate("login");
  });
  els.registerButton.addEventListener("click", () => authenticate("register"));
  els.searchInput.addEventListener("input", renderEntries);
  els.addEntryButton.addEventListener("click", addEntry);
  els.entryForm.addEventListener("input", handleEntryInput);
  els.generatePasswordButton.addEventListener("click", fillGeneratedPassword);
  els.togglePasswordButton.addEventListener("click", togglePassword);
  els.toggleTotpButton.addEventListener("click", toggleTotp);
  els.deleteEntryButton.addEventListener("click", deleteSelectedEntry);
  els.importButton.addEventListener("click", () => els.importFileInput.click());
  els.importFileInput.addEventListener("change", importVaultBackup);
  els.exportButton.addEventListener("click", exportVaultBackup);
  els.changePasswordButton.addEventListener("click", changeMasterPassword);
  els.autoLockSelect.addEventListener("change", saveAutoLockPreference);
  els.localCacheToggle.addEventListener("change", saveLocalCachePreference);
  els.saveButton.addEventListener("click", () => saveVaultNow(true));
  els.pullButton.addEventListener("click", pullRemoteVault);
  els.lockButton.addEventListener("click", logoutVault);

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-copy]");
    if (!button) return;
    copyInputValue(button.dataset.copy);
  });

  setInterval(updateTotpDisplay, 1000);
  setInterval(lockIfHiddenTooLong, 30_000);
  setInterval(lockIfIdleTooLong, 30_000);

  for (const eventName of ["pointerdown", "keydown", "input"]) {
    document.addEventListener(eventName, markActivity, true);
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      sessionStorage.removeItem("vault.hidden-at");
      markActivity();
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty && !state.saving) return;
    event.preventDefault();
    event.returnValue = "";
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
}

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
}

function saveAutoLockPreference() {
  const minutes = Number(els.autoLockSelect.value);
  state.autoLockMinutes = Number.isFinite(minutes) ? minutes : 5;
  localStorage.setItem(AUTO_LOCK_KEY, String(state.autoLockMinutes));
  markActivity();
}

function saveLocalCachePreference() {
  state.cacheDisabled = !els.localCacheToggle.checked;
  localStorage.setItem(CACHE_DISABLED_KEY, state.cacheDisabled ? "true" : "false");
  if (state.cacheDisabled && state.user) {
    localStorage.removeItem(getStorageKey(state.user.id));
    els.saveStatus.textContent = "已关闭本地缓存";
  } else if (state.user && state.vault && state.key) {
    saveVaultNow(false);
  }
}

function markActivity() {
  state.lastActivityAt = Date.now();
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
    selectEntry(state.vault.entries[0]?.id || null);
    if (selected.source === "local") {
      state.dirty = true;
      els.saveStatus.textContent = "本地版本较新，尚未同步";
    } else {
      await saveVaultNow(false);
    }
    els.loginPassword.value = "";
    setUnlockMessage("");
  } catch (error) {
    state.key = null;
    setUnlockMessage(error.message || "无法登录。");
  } finally {
    state.authenticating = false;
    setAuthButtonsDisabled(false);
  }
}

async function makeAuthSecret(email, password) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(`account-secret-vault auth v2\n${email}`),
      iterations: AUTH_KDF_ITERATIONS,
      hash: "SHA-256",
    },
    material,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

async function loadBestEnvelope() {
  const remote = await fetchRemoteVault();
  const localEnvelope = readLocalEnvelope();
  if (!remote.envelope && !localEnvelope) {
    return { envelope: null, remoteRevision: null, source: "empty" };
  }
  if (!remote.envelope) {
    return { envelope: localEnvelope, remoteRevision: localEnvelope?.remoteRevision || null, source: "local" };
  }
  if (!localEnvelope) {
    return { envelope: remote.envelope, remoteRevision: remote.revision, source: "remote" };
  }

  const localTime = envelopeTimestamp(localEnvelope);
  const remoteTime = envelopeTimestamp(remote.envelope, remote.updatedAt);
  if (localTime > remoteTime) {
    const useLocal = confirm("本地加密副本比 Cloudflare 上的版本更新。使用本地版本并稍后同步？");
    if (useLocal) {
      return { envelope: localEnvelope, remoteRevision: remote.revision, source: "local" };
    }
  }

  return { envelope: remote.envelope, remoteRevision: remote.revision, source: "remote" };
}

async function openEnvelope(password, envelope) {
  const salt = base64ToBytes(envelope.kdf.salt);
  const key = await deriveVaultKey(password, salt, envelope.kdf.iterations);
  const vault = await decryptVault(envelope, key);

  state.vault = normalizeVault(vault);
  state.key = key;
  state.salt = salt;
  state.iterations = envelope.kdf.iterations;
}

async function createEmptyVault(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveVaultKey(password, salt, KDF_ITERATIONS);
  const now = new Date().toISOString();

  state.vault = {
    version: 1,
    createdAt: now,
    updatedAt: now,
    entries: [createEntryRecord("Google 账号")],
  };
  state.key = key;
  state.salt = salt;
  state.iterations = KDF_ITERATIONS;
}

function normalizeVault(vault) {
  if (!vault || typeof vault !== "object") {
    throw new Error("保险箱内容无效。");
  }

  return {
    version: 1,
    createdAt: vault.createdAt || new Date().toISOString(),
    updatedAt: vault.updatedAt || new Date().toISOString(),
    entries: Array.isArray(vault.entries) ? vault.entries.map(normalizeEntry) : [],
  };
}

function normalizeEntry(entry) {
  return {
    id: entry.id || crypto.randomUUID(),
    name: entry.name || "",
    login: entry.login || "",
    password: entry.password || "",
    totpSecret: entry.totpSecret || "",
    recoveryCodes: entry.recoveryCodes || "",
    backupEmail: entry.backupEmail || "",
    backupPhone: entry.backupPhone || "",
    tags: entry.tags || "",
    notes: entry.notes || "",
    createdAt: entry.createdAt || new Date().toISOString(),
    updatedAt: entry.updatedAt || new Date().toISOString(),
  };
}

function showVault() {
  els.lockedView.classList.add("hidden");
  els.vaultView.classList.remove("hidden");
  setInlineLabel(els.lockStatus, "Unlocked");
  setInlineIcon(els.lockStatus, "icon-unlock");
  setInlineLabel(els.syncStatus, state.user.email);
  els.syncStatus.classList.remove("neutral");

  if (state.user.isAdmin) {
    els.adminPanel.classList.remove("hidden");
    loadAdminSettings();
  } else {
    els.adminPanel.classList.add("hidden");
  }
}

async function logoutVault() {
  clearTimeout(state.saveTimer);
  if (state.vault && state.key) {
    const saved = await saveVaultNow(false);
    if (!saved && state.dirty && !confirm("保险箱尚未同步到 Cloudflare，仍要退出？本地加密副本会尽量保留。")) {
      return;
    }
  }

  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  } catch {
    // Locking local state is still useful even if the network request fails.
  }

  lockVault();
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
  clearTimeout(state.clipboardClearTimer);

  els.entryForm.reset();
  resetSecretVisibility();
  els.adminPanel.classList.add("hidden");
  els.entryList.textContent = "";
  els.lockedView.classList.remove("hidden");
  els.vaultView.classList.add("hidden");
  setInlineLabel(els.lockStatus, "Locked");
  setInlineIcon(els.lockStatus, "icon-lock");
  setInlineLabel(els.syncStatus, "Signed out");
  els.syncStatus.classList.add("neutral");
  els.saveStatus.textContent = "未解锁";
  els.totpCode.textContent = "------";
  els.totpTimerBar.style.width = "0";
  updatePasswordStatus();
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

  const query = els.searchInput.value.trim().toLowerCase();
  els.entryList.textContent = "";

  const entries = state.vault.entries.filter((entry) => {
    const haystack = [
      entry.name,
      entry.login,
      entry.backupEmail,
      entry.backupPhone,
      entry.tags,
      entry.notes,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });

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
    use.setAttribute("href", "#icon-search");
    icon.append(use);
    title.textContent = query ? "没有匹配账号" : "还没有账号";
    hint.textContent = query ? "换个关键词试试" : "点击右上角新增账号";
    empty.append(icon, title, hint);
    els.entryList.append(empty);
    return;
  }

  for (const entry of entries) {
    const item = els.entryTemplate.content.firstElementChild.cloneNode(true);
    item.dataset.id = entry.id;
    item.classList.toggle("active", entry.id === state.selectedId);
    item.querySelector("strong").textContent = entry.name || "未命名账号";
    item.querySelector(".entry-meta").textContent = entry.login || entry.tags || "无登录名";
    initDecorativeIcons(item);
    item.addEventListener("click", () => selectEntry(entry.id));
    els.entryList.append(item);
  }
}

function selectEntry(id) {
  state.selectedId = id;
  const entry = getSelectedEntry();
  els.entryForm.reset();
  resetSecretVisibility();
  setFormDisabled(!entry);

  if (entry) {
    els.entryName.value = entry.name;
    els.entryLogin.value = entry.login;
    els.entryBackupEmail.value = entry.backupEmail;
    els.entryBackupPhone.value = entry.backupPhone;
    els.entryTags.value = entry.tags;
    els.entryPassword.value = entry.password;
    els.entryTotpSecret.value = entry.totpSecret;
    els.entryRecoveryCodes.value = entry.recoveryCodes;
    els.entryNotes.value = entry.notes;
  }

  renderEntries();
  updatePasswordStatus();
  updateTotpDisplay();
}

function setFormDisabled(disabled) {
  for (const control of els.entryForm.elements) {
    control.disabled = disabled;
  }
  els.deleteEntryButton.disabled = disabled;
}

function getSelectedEntry() {
  return state.vault?.entries.find((entry) => entry.id === state.selectedId) || null;
}

function handleEntryInput() {
  const entry = getSelectedEntry();
  if (!entry) return;

  entry.name = els.entryName.value;
  entry.login = els.entryLogin.value;
  entry.backupEmail = els.entryBackupEmail.value;
  entry.backupPhone = els.entryBackupPhone.value;
  entry.tags = els.entryTags.value;
  entry.password = els.entryPassword.value;
  const totp = parseTotpInput(els.entryTotpSecret.value);
  if (totp.secret !== els.entryTotpSecret.value) {
    els.entryTotpSecret.value = totp.secret;
  }
  if (totp.label && !entry.name.trim()) {
    entry.name = totp.label;
    els.entryName.value = totp.label;
  }
  entry.totpSecret = totp.secret;
  entry.recoveryCodes = els.entryRecoveryCodes.value;
  entry.notes = els.entryNotes.value;
  entry.updatedAt = new Date().toISOString();

  renderEntries();
  updatePasswordStatus();
  markDirty();
}

function addEntry() {
  if (!state.vault) return;
  const entry = createEntryRecord("新账号");
  state.vault.entries.unshift(entry);
  selectEntry(entry.id);
  els.entryName.focus();
  markDirty();
}

function createEntryRecord(name) {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    name,
    login: "",
    password: "",
    totpSecret: "",
    recoveryCodes: "",
    backupEmail: "",
    backupPhone: "",
    tags: "",
    notes: "",
    createdAt: now,
    updatedAt: now,
  };
}

function deleteSelectedEntry() {
  const entry = getSelectedEntry();
  if (!entry) return;
  if (!confirm(`删除“${entry.name || "未命名账号"}”？`)) return;

  state.vault.entries = state.vault.entries.filter((item) => item.id !== entry.id);
  selectEntry(state.vault.entries[0]?.id || null);
  markDirty();
}

function fillGeneratedPassword() {
  const entry = getSelectedEntry();
  if (!entry) return;

  const password = generatePassword(GENERATED_PASSWORD_LENGTH);
  els.entryPassword.value = password;
  entry.password = password;
  entry.updatedAt = new Date().toISOString();
  updatePasswordStatus();
  markDirty();
}

function updatePasswordStatus() {
  if (!hasDocument || !els.passwordStrength) return;
  const entry = getSelectedEntry();
  const password = entry?.password || els.entryPassword?.value || "";
  if (!password) {
    els.passwordStrength.textContent = "未填写密码";
    els.passwordStrength.dataset.level = "empty";
    return;
  }

  const strength = scorePassword(password);
  const duplicateCount = state.vault
    ? state.vault.entries.filter((item) => item.id !== entry?.id && item.password && item.password === password).length
    : 0;
  const duplicateText = duplicateCount ? `，与 ${duplicateCount} 个账号重复` : "";
  els.passwordStrength.textContent = `${strength.label}${duplicateText}`;
  els.passwordStrength.dataset.level = duplicateCount ? "duplicate" : strength.level;
}

function togglePassword() {
  state.passwordVisible = !state.passwordVisible;
  els.entryPassword.type = state.passwordVisible ? "text" : "password";
  setInlineLabel(els.togglePasswordButton, state.passwordVisible ? "隐藏" : "显示");
  setInlineIcon(els.togglePasswordButton, state.passwordVisible ? "icon-eye-off" : "icon-eye");
}

function toggleTotp() {
  state.totpVisible = !state.totpVisible;
  els.entryTotpSecret.type = state.totpVisible ? "text" : "password";
  setInlineLabel(els.toggleTotpButton, state.totpVisible ? "隐藏" : "显示");
  setInlineIcon(els.toggleTotpButton, state.totpVisible ? "icon-eye-off" : "icon-eye");
}

function markDirty() {
  if (!state.vault) return;
  state.dirty = true;
  els.saveStatus.textContent = "未保存";
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => saveVaultNow(false), 700);
}

async function saveVaultNow(manual) {
  if (!state.user || !state.vault || !state.key || state.saving) return false;

  clearTimeout(state.saveTimer);
  state.saveTimer = null;
  state.saving = true;
  updateBusyControls();
  els.saveStatus.textContent = "正在保存…";
  try {
    state.vault.updatedAt = new Date().toISOString();
    const envelope = await encryptVault(state.vault, state.key);
    envelope.remoteRevision = state.remoteRevision;
    writeLocalEnvelope(envelope);
    const saved = await putRemoteEnvelope(envelope, state.remoteRevision);
    state.remoteRevision = saved.revision;
    envelope.remoteRevision = saved.revision;
    envelope.updatedAt = saved.updatedAt || envelope.updatedAt;
    writeLocalEnvelope(envelope);
    state.dirty = false;
    els.saveStatus.textContent = "已同步到 Cloudflare";
    return true;
  } catch (error) {
    state.dirty = true;
    els.saveStatus.textContent = error.message || "保存失败";
    if (manual) alert(els.saveStatus.textContent);
    return false;
  } finally {
    state.saving = false;
    updateBusyControls();
  }
}

async function pullRemoteVault() {
  if (!state.user || !state.key) return;
  if (state.pulling) return;
  if (state.dirty && !confirm("当前有未保存修改，继续拉取会覆盖本地内容。继续？")) return;

  try {
    state.pulling = true;
    updateBusyControls();
    els.saveStatus.textContent = "正在拉取…";
    const remote = await fetchRemoteVault();
    if (!remote.envelope) {
      els.saveStatus.textContent = "远端没有保险箱";
      return;
    }

    if (remote.envelope.kdf.salt !== bytesToBase64(state.salt)) {
      els.saveStatus.textContent = "远端保险箱需要重新登录解锁";
      return;
    }

    state.vault = normalizeVault(await decryptVault(remote.envelope, state.key));
    state.remoteRevision = remote.revision;
    state.dirty = false;
    remote.envelope.remoteRevision = remote.revision;
    writeLocalEnvelope(remote.envelope);
    renderEntries();
    selectEntry(state.vault.entries[0]?.id || null);
    els.saveStatus.textContent = "已拉取远端密文";
  } catch (error) {
    els.saveStatus.textContent = error.message || "拉取失败";
  } finally {
    state.pulling = false;
    updateBusyControls();
  }
}

async function exportVaultBackup() {
  if (!state.user || !state.vault || !state.key) return;

  try {
    const envelope = await encryptVault(state.vault, state.key);
    envelope.remoteRevision = state.remoteRevision;
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `account-vault-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    els.saveStatus.textContent = "已导出加密备份";
  } catch (error) {
    els.saveStatus.textContent = error.message || "导出失败";
  }
}

async function importVaultBackup() {
  const file = els.importFileInput.files?.[0];
  els.importFileInput.value = "";
  if (!file || !state.user) return;

  try {
    const envelope = JSON.parse(await file.text());
    if (!isVaultEnvelope(envelope)) {
      throw new Error("备份文件不是有效的保险箱密文。");
    }

    const password = prompt("输入当前主密码以解密备份。");
    if (!password) return;

    const salt = base64ToBytes(envelope.kdf.salt);
    const key = await deriveVaultKey(password, salt, envelope.kdf.iterations);
    const vault = normalizeVault(await decryptVault(envelope, key));
    if (!confirm("导入会替换当前保险箱内容。继续？")) return;

    state.vault = vault;
    state.key = key;
    state.salt = salt;
    state.iterations = envelope.kdf.iterations;
    state.remoteRevision = envelope.remoteRevision || state.remoteRevision;
    state.dirty = true;
    renderEntries();
    selectEntry(state.vault.entries[0]?.id || null);
    await saveVaultNow(true);
  } catch (error) {
    els.saveStatus.textContent = error.message || "导入失败";
  }
}

async function changeMasterPassword() {
  if (!state.user || !state.vault) return;

  const currentPassword = prompt("输入当前主密码。");
  if (!currentPassword) return;
  const nextPassword = prompt("输入新的主密码，至少 10 个字符。");
  if (!nextPassword) return;
  if (nextPassword.length < 10) {
    alert("新主密码至少需要 10 个字符。");
    return;
  }
  const repeatedPassword = prompt("再次输入新的主密码。");
  if (nextPassword !== repeatedPassword) {
    alert("两次输入的新主密码不一致。");
    return;
  }

  try {
    els.saveStatus.textContent = "正在修改主密码…";
    const authSecret = await makeAuthSecret(state.user.email, currentPassword);
    const newAuthSecret = await makeAuthSecret(state.user.email, nextPassword);
    await postJson("/api/auth/change-password", { authSecret, newAuthSecret });

    const salt = crypto.getRandomValues(new Uint8Array(16));
    state.key = await deriveVaultKey(nextPassword, salt, KDF_ITERATIONS);
    state.salt = salt;
    state.iterations = KDF_ITERATIONS;
    state.dirty = true;
    const saved = await saveVaultNow(true);
    els.saveStatus.textContent = saved ? "主密码已修改并同步" : "主密码已修改，本地密文尚未同步";
  } catch (error) {
    els.saveStatus.textContent = error.message || "主密码修改失败";
  }
}

async function fetchRemoteVault() {
  const response = await fetch("/api/vault", { credentials: "same-origin" });
  const data = await readJsonResponse(response);
  if (!response.ok) throw new Error(data.error || "远端读取失败。");
  return {
    envelope: data.envelope || null,
    updatedAt: data.updatedAt || null,
    revision: data.revision || null,
  };
}

async function putRemoteEnvelope(envelope, baseRevision) {
  const response = await fetch("/api/vault", {
    method: "PUT",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ envelope, baseRevision }),
  });
  const data = await readJsonResponse(response);
  if (!response.ok) {
    const error = new Error(data.error || "远端保存失败。");
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const data = await readJsonResponse(response);
  if (!response.ok) throw new Error(data.error || "请求失败。");
  return data;
}

async function loadAdminSettings() {
  try {
    els.adminSettingsStatus.textContent = "正在读取注册设置...";
    const response = await fetch("/api/admin/settings", { credentials: "same-origin" });
    const data = await readJsonResponse(response);
    if (!response.ok) throw new Error(data.error || "无法读取管理员设置。");

    els.registrationOpenToggle.checked = Boolean(data.registrationOpen);
    els.adminSettingsStatus.textContent = data.registrationOpen ? "当前允许新用户注册" : "当前禁止新用户注册";
  } catch (error) {
    els.adminSettingsStatus.textContent = error.message || "管理员设置读取失败";
  }
}

async function saveAdminSettings() {
  try {
    els.adminSettingsStatus.textContent = "正在保存注册设置...";
    const response = await fetch("/api/admin/settings", {
      method: "PUT",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ registrationOpen: els.registrationOpenToggle.checked }),
    });
    const data = await readJsonResponse(response);
    if (!response.ok) throw new Error(data.error || "无法保存管理员设置。");

    els.registrationOpenToggle.checked = Boolean(data.registrationOpen);
    els.adminSettingsStatus.textContent = data.registrationOpen ? "当前允许新用户注册" : "当前禁止新用户注册";
  } catch (error) {
    els.adminSettingsStatus.textContent = error.message || "管理员设置保存失败";
    els.registrationOpenToggle.checked = !els.registrationOpenToggle.checked;
  }
}

async function createInvite() {
  try {
    els.adminSettingsStatus.textContent = "正在生成邀请链接...";
    const response = await fetch("/api/admin/invites", {
      method: "POST",
      credentials: "same-origin",
    });
    const data = await readJsonResponse(response);
    if (!response.ok) throw new Error(data.error || "无法生成邀请链接。");

    const inviteUrl = new URL(location.href);
    inviteUrl.searchParams.set("invite", data.token);
    els.inviteLink.value = inviteUrl.toString();
    await copyText(inviteUrl.toString());
    els.adminSettingsStatus.textContent = "邀请链接已生成并复制";
  } catch (error) {
    els.adminSettingsStatus.textContent = error.message || "邀请链接生成失败";
  }
}

async function readJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return { error: "远端响应不是 JSON。" };
  }
}

function readLocalEnvelope() {
  if (!state.user || state.cacheDisabled) return null;
  const raw = localStorage.getItem(getStorageKey(state.user.id));
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function writeLocalEnvelope(envelope) {
  if (!state.user) return;
  if (state.cacheDisabled) {
    localStorage.removeItem(getStorageKey(state.user.id));
    return;
  }
  localStorage.setItem(getStorageKey(state.user.id), JSON.stringify(envelope));
}

function getStorageKey(userId) {
  return `${STORAGE_PREFIX}${userId}`;
}

function envelopeTimestamp(envelope, fallback = null) {
  const value = envelope?.updatedAt || fallback;
  const timestamp = Date.parse(value || "");
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

async function deriveVaultKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVault(vault, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = encoder.encode(JSON.stringify(vault));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  return {
    version: 1,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations: state.iterations,
      salt: bytesToBase64(state.salt),
    },
    cipher: {
      name: "AES-GCM",
      iv: bytesToBase64(iv),
      data: bytesToBase64(new Uint8Array(encrypted)),
    },
    updatedAt: vault.updatedAt,
  };
}

async function decryptVault(envelope, key) {
  const iv = base64ToBytes(envelope.cipher.iv);
  const data = base64ToBytes(envelope.cipher.data);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(decoder.decode(decrypted));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    const chunk = bytes.subarray(offset, offset + 0x8000);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function updateTotpDisplay() {
  const entry = getSelectedEntry();
  const secret = entry?.totpSecret?.trim();
  const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
  els.totpTimerBar.style.width = `${(remaining / 30) * 100}%`;

  if (!secret) {
    els.totpCode.textContent = "------";
    return;
  }

  try {
    const code = await generateTotp(secret);
    els.totpCode.textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
  } catch {
    els.totpCode.textContent = "无效";
  }
}

async function generateTotp(secret, timestamp = Date.now()) {
  const keyBytes = base32ToBytes(secret);
  const counter = Math.floor(timestamp / 1000 / 30);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function base32ToBytes(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = "";

  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error("Invalid base32.");
    bits += value.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }

  if (!bytes.length) throw new Error("Invalid base32.");
  return new Uint8Array(bytes);
}

function parseTotpInput(input) {
  const value = String(input || "").trim();
  if (!value.toLowerCase().startsWith("otpauth://")) {
    return { secret: value, label: "" };
  }

  try {
    const url = new URL(value);
    const secret = url.searchParams.get("secret") || "";
    const issuer = url.searchParams.get("issuer") || "";
    const label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    return {
      secret: secret.replace(/\s/g, "").toUpperCase(),
      label: issuer || label,
    };
  } catch {
    return { secret: value, label: "" };
  }
}

function generatePassword(length = GENERATED_PASSWORD_LENGTH) {
  length = Math.max(4, Number(length) || GENERATED_PASSWORD_LENGTH);
  const groups = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%^&*()-_=+[]{}:,.?",
  ];
  const all = groups.join("");
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  const chars = groups.map((group, index) => group[bytes[index] % group.length]);

  for (let index = chars.length; index < length; index += 1) {
    chars.push(all[bytes[index] % all.length]);
  }

  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swapIndex = bytes[index] % (index + 1);
    [chars[index], chars[swapIndex]] = [chars[swapIndex], chars[index]];
  }

  return chars.join("");
}

function scorePassword(password) {
  const value = String(password || "");
  let score = 0;
  if (value.length >= 12) score += 1;
  if (value.length >= 16) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  if (/(.)\1{2,}/.test(value)) score -= 1;

  if (score >= 5) return { level: "strong", label: "强密码" };
  if (score >= 3) return { level: "medium", label: "中等强度" };
  return { level: "weak", label: "弱密码" };
}

function isVaultEnvelope(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      value.version === 1 &&
      value.kdf?.name === "PBKDF2-SHA256" &&
      Number.isInteger(value.kdf.iterations) &&
      value.kdf.iterations >= 100000 &&
      typeof value.kdf.salt === "string" &&
      value.cipher?.name === "AES-GCM" &&
      typeof value.cipher.iv === "string" &&
      typeof value.cipher.data === "string",
  );
}

async function copyInputValue(inputId) {
  const input = $(inputId);
  if (!input?.value) {
    els.saveStatus.textContent = "没有可复制的内容";
    return;
  }

  try {
    await copyText(input.value);
    els.saveStatus.textContent = "已复制";
  } catch {
    input.select();
    document.execCommand("copy");
    els.saveStatus.textContent = "已复制";
  }
}

async function copyText(text) {
  if (!navigator.clipboard?.writeText) return;
  await navigator.clipboard.writeText(text);
  scheduleClipboardClear(text);
}

function scheduleClipboardClear(value) {
  clearTimeout(state.clipboardClearTimer);
  if (!navigator.clipboard?.readText || !navigator.clipboard?.writeText) return;

  state.clipboardClearTimer = setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === value) {
        await navigator.clipboard.writeText("");
      }
    } catch {
      // Clipboard read permission is browser-controlled.
    }
  }, CLIPBOARD_CLEAR_MS);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function setUnlockMessage(message) {
  els.unlockMessage.textContent = message;
}

function setInlineLabel(element, text) {
  const label = element.querySelector("span:not(.sr-only)");
  if (label) {
    label.textContent = text;
    return;
  }
  element.textContent = text;
}

function setInlineIcon(element, iconId) {
  const use = element.querySelector("use");
  if (use) use.setAttribute("href", `#${iconId}`);
}

function initDecorativeIcons(root = document) {
  for (const icon of root.querySelectorAll(".icon")) {
    icon.setAttribute("aria-hidden", "true");
    icon.setAttribute("focusable", "false");
  }
}

function setAuthButtonsDisabled(disabled) {
  for (const button of els.unlockForm.querySelectorAll("button")) {
    button.disabled = disabled;
  }
}

function updateBusyControls() {
  els.saveButton.disabled = state.saving || state.pulling;
  els.pullButton.disabled = state.saving || state.pulling;
  els.lockButton.disabled = state.saving;
}

function resetSecretVisibility() {
  state.passwordVisible = false;
  state.totpVisible = false;
  els.entryPassword.type = "password";
  els.entryTotpSecret.type = "password";
  setInlineLabel(els.togglePasswordButton, "显示");
  setInlineIcon(els.togglePasswordButton, "icon-eye");
  setInlineLabel(els.toggleTotpButton, "显示");
  setInlineIcon(els.toggleTotpButton, "icon-eye");
}

export {
  base32ToBytes,
  bytesToBase64,
  generatePassword,
  generateTotp,
  isVaultEnvelope,
  makeAuthSecret,
  normalizeEmail,
  parseTotpInput,
  scorePassword,
};
