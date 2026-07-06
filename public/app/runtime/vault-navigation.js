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
    const useLocal = await confirmDialog("本地加密副本比 Cloudflare 上的版本更新。使用本地版本并稍后同步？", {
      title: "使用本地版本",
      confirmLabel: "使用本地",
      cancelLabel: "使用远端",
    });
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
    lastBackupAt: "",
    entries: [],
    trash: [],
  };
  state.key = key;
  state.salt = salt;
  state.iterations = KDF_ITERATIONS;
}

function showVault() {
  els.lockedView.classList.add("hidden");
  els.appNav.classList.remove("hidden");
  showAppPage(getHashAppPage(), { replaceHash: true });
  setInlineLabel(els.lockStatus, "已解锁");
  setInlineIcon(els.lockStatus, "icon-unlock");
  setInlineLabel(els.syncStatus, state.user.email);
  els.syncStatus.classList.remove("neutral");
  els.sessionStatus.classList.remove("hidden");
  updateSessionStatus();
  loadActivityLog();
  renderOverview();
  renderSecurityCheck();
  renderBackupStatus();
  renderBackupWizard();
  updateLocalCacheDetail();
  maybeShowBackupReminder();

  if (state.user.isAdmin) {
    els.adminPanel.classList.remove("hidden");
    els.adminSettingsTab.classList.remove("hidden");
    loadAdminSettings();
    loadInviteList();
    loadAuditLog();
  } else {
    els.adminPanel.classList.add("hidden");
    els.adminSettingsTab.classList.add("hidden");
    if (state.settingsSection === "admin") showSettingsSection("security");
  }
}

function navigateToAppPage(page) {
  if (!state.vault) return;
  showAppPage(page);
}

function getHashAppPage() {
  return normalizeAppPage(location.hash.replace("#", ""));
}

function syncAppPageFromHash() {
  if (!state.vault) return;
  showAppPage(getHashAppPage(), { updateHash: false });
}

function showAppPage(page, options = {}) {
  const nextPage = normalizeAppPage(page);
  state.appPage = nextPage;
  updateAppHash(nextPage, options);

  for (const view of [els.overviewView, els.vaultView, els.securityView, els.backupView, els.settingsView]) {
    view.classList.toggle("hidden", view.id !== `${nextPage}View`);
  }

  for (const button of getAvailableAppNavButtons()) {
    setNavButtonState(button, button.dataset.appPage === nextPage);
  }

  if (nextPage === "overview") {
    renderOverview();
  } else if (nextPage === "vault") {
    setMobileVaultPanel(state.mobilePanel || "list");
  } else if (nextPage === "security") {
    renderSecurityCheck();
  } else if (nextPage === "backup") {
    renderBackupStatus();
    renderBackupWizard();
  } else if (nextPage === "settings") {
    showSettingsSection(state.settingsSection);
  }
}

function normalizeAppPage(page) {
  return APP_PAGES.includes(page) ? page : "overview";
}

function updateAppHash(page, options) {
  if (options.updateHash === false) return;
  const nextHash = `#${page}`;
  if (location.hash === nextHash) return;
  const url = new URL(location.href);
  url.hash = page;
  const method = options.replaceHash ? "replaceState" : "pushState";
  history[method](null, "", url);
}

function setNavButtonState(button, active) {
  button.dataset.active = active ? "true" : "false";
  button.setAttribute("aria-pressed", active ? "true" : "false");
  if (active) {
    button.setAttribute("aria-current", "page");
  } else {
    button.removeAttribute("aria-current");
  }
}

function setMobileVaultPanel(panel) {
  state.mobilePanel = panel === "detail" ? "detail" : "list";
  els.vaultView.dataset.mobilePanel = state.mobilePanel;
}

function handleAppNavKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const buttons = getAvailableAppNavButtons();
  if (!buttons.length) return;
  event.preventDefault();
  const currentIndex = Math.max(0, buttons.findIndex((button) => button.dataset.active === "true"));
  let nextIndex = currentIndex;
  if (event.key === "ArrowLeft") nextIndex = Math.max(0, currentIndex - 1);
  if (event.key === "ArrowRight") nextIndex = Math.min(buttons.length - 1, currentIndex + 1);
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = buttons.length - 1;
  showAppPage(buttons[nextIndex].dataset.appPage);
  buttons[nextIndex].focus();
}

