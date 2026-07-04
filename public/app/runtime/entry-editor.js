function dateValue(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 0 : date.getTime();
}

function entryDisplayName(entry) {
  return String(entry.name || entry.login || "未命名账号").toLowerCase();
}

function renderTagFilters() {
  if (!state.vault || !els.tagFilter) return;
  const tags = getVaultTags(state.vault);
  if (state.selectedTag && !tags.includes(state.selectedTag)) {
    state.selectedTag = "";
  }

  els.tagFilter.textContent = "";
  if (!tags.length) return;
  const allButton = createTagButton("", `全部 ${state.vault.entries.length}`);
  els.tagFilter.append(allButton);
  for (const tag of tags) {
    const count = state.vault.entries.filter((entry) => parseEntryTags(entry.tags).includes(tag)).length;
    els.tagFilter.append(createTagButton(tag, `${tag} ${count}`));
  }
}

function createTagButton(tag, label) {
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.tag = tag;
  button.dataset.active = state.selectedTag === tag ? "true" : "false";
  button.textContent = label;
  return button;
}

function handleTagFilterClick(event) {
  const button = event.target.closest("button[data-tag]");
  if (!button) return;
  state.selectedTag = button.dataset.tag || "";
  renderEntries();
  setMobileVaultPanel("list");
}

function renderEntryBadges(container, entry) {
  container.textContent = "";
  const badges = [
    { label: entry.password ? "密码" : "无密码", tone: entry.password ? "good" : "warn" },
    { label: entry.totpSecret ? "2FA" : "无2FA", tone: entry.totpSecret ? "good" : "warn" },
    { label: entry.recoveryCodes ? "恢复码" : "无恢复码", tone: entry.recoveryCodes ? "good" : "warn" },
  ];
  for (const badge of badges) {
    const item = document.createElement("span");
    item.className = "entry-badge";
    item.dataset.tone = badge.tone;
    item.textContent = badge.label;
    container.append(item);
  }
}

function formatEntryMeta(entry) {
  const parts = [];
  if (entry.login) parts.push(entry.login);
  if (entry.tags) parts.push(entry.tags);
  if (entry.updatedAt) parts.push(`更新 ${formatShortDate(entry.updatedAt)}`);
  return parts.join(" / ") || "无登录名";
}

function formatShortDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "未知";
  return `${date.getMonth() + 1}/${date.getDate()}`;
}

function selectEntry(id, options = {}) {
  state.selectedId = id;
  const entry = getSelectedEntry();
  els.entryForm.reset();
  resetSecretVisibility();
  setFormDisabled(!entry);
  els.entryForm.classList.toggle("hidden", !entry);
  els.detailBottomBar.classList.toggle("hidden", !entry);
  els.detailEmptyState.classList.toggle("hidden", Boolean(entry));

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

  showDetailSection(state.detailSection);
  if (entry && options.openDetail !== false) {
    setMobileVaultPanel("detail");
  } else if (!entry) {
    setMobileVaultPanel("detail");
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
  state.securityFilterIds = null;
  state.securityFilterLabel = "";
  state.riskOnly = false;
  els.riskOnlyToggle.checked = false;
  const entry = createEntryRecord("新账号");
  state.vault.entries.unshift(entry);
  state.detailSection = "identity";
  selectEntry(entry.id, { openDetail: true });
  els.entryName.focus();
  markDirty();
  recordActivity("add_entry", entry.name);
  showToast("已新增账号", { message: "填写后会自动保存。" });
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

async function deleteSelectedEntry() {
  const entry = getSelectedEntry();
  if (!entry) return;
  if (
    !(await confirmDialog(`删除“${entry.name || "未命名账号"}”？`, {
      title: "删除账号",
      confirmLabel: "删除",
      danger: true,
    }))
  ) {
    return;
  }

  state.vault.entries = state.vault.entries.filter((item) => item.id !== entry.id);
  selectEntry(state.vault.entries[0]?.id || null, { openDetail: Boolean(state.vault.entries.length) });
  markDirty();
  recordActivity("delete_entry", entry.name || entry.login || "未命名账号");
  showToast("账号已删除", { tone: "warning" });
}

function fillGeneratedPassword() {
  const entry = getSelectedEntry();
  if (!entry) return;

  savePasswordGeneratorOptions();
  const password = generatePassword(getPasswordGeneratorOptions());
  els.entryPassword.value = password;
  entry.password = password;
  entry.updatedAt = new Date().toISOString();
  updatePasswordStatus();
  markDirty();
  recordActivity("generate_password", entry.name || entry.login || "未命名账号");
  showToast("已生成新密码", { message: `${password.length} 位`, tone: "success" });
}

