function dateValue(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 0 : date.getTime();
}

let passwordHistoryEntryId = "";
let passwordHistoryOriginal = "";
let passwordHistoryCaptured = false;

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
    ...(entry.favorite ? [{ label: "收藏", tone: "good" }] : []),
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
  if (entry.lastUsedAt) parts.push(`使用 ${formatShortDate(entry.lastUsedAt)}`);
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
  setPasswordHistorySnapshot(entry);
  renderFavoriteState(entry);
  renderPasswordHistory(entry);
  renderCustomFields(entry);

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
  els.addCustomFieldButton.disabled = disabled;
  els.favoriteEntryButton.disabled = disabled;
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
  entry.favorite = Boolean(entry.favorite);
  const nextPassword = els.entryPassword.value;
  maybeCaptureManualPasswordHistory(entry, nextPassword);
  entry.password = nextPassword;
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
  entry.customFields = readCustomFields();
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
    favorite: false,
    lastUsedAt: "",
    customFields: [],
    passwordHistory: [],
    createdAt: now,
    updatedAt: now,
  };
}

function renderFavoriteState(entry) {
  const active = Boolean(entry?.favorite);
  els.favoriteEntryButton.setAttribute("aria-pressed", active ? "true" : "false");
  els.favoriteEntryButton.dataset.active = active ? "true" : "false";
  setInlineLabel(els.favoriteEntryButton, active ? "已收藏" : "收藏");
}

function toggleFavoriteEntry() {
  const entry = getSelectedEntry();
  if (!entry) return;
  entry.favorite = !entry.favorite;
  entry.updatedAt = new Date().toISOString();
  renderFavoriteState(entry);
  renderEntries();
  markDirty();
  recordActivity(entry.favorite ? "favorite_entry" : "unfavorite_entry", entry.name || entry.login || "未命名账号");
}

function recordEntryUsageForCopy(inputId) {
  if (!["entryPassword", "entryTotpSecret"].includes(inputId)) return;
  const entry = getSelectedEntry();
  if (!entry) return;
  entry.lastUsedAt = new Date().toISOString();
  renderEntries();
  markDirty();
}

function setPasswordHistorySnapshot(entry) {
  passwordHistoryEntryId = entry?.id || "";
  passwordHistoryOriginal = entry?.password || "";
  passwordHistoryCaptured = false;
}

function maybeCaptureManualPasswordHistory(entry, nextPassword) {
  if (entry.id !== passwordHistoryEntryId) setPasswordHistorySnapshot(entry);
  if (passwordHistoryCaptured || !passwordHistoryOriginal || nextPassword === passwordHistoryOriginal) return;
  entry.passwordHistory = addPasswordHistoryEntry(entry.passwordHistory, passwordHistoryOriginal);
  passwordHistoryCaptured = true;
  renderPasswordHistory(entry);
}

function replaceEntryPassword(entry, nextPassword) {
  if (entry.password && entry.password !== nextPassword) {
    entry.passwordHistory = addPasswordHistoryEntry(entry.passwordHistory, entry.password);
  }
  entry.password = nextPassword;
  els.entryPassword.value = nextPassword;
  setPasswordHistorySnapshot(entry);
  renderPasswordHistory(entry);
}

function renderPasswordHistory(entry) {
  if (!els.passwordHistoryList) return;
  els.passwordHistoryList.textContent = "";
  if (!entry) return;

  entry.passwordHistory = normalizePasswordHistory(entry.passwordHistory);
  const history = entry.passwordHistory.filter((item) => item.password !== entry.password);
  if (!history.length) {
    const empty = document.createElement("span");
    empty.className = "password-history-empty";
    empty.textContent = "还没有旧密码。";
    els.passwordHistoryList.append(empty);
    return;
  }

  for (const item of history) {
    els.passwordHistoryList.append(createPasswordHistoryItem(item));
  }
}

function createPasswordHistoryItem(item) {
  const row = document.createElement("div");
  const meta = document.createElement("span");
  const title = document.createElement("strong");
  const detail = document.createElement("small");
  const actions = document.createElement("div");
  row.className = "password-history-item";
  title.textContent = "旧密码";
  detail.textContent = [formatDateTime(item.changedAt) || "未知时间", `${item.password.length} 位`].join(" / ");
  meta.append(title, detail);
  actions.className = "password-history-actions";
  actions.append(
    passwordHistoryButton(item.id, "copy", "复制"),
    passwordHistoryButton(item.id, "restore", "恢复"),
    passwordHistoryButton(item.id, "delete", "删除"),
  );
  row.append(meta, actions);
  return row;
}

function passwordHistoryButton(id, action, label) {
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.passwordHistoryId = id;
  button.dataset.passwordHistoryAction = action;
  button.textContent = label;
  return button;
}

async function handlePasswordHistoryAction(event) {
  const button = event.target.closest("button[data-password-history-action]");
  if (!button) return;
  const entry = getSelectedEntry();
  const item = normalizePasswordHistory(entry?.passwordHistory).find((history) => history.id === button.dataset.passwordHistoryId);
  if (!entry || !item) return;

  if (button.dataset.passwordHistoryAction === "copy") {
    await copyText(item.password);
    showToast("旧密码已复制", { message: "剪贴板会在短时间后尝试清空。", tone: "success" });
    return;
  }

  if (button.dataset.passwordHistoryAction === "restore") {
    entry.passwordHistory = normalizePasswordHistory(entry.passwordHistory).filter((history) => history.id !== item.id);
    replaceEntryPassword(entry, item.password);
    entry.updatedAt = new Date().toISOString();
    renderEntries();
    updatePasswordStatus();
    markDirty();
    recordActivity("restore_password", entry.name || entry.login || "未命名账号");
    showToast("已恢复旧密码", { tone: "success" });
    return;
  }

  entry.passwordHistory = normalizePasswordHistory(entry.passwordHistory).filter((history) => history.id !== item.id);
  entry.updatedAt = new Date().toISOString();
  renderPasswordHistory(entry);
  markDirty();
}

function renderCustomFields(entry) {
  if (!els.customFieldsList) return;
  els.customFieldsList.textContent = "";
  if (!entry) return;

  const fields = normalizeCustomFields(entry.customFields);
  if (!fields.length) {
    const empty = document.createElement("span");
    empty.className = "custom-fields-empty";
    empty.textContent = "还没有自定义字段。";
    els.customFieldsList.append(empty);
    return;
  }

  for (const field of fields) {
    appendCustomFieldRow(field);
  }
}

function appendCustomFieldRow(field) {
  const row = document.createElement("div");
  const label = document.createElement("input");
  const value = document.createElement("input");
  const remove = document.createElement("button");
  row.className = "custom-field-row";
  row.dataset.fieldId = field.id || crypto.randomUUID();
  label.type = "text";
  label.name = "customFieldLabel";
  label.placeholder = "字段名";
  label.autocomplete = "off";
  label.value = field.label || "";
  value.type = "text";
  value.name = "customFieldValue";
  value.placeholder = "字段值";
  value.autocomplete = "off";
  value.value = field.value || "";
  remove.type = "button";
  remove.className = "custom-field-remove";
  remove.dataset.customFieldRemove = "true";
  remove.setAttribute("aria-label", "删除自定义字段");
  remove.innerHTML = '<svg class="icon"><use href="/icons.svg#icon-trash"></use></svg><span>删除</span>';
  row.append(label, value, remove);
  els.customFieldsList.append(row);
  initDecorativeIcons(row);
  return row;
}

function readCustomFields() {
  return Array.from(els.customFieldsList.querySelectorAll(".custom-field-row"))
    .map((row) => ({
      id: row.dataset.fieldId || crypto.randomUUID(),
      label: row.querySelector('input[name="customFieldLabel"]')?.value || "",
      value: row.querySelector('input[name="customFieldValue"]')?.value || "",
    }))
    .filter((field) => field.label.trim() || field.value.trim());
}

function addCustomField() {
  if (!getSelectedEntry()) return;
  const empty = els.customFieldsList.querySelector(".custom-fields-empty");
  empty?.remove();
  const row = appendCustomFieldRow({ id: crypto.randomUUID(), label: "", value: "" });
  row.querySelector("input")?.focus();
}

function handleCustomFieldAction(event) {
  const button = event.target.closest("button[data-custom-field-remove]");
  if (!button) return;
  button.closest(".custom-field-row")?.remove();
  const entry = getSelectedEntry();
  if (!entry) return;
  entry.customFields = readCustomFields();
  if (!entry.customFields.length) renderCustomFields(entry);
  entry.updatedAt = new Date().toISOString();
  renderEntries();
  markDirty();
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

  moveEntryToTrash(state.vault, entry.id);
  selectEntry(state.vault.entries[0]?.id || null, { openDetail: Boolean(state.vault.entries.length) });
  markDirty();
  recordActivity("delete_entry", entry.name || entry.login || "未命名账号");
  showToast("已移到回收站", { message: "可在设置中恢复或永久删除。", tone: "warning" });
}

function fillGeneratedPassword() {
  const entry = getSelectedEntry();
  if (!entry) return;

  savePasswordGeneratorOptions();
  const password = generatePassword(getPasswordGeneratorOptions());
  replaceEntryPassword(entry, password);
  entry.updatedAt = new Date().toISOString();
  updatePasswordStatus();
  markDirty();
  recordActivity("generate_password", entry.name || entry.login || "未命名账号");
  showToast("已生成新密码", { message: `${password.length} 位`, tone: "success" });
}

