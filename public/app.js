const STORAGE_PREFIX = "account-secret-vault.envelope.";
const TOKEN_PREFIX = "account-secret-vault.sync-token.";
const KDF_ITERATIONS = 310000;
const VAULT_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{5,79}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  vault: null,
  key: null,
  salt: null,
  iterations: KDF_ITERATIONS,
  vaultId: "",
  syncToken: "",
  selectedId: null,
  saveTimer: null,
  saving: false,
  remoteEnabled: false,
  passwordVisible: false,
  totpVisible: false,
};

const $ = (id) => document.getElementById(id);

const els = {
  lockedView: $("lockedView"),
  vaultView: $("vaultView"),
  unlockForm: $("unlockForm"),
  vaultId: $("vaultId"),
  generateVaultIdButton: $("generateVaultIdButton"),
  masterPassword: $("masterPassword"),
  syncToken: $("syncToken"),
  rememberToken: $("rememberToken"),
  localOnlyButton: $("localOnlyButton"),
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
  entryTotpSecret: $("entryTotpSecret"),
  entryRecoveryCodes: $("entryRecoveryCodes"),
  entryNotes: $("entryNotes"),
  togglePasswordButton: $("togglePasswordButton"),
  toggleTotpButton: $("toggleTotpButton"),
  deleteEntryButton: $("deleteEntryButton"),
  pullButton: $("pullButton"),
  saveButton: $("saveButton"),
  lockButton: $("lockButton"),
  totpCode: $("totpCode"),
  totpTimerBar: $("totpTimerBar"),
};

init();

function init() {
  els.vaultId.value = getInitialVaultId();
  const rememberedToken = localStorage.getItem(getTokenKey(els.vaultId.value));
  if (rememberedToken) {
    els.syncToken.value = rememberedToken;
    els.rememberToken.checked = true;
  }

  els.vaultId.addEventListener("input", handleVaultIdInput);
  els.generateVaultIdButton.addEventListener("click", generateVaultId);
  els.unlockForm.addEventListener("submit", (event) => {
    event.preventDefault();
    unlockVault(false);
  });

  els.localOnlyButton.addEventListener("click", () => unlockVault(true));
  els.searchInput.addEventListener("input", renderEntries);
  els.addEntryButton.addEventListener("click", addEntry);
  els.entryForm.addEventListener("input", handleEntryInput);
  els.togglePasswordButton.addEventListener("click", togglePassword);
  els.toggleTotpButton.addEventListener("click", toggleTotp);
  els.deleteEntryButton.addEventListener("click", deleteSelectedEntry);
  els.saveButton.addEventListener("click", () => saveVaultNow(true));
  els.pullButton.addEventListener("click", pullRemoteVault);
  els.lockButton.addEventListener("click", lockVault);

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-copy]");
    if (!button) return;
    copyInputValue(button.dataset.copy);
  });

  setInterval(updateTotpDisplay, 1000);
  setInterval(lockIfHiddenTooLong, 30_000);
}

async function unlockVault(localOnly) {
  const vaultId = normalizeVaultId(els.vaultId.value);
  if (!VAULT_ID_PATTERN.test(vaultId)) {
    setUnlockMessage("保险箱 ID 需要 6-80 位，只能包含字母、数字、短横线或下划线。");
    return;
  }

  const password = els.masterPassword.value;
  if (password.length < 10) {
    setUnlockMessage("主密码至少需要 10 个字符。");
    return;
  }

  state.vaultId = vaultId;
  state.syncToken = localOnly ? "" : els.syncToken.value.trim();
  state.remoteEnabled = Boolean(state.syncToken);
  localStorage.setItem("account-secret-vault.last-vault-id", state.vaultId);
  setUnlockMessage("正在解锁...");

  if (els.rememberToken.checked && state.syncToken) {
    localStorage.setItem(getTokenKey(state.vaultId), state.syncToken);
  } else {
    localStorage.removeItem(getTokenKey(state.vaultId));
  }

  try {
    const envelope = await loadBestEnvelope();
    if (envelope) {
      await openEnvelope(password, envelope);
    } else {
      await createEmptyVault(password);
    }

    showVault();
    renderEntries();
    selectEntry(state.vault.entries[0]?.id || null);
    await saveVaultNow(false);
    setUnlockMessage("");
  } catch (error) {
    state.key = null;
    setUnlockMessage(error.message || "无法解锁保险箱。");
  }
}

async function loadBestEnvelope() {
  if (state.remoteEnabled) {
    const remoteEnvelope = await fetchRemoteEnvelope();
    if (remoteEnvelope) return remoteEnvelope;
  }

  return readLocalEnvelope();
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
  els.lockStatus.textContent = "Unlocked";
  els.syncStatus.textContent = state.remoteEnabled ? "Cloudflare" : "Local";
  els.syncStatus.classList.toggle("neutral", !state.remoteEnabled);
  els.masterPassword.value = "";
}

function lockVault() {
  clearTimeout(state.saveTimer);
  state.vault = null;
  state.key = null;
  state.salt = null;
  state.selectedId = null;
  state.vaultId = "";
  state.passwordVisible = false;
  state.totpVisible = false;

  els.entryForm.reset();
  els.entryList.textContent = "";
  els.lockedView.classList.remove("hidden");
  els.vaultView.classList.add("hidden");
  els.lockStatus.textContent = "Locked";
  els.syncStatus.textContent = "Local";
  els.syncStatus.classList.add("neutral");
  els.saveStatus.textContent = "未解锁";
  els.totpCode.textContent = "------";
  els.totpTimerBar.style.width = "0";
}

function lockIfHiddenTooLong() {
  if (document.visibilityState !== "hidden" || !state.vault) return;
  const hiddenAt = Number(sessionStorage.getItem("vault.hidden-at") || "0");
  if (!hiddenAt) {
    sessionStorage.setItem("vault.hidden-at", String(Date.now()));
    return;
  }
  if (Date.now() - hiddenAt > 5 * 60 * 1000) {
    sessionStorage.removeItem("vault.hidden-at");
    lockVault();
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    sessionStorage.removeItem("vault.hidden-at");
  }
});

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

  for (const entry of entries) {
    const item = els.entryTemplate.content.firstElementChild.cloneNode(true);
    item.dataset.id = entry.id;
    item.classList.toggle("active", entry.id === state.selectedId);
    item.querySelector("strong").textContent = entry.name || "未命名账号";
    item.querySelector("span").textContent = entry.login || entry.tags || "无登录名";
    item.addEventListener("click", () => selectEntry(entry.id));
    els.entryList.append(item);
  }
}

function selectEntry(id) {
  state.selectedId = id;
  const entry = getSelectedEntry();
  els.entryForm.reset();
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
  entry.totpSecret = els.entryTotpSecret.value;
  entry.recoveryCodes = els.entryRecoveryCodes.value;
  entry.notes = els.entryNotes.value;
  entry.updatedAt = new Date().toISOString();

  renderEntries();
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

function togglePassword() {
  state.passwordVisible = !state.passwordVisible;
  els.entryPassword.type = state.passwordVisible ? "text" : "password";
  els.togglePasswordButton.textContent = state.passwordVisible ? "隐藏" : "显示";
}

function toggleTotp() {
  state.totpVisible = !state.totpVisible;
  els.entryTotpSecret.type = state.totpVisible ? "text" : "password";
  els.toggleTotpButton.textContent = state.totpVisible ? "隐藏" : "显示";
}

function markDirty() {
  if (!state.vault) return;
  els.saveStatus.textContent = "未保存";
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => saveVaultNow(false), 700);
}

async function saveVaultNow(manual) {
  if (!state.vault || !state.key || state.saving) return;

  state.saving = true;
  els.saveStatus.textContent = "正在保存...";
  try {
    state.vault.updatedAt = new Date().toISOString();
    const envelope = await encryptVault(state.vault, state.key);
    localStorage.setItem(getStorageKey(state.vaultId), JSON.stringify(envelope));

    if (state.remoteEnabled) {
      await putRemoteEnvelope(envelope);
      els.saveStatus.textContent = "已同步到 Cloudflare";
    } else {
      els.saveStatus.textContent = "已保存到此浏览器";
    }
  } catch (error) {
    els.saveStatus.textContent = error.message || "保存失败";
    if (manual) alert(els.saveStatus.textContent);
  } finally {
    state.saving = false;
  }
}

async function pullRemoteVault() {
  if (!state.remoteEnabled) {
    els.saveStatus.textContent = "当前是本地模式";
    return;
  }

  try {
    els.saveStatus.textContent = "正在拉取...";
    const envelope = await fetchRemoteEnvelope();
    if (!envelope) {
      els.saveStatus.textContent = "远端没有保险箱";
      return;
    }

    if (envelope.kdf.salt !== bytesToBase64(state.salt)) {
      els.saveStatus.textContent = "远端保险箱需要重新解锁";
      return;
    }

    state.vault = normalizeVault(await decryptVault(envelope, state.key));
    localStorage.setItem(getStorageKey(state.vaultId), JSON.stringify(envelope));
    renderEntries();
    selectEntry(state.vault.entries[0]?.id || null);
    els.saveStatus.textContent = "已拉取远端密文";
  } catch (error) {
    els.saveStatus.textContent = error.message || "拉取失败";
  }
}

async function fetchRemoteEnvelope() {
  const response = await fetch(`/api/vault/${encodeURIComponent(state.vaultId)}`, {
    headers: { Authorization: `Bearer ${state.syncToken}` },
  });
  const data = await readJsonResponse(response);
  if (!response.ok) throw new Error(data.error || "远端读取失败。");
  return data.envelope;
}

async function putRemoteEnvelope(envelope) {
  const response = await fetch(`/api/vault/${encodeURIComponent(state.vaultId)}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${state.syncToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(envelope),
  });
  const data = await readJsonResponse(response);
  if (!response.ok) throw new Error(data.error || "远端保存失败。");
  return data;
}

async function readJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return { error: "远端响应不是 JSON。" };
  }
}

function readLocalEnvelope() {
  const raw = localStorage.getItem(getStorageKey(state.vaultId));
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function handleVaultIdInput() {
  const vaultId = normalizeVaultId(els.vaultId.value);
  els.syncToken.value = localStorage.getItem(getTokenKey(vaultId)) || "";
  els.rememberToken.checked = Boolean(els.syncToken.value);
}

function generateVaultId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  els.vaultId.value = `vault-${suffix}`;
  handleVaultIdInput();
  els.masterPassword.focus();
}

function getInitialVaultId() {
  const params = new URLSearchParams(window.location.search);
  const fromUrl = normalizeVaultId(params.get("vault") || "");
  if (VAULT_ID_PATTERN.test(fromUrl)) return fromUrl;

  const remembered = localStorage.getItem("account-secret-vault.last-vault-id") || "";
  if (VAULT_ID_PATTERN.test(remembered)) return remembered;

  return `vault-${crypto.randomUUID().slice(0, 8)}`;
}

function normalizeVaultId(value) {
  return String(value || "").trim();
}

function getStorageKey(vaultId) {
  return `${STORAGE_PREFIX}${vaultId}`;
}

function getTokenKey(vaultId) {
  return `${TOKEN_PREFIX}${vaultId}`;
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

async function generateTotp(secret) {
  const keyBytes = base32ToBytes(secret);
  const counter = Math.floor(Date.now() / 1000 / 30);
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

async function copyInputValue(inputId) {
  const input = $(inputId);
  if (!input?.value) return;

  try {
    await navigator.clipboard.writeText(input.value);
    els.saveStatus.textContent = "已复制";
  } catch {
    input.select();
    document.execCommand("copy");
    els.saveStatus.textContent = "已复制";
  }
}

function setUnlockMessage(message) {
  els.unlockMessage.textContent = message;
}
