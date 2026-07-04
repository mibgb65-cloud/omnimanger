function confirmDialog(message, options = {}) {
  return openDialog({
    title: options.title || "确认操作",
    message,
    confirmLabel: options.confirmLabel || "确认",
    cancelLabel: options.cancelLabel || "取消",
    danger: Boolean(options.danger),
  }).then(Boolean);
}

async function alertDialog(message, options = {}) {
  await openDialog({
    title: options.title || "提示",
    message,
    confirmLabel: options.confirmLabel || "知道了",
    cancelLabel: "",
    icon: options.icon || "icon-shield",
  });
}

async function promptPasswordDialog(message, options = {}) {
  const values = await openDialog({
    title: options.title || "输入主密码",
    message,
    fields: [
      {
        name: "password",
        label: options.label || "主密码",
        type: "password",
        autocomplete: options.autocomplete || "current-password",
        minLength: options.minLength || 1,
      },
    ],
    confirmLabel: options.confirmLabel || "继续",
    validate: (values) => (values.password ? "" : "请输入主密码。"),
  });
  return values?.password || "";
}

function changePasswordDialog() {
  return openDialog({
    title: "修改主密码",
    message: "修改后会用新主密码重新加密整个保险箱。",
    fields: [
      {
        name: "currentPassword",
        label: "当前主密码",
        type: "password",
        autocomplete: "current-password",
      },
      {
        name: "nextPassword",
        label: "新主密码",
        type: "password",
        autocomplete: "new-password",
        minLength: 10,
        hint: "主密码强度会在输入后显示。",
      },
      {
        name: "repeatedPassword",
        label: "再次输入新主密码",
        type: "password",
        autocomplete: "new-password",
        minLength: 10,
      },
    ],
    confirmLabel: "修改",
    afterRender: (controls) => {
      const updateHint = () => {
        controls.nextPasswordHint.textContent = controls.nextPassword.value
          ? formatMasterPasswordStrength(controls.nextPassword.value)
          : "主密码强度会在输入后显示。";
        controls.nextPasswordHint.dataset.level = controls.nextPassword.value
          ? scorePassword(controls.nextPassword.value).level
          : "empty";
      };
      controls.nextPassword.addEventListener("input", updateHint);
      updateHint();
    },
    validate: (values) => {
      if (!values.currentPassword) return "请输入当前主密码。";
      if (!values.nextPassword || values.nextPassword.length < 10) return "新主密码至少需要 10 个字符。";
      if (values.nextPassword !== values.repeatedPassword) return "两次输入的新主密码不一致。";
      return "";
    },
  });
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
    updateLocalCacheDetail();
    return;
  }
  localStorage.setItem(getStorageKey(state.user.id), JSON.stringify(envelope));
  updateLocalCacheDetail();
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
  return encryptVaultWith(vault, key, state.salt, state.iterations);
}

async function encryptVaultWith(vault, key, salt, iterations) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = encoder.encode(JSON.stringify(vault));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  return {
    schemaVersion: 1,
    version: 1,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations,
      salt: bytesToBase64(salt),
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

