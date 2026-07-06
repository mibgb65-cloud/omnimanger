function togglePassword() {
  state.passwordVisible = !state.passwordVisible;
  els.entryPassword.type = state.passwordVisible ? "text" : "password";
  setInlineLabel(els.togglePasswordButton, state.passwordVisible ? "隐藏" : "显示");
  setInlineIcon(els.togglePasswordButton, state.passwordVisible ? "icon-eye-off" : "icon-eye");
  els.togglePasswordButton.setAttribute("aria-pressed", state.passwordVisible ? "true" : "false");
  scheduleSecretAutoHide("password");
}

function toggleTotp() {
  state.totpVisible = !state.totpVisible;
  els.entryTotpSecret.type = state.totpVisible ? "text" : "password";
  setInlineLabel(els.toggleTotpButton, state.totpVisible ? "隐藏" : "显示");
  setInlineIcon(els.toggleTotpButton, state.totpVisible ? "icon-eye-off" : "icon-eye");
  els.toggleTotpButton.setAttribute("aria-pressed", state.totpVisible ? "true" : "false");
  scheduleSecretAutoHide("totp");
}

function scheduleSecretAutoHide(kind) {
  const visible = kind === "password" ? state.passwordVisible : state.totpVisible;
  const timerKey = kind === "password" ? "passwordRevealTimer" : "totpRevealTimer";
  clearTimeout(state[timerKey]);
  if (!visible) return;
  state[timerKey] = window.setTimeout(() => hideSecret(kind), SECRET_REVEAL_MS);
}

function hideSecret(kind) {
  if (kind === "password" && state.passwordVisible) {
    state.passwordVisible = false;
    els.entryPassword.type = "password";
    setInlineLabel(els.togglePasswordButton, "显示");
    setInlineIcon(els.togglePasswordButton, "icon-eye");
    els.togglePasswordButton.setAttribute("aria-pressed", "false");
  }

  if (kind === "totp" && state.totpVisible) {
    state.totpVisible = false;
    els.entryTotpSecret.type = "password";
    setInlineLabel(els.toggleTotpButton, "显示");
    setInlineIcon(els.toggleTotpButton, "icon-eye");
    els.toggleTotpButton.setAttribute("aria-pressed", "false");
  }
}

function hideVisibleSecrets() {
  hideSecret("password");
  hideSecret("totp");
}

function markDirty() {
  if (!state.vault) return;
  state.dirty = true;
  setSaveStatus("未保存", "dirty");
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => saveVaultNow(false), 700);
}

async function saveVaultNow(manual) {
  if (!state.user || !state.vault || !state.key || state.saving) return false;

  clearTimeout(state.saveTimer);
  state.saveTimer = null;
  state.saving = true;
  updateBusyControls();
  setSaveStatus("正在保存…", "saving");
  try {
    state.vault.updatedAt = new Date().toISOString();
    const envelope = await encryptVault(state.vault, state.key);
    envelope.remoteRevision = state.remoteRevision;
    writeLocalEnvelope(envelope);

    if (!state.online) {
      state.dirty = true;
      setSaveStatus("离线：已保存到本机", "offline");
      if (manual) showToast("已保存到本机", { message: "联网后再保存即可同步到 Cloudflare。", tone: "warning" });
      return false;
    }

    const saved = await putRemoteEnvelope(envelope, state.remoteRevision);
    state.remoteRevision = saved.revision;
    envelope.remoteRevision = saved.revision;
    envelope.updatedAt = saved.updatedAt || envelope.updatedAt;
    writeLocalEnvelope(envelope);
    state.dirty = false;
    setSaveStatus("已同步到 Cloudflare", "synced");
    if (manual) showToast("已同步", { message: "加密密文已保存到 Cloudflare。", tone: "success" });
    return true;
  } catch (error) {
    state.dirty = true;
    const conflict = error.status === 409;
    const message = conflict ? "远端有更新，需先拉取" : error.message || "保存失败";
    setSaveStatus(message, conflict ? "conflict" : "error");
    showToast(conflict ? "保存冲突" : "保存失败", { message, tone: "danger" });
    if (conflict && manual) {
      await resolveSaveConflict();
    } else if (manual) {
      await alertDialog(message, { title: "保存失败" });
    }
    return false;
  } finally {
    state.saving = false;
    updateBusyControls();
  }
}

async function resolveSaveConflict() {
  const pullRemote = await confirmDialog("Cloudflare 上已有更新。拉取远端会替换当前未同步的本地修改。", {
    title: "保存冲突",
    confirmLabel: "拉取远端",
    cancelLabel: "保留本地",
    danger: true,
  });

  if (pullRemote) {
    await pullRemoteVault({ skipDirtyConfirm: true });
    return;
  }

  setSaveStatus("本地修改已保留，尚未同步", "conflict");
  showToast("已保留本地修改", { message: "可以先导出备份，再决定是否拉取远端。", tone: "warning" });
}

async function pullRemoteVault(options = {}) {
  if (!state.user || !state.key) return;
  if (state.pulling) return;
  if (!state.online) {
    setSaveStatus("离线：无法拉取远端", "offline");
    showToast("当前离线", { message: "联网后再拉取 Cloudflare 密文。", tone: "warning" });
    return;
  }
  if (
    state.dirty &&
    !options.skipDirtyConfirm &&
    !(await confirmDialog("当前有未同步修改。继续拉取会用 Cloudflare 上的密文覆盖本机内容；建议先导出备份。继续？", {
      title: "拉取远端密文",
      confirmLabel: "继续拉取",
      danger: true,
    }))
  ) {
    return;
  }

  try {
    state.pulling = true;
    updateBusyControls();
    setSaveStatus("正在拉取…", "saving");
    const remote = await fetchRemoteVault();
    if (!remote.envelope) {
      setSaveStatus("远端没有保险箱", "neutral");
      showToast("远端没有保险箱", { tone: "warning" });
      return;
    }

    if (remote.envelope.kdf.salt !== bytesToBase64(state.salt)) {
      setSaveStatus("远端保险箱需要重新登录", "error");
      showToast("需要重新登录", { message: "远端密文使用了不同主密码。", tone: "danger" });
      return;
    }

    state.vault = normalizeVault(await decryptVault(remote.envelope, state.key));
    state.remoteRevision = remote.revision;
    state.dirty = false;
    remote.envelope.remoteRevision = remote.revision;
    writeLocalEnvelope(remote.envelope);
    renderEntries();
    selectEntry(state.vault.entries[0]?.id || null, { openDetail: false });
    setMobileVaultPanel("list");
    setSaveStatus("已拉取远端密文", "synced");
    recordActivity("pull_remote", `${state.vault.entries.length} 个账号`);
    showToast("已拉取远端密文", { tone: "success" });
  } catch (error) {
    const message = error.message || "拉取失败";
    setSaveStatus(message, "error");
    showToast("拉取失败", { message, tone: "danger" });
  } finally {
    state.pulling = false;
    updateBusyControls();
  }
}

async function exportVaultBackup() {
  if (!state.user || !state.vault || !state.key) return;
  if (
    !(await requireCurrentPassword("导出文件包含加密后的完整保险箱，请保存在安全位置。请重新输入当前主密码。", {
      title: "验证主密码",
      confirmLabel: "导出",
    }))
  ) {
    return;
  }

  try {
    const exportedAt = new Date().toISOString();
    const envelope = await encryptVault({ ...state.vault, lastBackupAt: exportedAt }, state.key);
    envelope.remoteRevision = state.remoteRevision;
    await verifyExportEnvelope(envelope);
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `account-vault-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    await recordBackupExport(exportedAt);
    recordActivity("export_backup", link.download);
    showToast("已导出并校验备份", { message: link.download, tone: "success" });
  } catch (error) {
    showToast("导出失败", { message: error.message || "无法生成备份文件。", tone: "danger" });
  }
}

