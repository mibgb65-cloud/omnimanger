async function importVaultBackup() {
  const file = els.importFileInput.files?.[0];
  els.importFileInput.value = "";
  if (!file || !state.user) return;

  try {
    const envelope = JSON.parse(await file.text());
    if (!isVaultEnvelope(envelope)) {
      throw new Error("备份文件不是有效的保险箱密文。");
    }

    const password = await promptPasswordDialog("输入用于解密此备份的主密码。", {
      title: "解密备份",
      label: "主密码",
      autocomplete: "current-password",
    });
    if (!password) return;

    const salt = base64ToBytes(envelope.kdf.salt);
    const key = await deriveVaultKey(password, salt, envelope.kdf.iterations);
    const vault = normalizeVault(await decryptVault(envelope, key));
    await confirmAndApplyVaultImport(vault, file.name, {
      title: "导入备份",
      confirmLabel: "继续导入",
      activityType: "import_backup",
      successTitle: "备份已导入",
    });
  } catch (error) {
    showToast("导入失败", { message: error.message || "无法读取备份文件。", tone: "danger" });
  }
}

async function importExternalVaultFile() {
  const file = els.externalImportFileInput.files?.[0];
  els.externalImportFileInput.value = "";
  if (!file || !state.user) return;

  try {
    const vault = parseExternalVaultImport(await file.text(), file.name);
    await confirmAndApplyVaultImport(vault, file.name, {
      title: "导入外部密码库",
      confirmLabel: "导入",
      activityType: "import_external",
      successTitle: "密码库已导入",
      warning: "外部导出文件通常是明文。导入完成并确认同步后，请删除原始导出文件。",
    });
  } catch (error) {
    showToast("导入失败", { message: error.message || "无法读取外部密码库。", tone: "danger" });
  }
}

async function confirmAndApplyVaultImport(vault, fileName, options) {
  const diff = summarizeImportDiff(state.vault, vault);
  const importMode = state.importMode === "replace" ? "replace" : "merge";
  const lines = [options.warning, formatImportConfirmation(fileName, diff, importMode)].filter(Boolean);
  if (
    !(await confirmDialog(lines.join("\n\n"), {
      title: options.title,
      confirmLabel: options.confirmLabel,
      danger: importMode === "replace",
    }))
  ) {
    return false;
  }

  if (
    importMode === "replace" &&
    !(await requireCurrentPassword("整体替换会覆盖当前保险箱并同步到 Cloudflare。请重新输入当前主密码。", {
      title: "验证主密码",
      confirmLabel: "确认替换",
    }))
  ) {
    return false;
  }

  state.vault = importMode === "merge" ? mergeImportedVault(state.vault, vault) : vault;
  state.dirty = true;
  renderEntries();
  selectEntry(state.vault.entries[0]?.id || null, { openDetail: false });
  setMobileVaultPanel("list");
  await saveVaultNow(true);
  state.lastBackupVerification = null;
  renderBackupWizard();
  recordActivity(options.activityType, importMode === "merge" ? "合并导入" : "整体替换");
  showToast(options.successTitle, {
    message: importMode === "merge" ? "已合并到当前保险箱" : `${diff.incomingTotal} 个账号`,
    tone: "success",
  });
  return true;
}

async function verifyVaultBackup() {
  const file = els.verifyBackupFileInput.files?.[0];
  els.verifyBackupFileInput.value = "";
  if (!file || !state.user) return;

  try {
    const envelope = JSON.parse(await file.text());
    if (!isVaultEnvelope(envelope)) {
      throw new Error("备份文件不是有效的保险箱密文。");
    }

    const password = await promptPasswordDialog("输入用于验证此备份的主密码。不会导入或修改当前保险箱。", {
      title: "验证备份",
      label: "备份主密码",
      autocomplete: "current-password",
    });
    if (!password) return;

    const salt = base64ToBytes(envelope.kdf.salt);
    const key = await deriveVaultKey(password, salt, envelope.kdf.iterations);
    const vault = normalizeVault(await decryptVault(envelope, key));
    const summary = summarizeBackupVerification(state.vault, vault);
    state.lastBackupVerification = summary;
    renderBackupWizard();
    recordActivity("verify_backup", `${summary.incomingTotal} 个账号`);
    await alertDialog(formatBackupVerification(summary), {
      title: "备份验证通过",
      confirmLabel: "知道了",
      icon: "icon-check-circle",
    });
  } catch (error) {
    showToast("备份验证失败", { message: error.message || "无法验证备份文件。", tone: "danger" });
  }
}

async function verifyExportEnvelope(envelope) {
  const verified = normalizeVault(await decryptVault(envelope, state.key));
  if (verified.entries.length !== state.vault.entries.length) {
    throw new Error("备份校验失败：账号数量不一致。");
  }
}

function formatBackupVerification(summary) {
  const backupTimeText = formatDateTime(summary.backupUpdatedAt) || "未知";
  return [
    `备份可正常解密，包含 ${summary.incomingTotal} 个账号。`,
    `与当前保险箱相比：新增 ${summary.added} 个，重名 ${summary.matched} 个，当前未包含 ${summary.removed} 个。`,
    `备份更新时间：${backupTimeText}。`,
    formatPreviewLine("新增", summary.addedEntries, summary.added),
    formatPreviewLine("重名", summary.matchedEntries, summary.matched),
    formatPreviewLine("当前独有", summary.removedEntries, summary.removed),
  ]
    .filter(Boolean)
    .join("\n");
}

function formatPreviewLine(label, entries, total) {
  if (!total) return `${label}：无。`;
  const shown = entries.slice(0, 5).join("、");
  const extra = total > 5 ? ` 等 ${total} 个` : "";
  return `${label}：${shown}${extra}。`;
}

async function changeMasterPassword() {
  if (!state.user || !state.vault) return;
  if (state.saving || state.pulling) {
    await alertDialog("当前有同步操作正在进行，请稍后再修改主密码。", { title: "暂时无法改密" });
    return;
  }

  const passwords = await changePasswordDialog();
  if (!passwords) return;

  clearTimeout(state.saveTimer);
  state.saveTimer = null;
  state.saving = true;
  updateBusyControls();
  try {
    setSaveStatus("正在修改主密码…", "saving");
    const authSecret = await makeAuthSecret(state.user.email, passwords.currentPassword);
    const newAuthSecret = await makeAuthSecret(state.user.email, passwords.nextPassword);
    const nextSalt = crypto.getRandomValues(new Uint8Array(16));
    const nextKey = await deriveVaultKey(passwords.nextPassword, nextSalt, KDF_ITERATIONS);
    const nextVault = {
      ...state.vault,
      updatedAt: new Date().toISOString(),
      entries: state.vault.entries.map((entry) => ({ ...entry })),
    };
    const envelope = await encryptVaultWith(nextVault, nextKey, nextSalt, KDF_ITERATIONS);
    const changed = await postJson("/api/auth/change-password", {
      authSecret,
      newAuthSecret,
      envelope,
      baseRevision: state.remoteRevision,
    });

    state.vault = nextVault;
    state.key = nextKey;
    state.salt = nextSalt;
    state.iterations = KDF_ITERATIONS;
    state.remoteRevision = changed.revision;
    envelope.remoteRevision = changed.revision;
    envelope.updatedAt = changed.updatedAt || envelope.updatedAt;
    writeLocalEnvelope(envelope);
    state.dirty = false;
    setSaveStatus("主密码已修改并同步", "synced");
    recordActivity("change_password", "主密码");
    showToast("主密码已修改", { message: "保险箱已用新主密码重新加密。", tone: "success" });
  } catch (error) {
    const message = error.message || "主密码修改失败";
    setSaveStatus(message, "error");
    showToast("主密码修改失败", { message, tone: "danger" });
  } finally {
    state.saving = false;
    updateBusyControls();
  }
}

