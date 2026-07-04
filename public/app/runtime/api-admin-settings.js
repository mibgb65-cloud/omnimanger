async function fetchRemoteVault() {
  const data = await apiGet("/api/vault", "远端读取失败。");
  return {
    envelope: data.envelope || null,
    updatedAt: data.updatedAt || null,
    revision: data.revision || null,
  };
}

async function putRemoteEnvelope(envelope, baseRevision) {
  return apiPut("/api/vault", { envelope, baseRevision }, "远端保存失败。");
}

async function requireCurrentPassword(message, options = {}) {
  if (!state.user?.email) return false;
  const password = await promptPasswordDialog(message, {
    title: options.title || "验证主密码",
    label: "当前主密码",
    autocomplete: "current-password",
    confirmLabel: options.confirmLabel || "验证",
  });
  if (!password) return false;

  try {
    const authSecret = await makeAuthSecret(state.user.email, password);
    await postJson("/api/auth/verify-password", { authSecret });
    return true;
  } catch (error) {
    showToast("主密码验证失败", { message: error.message || "请确认后再试。", tone: "danger" });
    return false;
  }
}

function recordBackupExport() {
  if (!state.user) return;
  const timestamp = new Date().toISOString();
  localStorage.setItem(getBackupStatusKey(state.user.id), timestamp);
  renderBackupStatus();
  renderBackupWizard();
  renderOverview();
}

function renderBackupStatus() {
  if (!hasDocument || !els.backupStatus || !state.user) return;
  const lastBackupAt = getLastBackupAt();
  const stale = isBackupStale(lastBackupAt);
  els.backupStatus.dataset.state = stale ? "warning" : "ok";
  if (!lastBackupAt) {
    els.backupStatusTitle.textContent = "还没有导出备份";
    els.backupStatusDetail.textContent = "建议先导出一份备份文件，并保存在安全位置。";
    return;
  }

  const backupTimeText = formatDateTime(lastBackupAt) || "未知";
  els.backupStatusTitle.textContent = stale ? "建议更新备份" : "备份状态正常";
  els.backupStatusDetail.textContent = `上次导出：${backupTimeText}。${stale ? `已超过 ${BACKUP_REMINDER_DAYS} 天。` : "当前不需要额外操作。"}`;
}

function renderBackupWizard() {
  if (!hasDocument || !els.backupWizardSteps) return;
  const importModeLabel = state.importMode === "replace" ? "整体替换" : "合并导入";
  const verified = state.lastBackupVerification;
  const lastBackupAt = getLastBackupAt();
  const steps = [
    {
      title: "验证备份",
      detail: verified ? `已验证 ${verified.incomingTotal} 个账号` : "先确认文件能被主密码解开",
      state: verified ? "done" : "active",
    },
    {
      title: "选择导入模式",
      detail: importModeLabel,
      state: verified ? "active" : "idle",
    },
    {
      title: "导入前确认",
      detail: verified ? `新增 ${verified.added} 个，重名 ${verified.matched} 个，当前独有 ${verified.removed} 个` : "验证后会显示差异",
      state: verified ? "active" : "idle",
    },
    {
      title: "保留回滚备份",
      detail: lastBackupAt ? `最近导出 ${formatDateTime(lastBackupAt) || "未知"}` : "导入前建议先导出当前保险箱",
      state: lastBackupAt ? "done" : "idle",
    },
  ];

  els.backupWizardStatus.textContent = verified
    ? `备份验证通过。当前导入模式：${importModeLabel}。`
    : "建议先验证备份，再选择导入模式。";
  els.backupWizardSteps.textContent = "";

  for (const step of steps) {
    const item = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    item.className = "backup-step";
    item.dataset.state = step.state;
    title.textContent = step.title;
    detail.textContent = step.detail;
    item.append(title, detail);
    els.backupWizardSteps.append(item);
  }
}

function maybeShowBackupReminder() {
  if (!state.user || state.backupReminderShown) return;
  const userId = state.user.id;
  const lastBackupAt = getLastBackupAt();
  if (!isBackupStale(lastBackupAt)) return;
  state.backupReminderShown = true;
  window.setTimeout(() => {
    if (!state.user || state.user.id !== userId) return;
    showToast("建议导出备份", {
      message: lastBackupAt ? `上次导出已超过 ${BACKUP_REMINDER_DAYS} 天。` : "当前账号还没有导出过备份。",
      tone: "warning",
      duration: 6000,
    });
  }, 600);
}

function getLastBackupAt() {
  if (!state.user) return "";
  return localStorage.getItem(getBackupStatusKey(state.user.id)) || "";
}

function getBackupStatusKey(userId) {
  return `account-secret-vault.last-backup.${userId}`;
}

function formatAuthError(error) {
  const retryAfter = Number(error?.data?.retryAfter || 0);
  if (error?.status === 429 && retryAfter > 0) {
    return `尝试次数过多，请等待 ${formatDuration(retryAfter)} 后再试。`;
  }
  return formatApiErrorMessage(error?.message, "无法登录。");
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} 分钟`;
}

async function loadAdminSettings() {
  try {
    els.adminSettingsStatus.textContent = "正在读取注册设置...";
    const data = await apiGet("/api/admin/settings", "无法读取管理员设置。");

    els.registrationOpenToggle.checked = Boolean(data.registrationOpen);
    els.adminSettingsStatus.textContent = data.registrationOpen ? "当前允许新用户注册" : "当前禁止新用户注册";
    await loadAuditLog();
  } catch (error) {
    els.adminSettingsStatus.textContent = error.message || "管理员设置读取失败";
  }
}

async function saveAdminSettings() {
  const desiredRegistrationOpen = els.registrationOpenToggle.checked;
  const actionText = desiredRegistrationOpen
    ? "开放后，知道站点地址的人可以自行注册新账号。请重新输入当前主密码。"
    : "关闭后，新用户只能通过管理员生成的一次性邀请链接注册。请重新输入当前主密码。";
  if (
    !(await requireCurrentPassword(actionText, {
      title: "验证管理员操作",
      confirmLabel: "保存设置",
    }))
  ) {
    els.registrationOpenToggle.checked = !desiredRegistrationOpen;
    return;
  }

  try {
    els.adminSettingsStatus.textContent = "正在保存注册设置...";
    const data = await apiPut(
      "/api/admin/settings",
      { registrationOpen: desiredRegistrationOpen },
      "无法保存管理员设置。",
    );

    els.registrationOpenToggle.checked = Boolean(data.registrationOpen);
    els.adminSettingsStatus.textContent = data.registrationOpen ? "当前允许新用户注册" : "当前禁止新用户注册";
    await loadAuditLog();
  } catch (error) {
    els.adminSettingsStatus.textContent = error.message || "管理员设置保存失败";
    els.registrationOpenToggle.checked = !els.registrationOpenToggle.checked;
  }
}

