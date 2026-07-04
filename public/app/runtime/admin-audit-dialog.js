async function createInvite() {
  try {
    els.adminSettingsStatus.textContent = "正在生成邀请链接...";
    const data = await apiPost("/api/admin/invites", null, "无法生成邀请链接。");

    const inviteUrl = new URL(location.href);
    inviteUrl.searchParams.set("invite", data.token);
    els.inviteLink.value = inviteUrl.toString();
    await copyText(inviteUrl.toString());
    els.adminSettingsStatus.textContent = "邀请链接已生成并复制";
    await loadInviteList();
    await loadAuditLog();
  } catch (error) {
    els.adminSettingsStatus.textContent = error.message || "邀请链接生成失败";
  }
}

async function loadInviteList() {
  if (!state.user?.isAdmin) return;
  try {
    els.inviteList.textContent = "";
    const data = await apiGet("/api/admin/invites", "无法读取邀请列表。");
    renderInviteList(data.invites || []);
  } catch (error) {
    renderAdminListError(els.inviteList, error.message || "邀请列表读取失败");
  }
}

function renderInviteList(invites) {
  els.inviteList.textContent = "";
  if (!invites.length) {
    renderAdminListEmpty(els.inviteList, "还没有邀请链接");
    return;
  }

  for (const invite of invites) {
    const item = document.createElement("div");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    const token = document.createElement("code");
    const actions = document.createElement("div");
    const copyButton = document.createElement("button");
    item.className = "admin-list-item";
    copy.className = "admin-list-copy";
    title.textContent = inviteStatusLabel(invite.status);
    token.textContent = invite.token || "";
    detail.textContent = inviteDetailText(invite);
    copy.append(title, detail, token);
    copyButton.type = "button";
    copyButton.textContent = "复制";
    copyButton.addEventListener("click", () => copyInviteLink(invite.token, copyButton));
    actions.append(copyButton);
    if (invite.status === "active") {
      const revokeButton = document.createElement("button");
      revokeButton.type = "button";
      revokeButton.className = "danger";
      revokeButton.textContent = "撤销";
      revokeButton.addEventListener("click", () => revokeInvite(invite.token));
      actions.append(revokeButton);
    }
    item.append(copy, actions);
    els.inviteList.append(item);
  }
}

async function copyInviteLink(token, button) {
  if (!token) return;
  const inviteUrl = new URL(location.href);
  inviteUrl.hash = "";
  inviteUrl.searchParams.set("invite", token);
  await copyText(inviteUrl.toString());
  flashButtonLabel(button, "已复制");
  showToast("邀请链接已复制", { tone: "success" });
}

async function revokeInvite(token) {
  const confirmed = await confirmDialog("撤销后这个邀请链接不能再用于注册。继续？", {
    title: "撤销邀请",
    confirmLabel: "撤销",
    danger: true,
  });
  if (!confirmed) return;

  try {
    await postJson("/api/admin/invites/revoke", { token });
    showToast("邀请已撤销", { tone: "success" });
    await loadInviteList();
    await loadAuditLog();
  } catch (error) {
    showToast("撤销失败", { message: error.message || "无法撤销邀请。", tone: "danger" });
  }
}

async function loadAuditLog() {
  if (!state.user?.isAdmin) return;
  try {
    els.auditList.textContent = "";
    const data = await apiGet("/api/admin/audit", "无法读取审计日志。");
    renderAuditLog(data.events || []);
  } catch (error) {
    renderAdminListError(els.auditList, error.message || "审计日志读取失败");
  }
}

function renderAuditLog(events) {
  els.auditList.textContent = "";
  if (!events.length) {
    renderAdminListEmpty(els.auditList, "还没有审计事件");
    return;
  }

  for (const event of events.slice(0, 20)) {
    const item = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    item.className = "admin-list-item";
    title.textContent = auditEventLabel(event.type);
    detail.textContent = `${formatDateTime(event.at)} ${auditDetailText(event.details)}`;
    item.append(title, detail);
    els.auditList.append(item);
  }
}

function renderAdminListEmpty(container, message) {
  const item = document.createElement("div");
  item.className = "admin-list-item";
  item.textContent = message;
  container.append(item);
}

function renderAdminListError(container, message) {
  container.textContent = "";
  const item = document.createElement("div");
  item.className = "admin-list-item";
  item.textContent = message;
  container.append(item);
}

function inviteStatusLabel(status) {
  return {
    active: "可用邀请",
    used: "已使用",
    revoked: "已撤销",
    expired: "已过期",
  }[status] || "邀请";
}

function inviteDetailText(invite) {
  if (invite.usedEmail) return `${formatDateTime(invite.usedAt)} 被 ${invite.usedEmail} 使用`;
  if (invite.revokedAt) return `${formatDateTime(invite.revokedAt)} 已撤销`;
  if (invite.expiresAt) return `${formatDateTime(invite.expiresAt)} 过期`;
  return "无过期时间";
}

function auditEventLabel(type) {
  return {
    user_registered: "用户注册",
    login_succeeded: "登录成功",
    login_failed: "登录失败",
    password_changed: "主密码修改",
    sessions_revoked: "退出所有设备",
    reauth_failed: "二次验证失败",
    invite_created: "创建邀请",
    invite_revoked: "撤销邀请",
    admin_registration_setting_changed: "注册设置变更",
  }[type] || type;
}

function auditDetailText(details = {}) {
  if (details.usedEmail) return details.usedEmail;
  if (details.reason) return details.reason;
  if (details.role) return details.role;
  if (typeof details.registrationOpen === "boolean") return details.registrationOpen ? "开放注册" : "关闭注册";
  return "";
}

function openDialog({
  title,
  message,
  fields = [],
  confirmLabel = "确认",
  cancelLabel = "取消",
  danger = false,
  icon = "icon-shield",
  validate = null,
  afterRender = null,
}) {
  if (!hasDocument || !els.appDialog) return Promise.resolve(null);

  return new Promise((resolve) => {
    const controls = {};
    let settled = false;

    els.appDialog.dataset.danger = danger ? "true" : "false";
    els.appDialogTitle.textContent = title || "确认操作";
    els.appDialogMessage.textContent = message || "";
    els.appDialogError.textContent = "";
    els.appDialogFields.textContent = "";
    els.appDialogConfirm.textContent = confirmLabel;
    els.appDialogCancel.textContent = cancelLabel || "取消";
    els.appDialogCancel.classList.toggle("hidden", !cancelLabel);
    els.appDialogConfirm.classList.toggle("danger", danger);
    setInlineIcon(els.appDialogIcon, danger ? "icon-trash" : icon);

    for (const field of fields) {
      const label = document.createElement("label");
      const labelText = document.createElement("span");
      const input = document.createElement("input");
      const hint = document.createElement("small");
      const id = `dialog-${field.name}`;

      labelText.className = "label-text";
      labelText.textContent = field.label;
      input.id = id;
      input.name = field.name;
      input.type = field.type || "text";
      input.value = field.value || "";
      input.autocomplete = field.autocomplete || "off";
      input.spellcheck = false;
      if (field.placeholder) input.placeholder = field.placeholder;
      if (field.minLength) input.minLength = field.minLength;
      if (field.required !== false) input.required = true;

      label.setAttribute("for", id);
      label.append(labelText, input);
      if (field.hint) {
        hint.className = "dialog-field-hint";
        hint.textContent = field.hint;
        label.append(hint);
        controls[`${field.name}Hint`] = hint;
      }
      els.appDialogFields.append(label);
      controls[field.name] = input;
    }

    const cleanup = () => {
      els.appDialogForm.removeEventListener("submit", handleSubmit);
      els.appDialogCancel.removeEventListener("click", handleCancel);
      els.appDialog.removeEventListener("cancel", handleCancelEvent);
    };

    const finish = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (els.appDialog.open) els.appDialog.close();
      resolve(value);
    };

    const collectValues = () => {
      const values = {};
      for (const field of fields) {
        values[field.name] = controls[field.name].value;
      }
      return values;
    };

    const focusFirstField = () => {
      const firstField = fields[0] ? controls[fields[0].name] : null;
      (firstField || els.appDialogConfirm).focus();
    };

    function handleCancel() {
      finish(null);
    }

    function handleCancelEvent(event) {
      event.preventDefault();
      finish(null);
    }

    function handleSubmit(event) {
      event.preventDefault();
      const values = collectValues();
      const validationMessage = validate ? validate(values) : "";
      if (validationMessage) {
        els.appDialogError.textContent = validationMessage;
        focusFirstField();
        return;
      }
      finish(fields.length ? values : true);
    }

    els.appDialogForm.addEventListener("submit", handleSubmit);
    els.appDialogCancel.addEventListener("click", handleCancel);
    els.appDialog.addEventListener("cancel", handleCancelEvent);
    if (afterRender) afterRender(controls);
    els.appDialog.showModal();
    window.setTimeout(focusFirstField, 0);
  });
}

