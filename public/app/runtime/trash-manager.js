function renderTrashManager() {
  if (!els.trashManagerList || !state.vault) return;
  const entries = getTrashEntries(state.vault);
  els.trashManagerList.textContent = "";
  if (!entries.length) {
    renderTrashManagerEmpty("回收站为空");
    return;
  }

  for (const entry of entries) {
    const item = document.createElement("div");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    const actions = document.createElement("div");
    item.className = "admin-list-item";
    actions.className = "trash-manager-actions";
    title.textContent = trashEntryLabel(entry);
    detail.textContent = [`删除 ${formatDateTime(entry.deletedAt) || "未知时间"}`, entry.login].filter(Boolean).join(" / ");
    copy.append(title, detail);
    actions.append(trashManagerButton("恢复", () => restoreDeletedEntry(entry.id)), trashManagerButton("永久删除", () => purgeDeletedEntry(entry.id), "danger"));
    item.append(copy, actions);
    els.trashManagerList.append(item);
  }
}

function trashManagerButton(label, onClick, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.addEventListener("click", onClick);
  return button;
}

function renderTrashManagerEmpty(message) {
  const item = document.createElement("div");
  item.className = "admin-list-item";
  item.textContent = message;
  els.trashManagerList.append(item);
}

async function restoreDeletedEntry(entryId) {
  const entry = restoreTrashEntry(state.vault, entryId);
  if (!entry) {
    showToast("账号不存在", { tone: "warning" });
    renderTrashManager();
    return;
  }

  renderEntries();
  selectEntry(entry.id, { openDetail: true });
  markDirty();
  recordActivity("restore_entry", trashEntryLabel(entry));
  showToast("账号已恢复", { message: trashEntryLabel(entry), tone: "success" });
}

async function purgeDeletedEntry(entryId) {
  const entry = getTrashEntries(state.vault).find((item) => item.id === entryId);
  if (!entry) return;
  const label = trashEntryLabel(entry);
  if (
    !(await confirmDialog(`永久删除“${label}”？此操作无法从回收站恢复。`, {
      title: "永久删除账号",
      confirmLabel: "永久删除",
      danger: true,
    }))
  ) {
    return;
  }

  deleteTrashEntry(state.vault, entryId);
  renderTrashManager();
  markDirty();
  recordActivity("purge_entry", label);
  showToast("已永久删除", { message: label, tone: "warning" });
}

function trashEntryLabel(entry) {
  return entry.name || entry.login || "未命名账号";
}
