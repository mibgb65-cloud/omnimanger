function renderTagManager() {
  if (!els.tagManagerList || !state.vault) return;
  const tags = getVaultTags(state.vault);
  els.tagManagerList.textContent = "";
  if (!tags.length) {
    renderTagManagerEmpty("还没有标签");
    return;
  }

  for (const tag of tags) {
    const item = document.createElement("div");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    const actions = document.createElement("div");
    const count = state.vault.entries.filter((entry) => parseEntryTags(entry.tags).includes(tag)).length;
    item.className = "admin-list-item";
    actions.className = "tag-manager-actions";
    title.textContent = tag;
    detail.textContent = `${count} 个账号`;
    copy.append(title, detail);
    actions.append(tagManagerButton("重命名", () => renameTag(tag)), tagManagerButton("删除", () => deleteTag(tag), "danger"));
    item.append(copy, actions);
    els.tagManagerList.append(item);
  }
}

function tagManagerButton(label, onClick, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.addEventListener("click", onClick);
  return button;
}

function renderTagManagerEmpty(message) {
  const item = document.createElement("div");
  item.className = "admin-list-item";
  item.textContent = message;
  els.tagManagerList.append(item);
}

async function renameTag(tag) {
  const values = await openDialog({
    title: "重命名标签",
    message: `把“${tag}”重命名或合并到另一个标签。`,
    confirmLabel: "保存",
    icon: "icon-tags",
    fields: [{ name: "tag", label: "新标签", value: tag, placeholder: "work" }],
    validate: ({ tag: nextTag }) => {
      if (!normalizeTag(nextTag)) return "请输入新标签。";
      if (normalizeTag(nextTag) === tag) return "新标签和原标签相同。";
      return "";
    },
  });
  if (!values) return;
  applyTagUpdate(tag, values.tag, "标签已更新");
}

async function deleteTag(tag) {
  if (
    !(await confirmDialog(`从所有账号中删除“${tag}”标签？账号本身不会被删除。`, {
      title: "删除标签",
      confirmLabel: "删除标签",
      danger: true,
    }))
  ) {
    return;
  }
  applyTagUpdate(tag, "", "标签已删除");
}

function applyTagUpdate(oldTag, nextTag, title) {
  const result = updateVaultTag(state.vault, oldTag, nextTag);
  if (!result.changed) {
    showToast("没有账号需要更新", { tone: "warning" });
    return;
  }

  if (state.selectedTag === oldTag) state.selectedTag = normalizeTag(nextTag);
  renderEntries();
  renderTagManager();
  markDirty();
  recordActivity("manage_tags", nextTag ? `${oldTag} -> ${normalizeTag(nextTag)}` : oldTag);
  showToast(title, { message: `${result.changed} 个账号`, tone: "success" });
}
