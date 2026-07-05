async function copyInputValue(inputId, button = null) {
  const input = $(inputId);
  if (!input?.value) {
    showToast("没有可复制的内容", { tone: "warning" });
    return;
  }

  try {
    if (!(await copyText(input.value))) {
      input.select();
      document.execCommand("copy");
    }
  } catch {
    input.select();
    document.execCommand("copy");
  }
  flashButtonLabel(button, "已复制");
  recordEntryUsageForCopy(inputId);
  showToast("已复制", { message: "剪贴板会在 30 秒后尝试清空。", tone: "success" });
}

async function copyText(text) {
  if (!navigator.clipboard?.writeText) return false;
  await navigator.clipboard.writeText(text);
  scheduleClipboardClear(text);
  return true;
}

function scheduleClipboardClear(value) {
  clearTimeout(state.clipboardClearTimer);
  if (!navigator.clipboard?.readText || !navigator.clipboard?.writeText) return;

  state.clipboardClearTimer = setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === value) {
        await navigator.clipboard.writeText("");
      }
    } catch {
      // Clipboard read permission is browser-controlled.
    }
  }, CLIPBOARD_CLEAR_MS);
}

function setSaveStatus(message, status = "neutral") {
  if (!hasDocument || !els.saveStatus) return;
  els.saveStatus.textContent = message;
  els.saveStatus.dataset.state = status;
  els.saveStatus.classList.toggle("neutral", status === "neutral" || status === "locked");
}

function showToast(title, options = {}) {
  if (!hasDocument || !els.toastRegion || !title) return;
  const tone = options.tone || "info";
  const iconId =
    tone === "success" ? "icon-check-circle" : tone === "danger" || tone === "warning" ? "icon-alert-circle" : "icon-shield";
  const toast = document.createElement("div");
  const iconWrap = document.createElement("span");
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  const copy = document.createElement("div");
  const heading = document.createElement("strong");

  toast.className = "toast";
  toast.dataset.tone = tone;
  toast.setAttribute("role", tone === "danger" ? "alert" : "status");
  iconWrap.className = "section-icon";
  icon.classList.add("icon");
  use.setAttribute("href", `/icons.svg#${iconId}`);
  icon.append(use);
  iconWrap.append(icon);
  heading.textContent = title;
  copy.append(heading);

  if (options.message) {
    const message = document.createElement("span");
    message.textContent = options.message;
    copy.append(message);
  }

  toast.append(iconWrap, copy);
  initDecorativeIcons(toast);
  els.toastRegion.prepend(toast);

  window.setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    window.setTimeout(() => toast.remove(), 180);
  }, options.duration || TOAST_DURATION_MS);
}

function flashButtonLabel(button, label) {
  if (!button) return;
  const current = button.querySelector("span:not(.sr-only)")?.textContent || "";
  const original = button.dataset.originalLabel || current;
  button.dataset.originalLabel = original;
  setInlineLabel(button, label);
  window.setTimeout(() => setInlineLabel(button, original), 1600);
}

function setUnlockMessage(message) {
  els.unlockMessage.textContent = message;
}

function setHeadingText(element, text) {
  const textNode = Array.from(element.childNodes).find((node) => node.nodeType === Node.TEXT_NODE);
  if (textNode) {
    textNode.textContent = text;
    return;
  }
  element.append(document.createTextNode(text));
}

