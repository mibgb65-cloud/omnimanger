function setInlineLabel(element, text) {
  const label = element.querySelector("span:not(.sr-only)");
  if (label) {
    label.textContent = text;
    return;
  }
  element.textContent = text;
}

function setInlineIcon(element, iconId) {
  const use = element.querySelector("use");
  if (use) use.setAttribute("href", `/icons.svg#${iconId}`);
}

function initDecorativeIcons(root = document) {
  for (const icon of root.querySelectorAll(".icon")) {
    icon.setAttribute("aria-hidden", "true");
    icon.setAttribute("focusable", "false");
  }
}

function setAuthButtonsDisabled(disabled) {
  for (const button of els.unlockForm.querySelectorAll("button")) {
    button.disabled = disabled;
  }
}

function updateBusyControls() {
  els.importButton.disabled = state.saving || state.pulling;
  els.verifyBackupButton.disabled = state.saving || state.pulling;
  els.wizardVerifyBackupButton.disabled = state.saving || state.pulling;
  els.wizardImportButton.disabled = state.saving || state.pulling;
  els.exportButton.disabled = state.saving || state.pulling;
  els.saveButton.disabled = state.saving || state.pulling;
  els.pullButton.disabled = state.saving || state.pulling || !state.online;
  els.lockButton.disabled = state.saving;
  els.changePasswordButton.disabled = state.saving || state.pulling;
  els.logoutAllButton.disabled = state.saving || state.pulling;
}

function resetSecretVisibility() {
  clearTimeout(state.passwordRevealTimer);
  clearTimeout(state.totpRevealTimer);
  state.passwordVisible = false;
  state.totpVisible = false;
  els.entryPassword.type = "password";
  els.entryTotpSecret.type = "password";
  setInlineLabel(els.togglePasswordButton, "显示");
  setInlineIcon(els.togglePasswordButton, "icon-eye");
  setInlineLabel(els.toggleTotpButton, "显示");
  setInlineIcon(els.toggleTotpButton, "icon-eye");
  els.togglePasswordButton.setAttribute("aria-pressed", "false");
  els.toggleTotpButton.setAttribute("aria-pressed", "false");
}

