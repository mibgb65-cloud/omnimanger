function init() {
  initDecorativeIcons();
  initTheme();
  initSecurityPreferences();
  initDataPreferences();
  initPasswordGeneratorOptions();
  initConnectivity();
  els.loginEmail.value = localStorage.getItem(LAST_EMAIL_KEY) || "";
  const inviteToken = new URLSearchParams(location.search).get("invite") || "";
  els.inviteToken.value = inviteToken;
  setAuthMode(inviteToken ? "register" : "login");
  setMobileVaultPanel("list");
  showSettingsSection("security");

  els.themeToggleButton.addEventListener("click", toggleTheme);
  els.overviewNavButton.addEventListener("click", () => navigateToAppPage("overview"));
  els.vaultNavButton.addEventListener("click", () => navigateToAppPage("vault"));
  els.securityNavButton.addEventListener("click", () => navigateToAppPage("security"));
  els.backupNavButton.addEventListener("click", () => navigateToAppPage("backup"));
  els.settingsNavButton.addEventListener("click", () => navigateToAppPage("settings"));
  els.appNav.addEventListener("keydown", handleAppNavKeydown);
  els.settingsTabs.addEventListener("click", handleSettingsTabClick);
  els.settingsTabs.addEventListener("keydown", handleSettingsTabKeydown);
  els.registrationOpenToggle.addEventListener("change", saveAdminSettings);
  els.createInviteButton.addEventListener("click", createInvite);
  els.unlockForm.addEventListener("submit", (event) => {
    event.preventDefault();
    authenticate(state.authMode);
  });
  els.loginModeButton.addEventListener("click", () => setAuthMode("login"));
  els.registerButton.addEventListener("click", () => setAuthMode("register"));
  els.loginModeButton.addEventListener("keydown", handleAuthModeKeydown);
  els.registerButton.addEventListener("keydown", handleAuthModeKeydown);
  els.loginPassword.addEventListener("input", updateMasterPasswordStrength);
  els.searchInput.addEventListener("input", () => {
    renderEntries();
    setMobileVaultPanel("list");
  });
  els.entrySortSelect.addEventListener("change", saveEntrySortPreference);
  els.riskOnlyToggle.addEventListener("change", toggleRiskOnlyFilter);
  els.clearSecurityFilterButton.addEventListener("click", clearSecurityFilter);
  els.tagFilter.addEventListener("click", handleTagFilterClick);
  els.addEntryButton.addEventListener("click", addEntry);
  els.overviewAddButton.addEventListener("click", addEntryFromOverview);
  els.overviewVaultButton.addEventListener("click", () => navigateToAppPage("vault"));
  els.overviewRiskButton.addEventListener("click", showRiskAccountsFromOverview);
  els.overviewBackupButton.addEventListener("click", () => navigateToAppPage("backup"));
  els.overviewSecurityButton.addEventListener("click", () => navigateToAppPage("security"));
  els.overviewSettingsButton.addEventListener("click", () => navigateToAppPage("settings"));
  els.emptyAddButton.addEventListener("click", addEntry);
  els.detailTabs.addEventListener("click", handleDetailTabClick);
  els.detailTabs.addEventListener("keydown", handleDetailTabKeydown);
  els.backToListButton.addEventListener("click", () => setMobileVaultPanel("list"));
  els.entryList.addEventListener("keydown", handleEntryListKeydown);
  els.entryForm.addEventListener("input", handleEntryInput);
  els.addCustomFieldButton.addEventListener("click", addCustomField);
  els.customFieldsList.addEventListener("click", handleCustomFieldAction);
  els.generatePasswordButton.addEventListener("click", fillGeneratedPassword);
  els.generateCopyPasswordButton.addEventListener("click", generateAndCopyPassword);
  els.passwordLengthInput.addEventListener("change", savePasswordGeneratorOptions);
  els.passwordSymbolsToggle.addEventListener("change", savePasswordGeneratorOptions);
  els.passwordReadableToggle.addEventListener("change", savePasswordGeneratorOptions);
  els.togglePasswordButton.addEventListener("click", togglePassword);
  els.toggleTotpButton.addEventListener("click", toggleTotp);
  els.deleteEntryButton.addEventListener("click", deleteSelectedEntry);
  els.importButton.addEventListener("click", () => els.importFileInput.click());
  els.importFileInput.addEventListener("change", importVaultBackup);
  els.externalImportButton.addEventListener("click", () => els.externalImportFileInput.click());
  els.externalImportFileInput.addEventListener("change", importExternalVaultFile);
  els.verifyBackupButton.addEventListener("click", () => els.verifyBackupFileInput.click());
  els.verifyBackupFileInput.addEventListener("change", verifyVaultBackup);
  els.wizardVerifyBackupButton.addEventListener("click", () => els.verifyBackupFileInput.click());
  els.wizardImportButton.addEventListener("click", () => els.importFileInput.click());
  els.importModeSelect.addEventListener("change", saveImportModePreference);
  els.exportButton.addEventListener("click", exportVaultBackup);
  els.changePasswordButton.addEventListener("click", changeMasterPassword);
  els.logoutAllButton.addEventListener("click", logoutAllSessions);
  els.refreshInvitesButton.addEventListener("click", loadInviteList);
  els.refreshAuditButton.addEventListener("click", loadAuditLog);
  els.autoLockSelect.addEventListener("change", saveAutoLockPreference);
  els.localCacheToggle.addEventListener("change", saveLocalCachePreference);
  els.saveButton.addEventListener("click", () => saveVaultNow(true));
  els.pullButton.addEventListener("click", pullRemoteVault);
  els.lockButton.addEventListener("click", logoutVault);

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-copy]");
    if (!button) return;
    copyInputValue(button.dataset.copy, button);
  });
  document.addEventListener("keydown", handleGlobalKeydown);

  setInterval(updateTotpDisplay, 1000);
  setInterval(lockIfHiddenTooLong, 30_000);
  setInterval(lockIfIdleTooLong, 30_000);

  for (const eventName of ["pointerdown", "keydown", "input"]) {
    document.addEventListener(eventName, markActivity, true);
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      hideVisibleSecrets();
      return;
    }
    if (document.visibilityState === "visible") {
      sessionStorage.removeItem("vault.hidden-at");
      markActivity();
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty && !state.saving) return;
    event.preventDefault();
    event.returnValue = "";
  });
  window.addEventListener("hashchange", syncAppPageFromHash);

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
}
