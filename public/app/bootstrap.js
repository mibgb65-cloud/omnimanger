const PARTIALS = [
  "/partials/01-shell-overview.html",
  "/partials/02-vault.html",
  "/partials/03-security-backup.html",
  "/partials/04-settings.html",
  "/partials/05-dialogs.html",
];

import * as AppCore from "./core.js";

window.AppCore = AppCore;

const RUNTIME_SCRIPTS = [
  "/app/runtime/constants.js",
  "/app/runtime/state.js",
  "/app/runtime/elements.js",
  "/app/runtime/core-bindings.js",
  "/app/runtime/api-client.js",
  "/app/runtime/preferences-auth.js",
  "/app/runtime/vault-navigation.js",
  "/app/runtime/navigation-lock.js",
  "/app/runtime/entries-list.js",
  "/app/runtime/entry-editor.js",
  "/app/runtime/overview-activity.js",
  "/app/runtime/security-report.js",
  "/app/runtime/sync-secrets.js",
  "/app/runtime/backup-import.js",
  "/app/runtime/api-admin-settings.js",
  "/app/runtime/admin-audit-dialog.js",
  "/app/runtime/tag-manager.js",
  "/app/runtime/trash-manager.js",
  "/app/runtime/storage-crypto-totp.js",
  "/app/runtime/generators-toast.js",
  "/app/runtime/dom-controls.js",
  "/app/runtime/init-events.js",
  "/app/runtime/start.js",
];

async function loadHtmlShell() {
  const root = document.getElementById("appRoot");
  const fragments = await Promise.all(
    PARTIALS.map(async (path) => {
      const response = await fetch(path, { credentials: "same-origin" });
      if (!response.ok) throw new Error(`Unable to load ${path}`);
      return response.text();
    }),
  );
  root.innerHTML = fragments.join("\n");
}

function loadScript(path) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = path;
    script.onload = resolve;
    script.onerror = () => reject(new Error(`Unable to load ${path}`));
    document.body.append(script);
  });
}

await loadHtmlShell();
for (const path of RUNTIME_SCRIPTS) {
  await loadScript(path);
}
document.body.dataset.appReady = "true";
