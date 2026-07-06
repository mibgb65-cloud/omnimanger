const CACHE_VERSION = "2026-07-06-02";
const CACHE_NAME = `account-secret-vault-shell-${CACHE_VERSION}`;
const SHELL_ASSETS = [
  "/",
  "/index.html",
  "/styles.css",
  "/manifest.webmanifest",
  "/icon.svg",
  "/icons.svg",
  "/app.js",
  "/app/bootstrap.js",
  "/app/backup-health.js",
  "/app/core.js",
  "/app/expiry.js",
  "/app/importers.js",
  "/app/tags.js",
  "/app/trash.js",
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
  "/styles/01-tokens-base.css",
  "/styles/02-shell-auth.css",
  "/styles/03-vault-list.css",
  "/styles/04-overview.css",
  "/styles/05-settings-admin.css",
  "/styles/06-dialogs.css",
  "/styles/07-responsive-large.css",
  "/styles/08-responsive-small.css",
  "/partials/01-shell-overview.html",
  "/partials/02-vault.html",
  "/partials/03-security-backup.html",
  "/partials/04-settings.html",
  "/partials/05-dialogs.html",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) => Promise.all(names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  const url = new URL(event.request.url);
  if (url.origin !== location.origin || url.pathname.startsWith("/api/")) return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (event.request.method === "GET" && response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || caches.match("/index.html"))),
  );
});
