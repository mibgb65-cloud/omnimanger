import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "public", "scripts", "test", "e2e"];
const scriptExtensions = new Set([".js", ".mjs"]);
const countedExtensions = new Set([".css", ".html", ".js", ".mjs", ".py", ".svg"]);
const maxLines = 500;
const secretMarkers = [
  ["cfut", "_"].join(""),
  ["CLOUDFLARE", "API", "TOKEN"].join("_") + "=",
];

const files = roots.flatMap(collectFiles).sort();

for (const file of files.filter(isScript)) {
  execFileSync(process.execPath, ["--check", file], { stdio: "inherit" });
}

assertLineBudget(files);
assertNoSecretMarkers(files);
assertServiceWorkerAssetList();

function collectFiles(root) {
  const stat = statSync(root, { throwIfNoEntry: false });
  if (!stat) return [];
  if (stat.isFile()) return shouldInspect(root) ? [root] : [];

  return readdirSync(root)
    .flatMap((entry) => collectFiles(join(root, entry)));
}

function isScript(file) {
  return scriptExtensions.has(extension(file));
}

function shouldInspect(file) {
  return countedExtensions.has(extension(file));
}

function extension(file) {
  return file.slice(file.lastIndexOf("."));
}

function assertLineBudget(files) {
  const oversized = files
    .map((file) => ({ file, lines: lineCount(file) }))
    .filter((entry) => entry.lines >= maxLines);

  if (oversized.length === 0) return;

  for (const entry of oversized) {
    console.error(`File exceeds ${maxLines - 1} lines: ${entry.file} (${entry.lines})`);
  }
  process.exitCode = 1;
}

function assertNoSecretMarkers(files) {
  const leaks = [];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const marker of secretMarkers) {
      if (text.includes(marker)) leaks.push({ file, marker });
    }
  }

  if (leaks.length === 0) return;

  for (const leak of leaks) {
    console.error(`Potential secret marker found in ${leak.file}: ${leak.marker}`);
  }
  process.exitCode = 1;
}

function assertServiceWorkerAssetList() {
  const serviceWorker = readFileSync("public/sw.js", "utf8");
  const expected = new Set([
    "/app/bootstrap.js",
    "/app/core.js",
    "/icons.svg",
    ...extractQuotedPaths("public/app/bootstrap.js"),
    ...extractCssImports("public/styles.css"),
  ]);
  const missing = [...expected].filter((asset) => !serviceWorker.includes(`"${asset}"`));
  const missingFiles = [...expected]
    .map((asset) => ({ asset, file: join("public", asset.slice(1)) }))
    .filter((entry) => !statSync(entry.file, { throwIfNoEntry: false }));

  for (const asset of missing) {
    console.error(`Service worker cache list is missing ${asset}`);
  }
  for (const entry of missingFiles) {
    console.error(`Referenced asset does not exist: ${entry.asset}`);
  }
  if (missing.length || missingFiles.length) process.exitCode = 1;
}

function extractQuotedPaths(file) {
  const text = readFileSync(file, "utf8");
  return [...text.matchAll(/"((?:\/app|\/partials)\/[^"]+)"/g)].map((match) => match[1]);
}

function extractCssImports(file) {
  const text = readFileSync(file, "utf8");
  return [...text.matchAll(/@import url\("([^"]+)"\)/g)].map((match) => match[1]);
}

function lineCount(file) {
  const text = readFileSync(file, "utf8");
  if (!text) return 0;
  return text.split(/\r\n|\r|\n/).length;
}
