const BACKUP_REMINDER_DAYS = 7;
const BACKUP_REMINDER_MS = BACKUP_REMINDER_DAYS * 24 * 60 * 60 * 1000;
const KDF_ITERATIONS = 310000;
const AUTH_KDF_ITERATIONS = 120000;
const GENERATED_PASSWORD_LENGTH = 20;
const PASSWORD_HISTORY_LIMIT = 5;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export { parseExternalVaultImport } from "./importers.js";
export { getBackupVerificationHealth } from "./backup-health.js";
export { normalizeTag, updateVaultTag } from "./tags.js";

function normalizeVault(vault) {
  if (!vault || typeof vault !== "object") {
    throw new Error("保险箱内容无效。");
  }

  return {
    version: 1,
    createdAt: vault.createdAt || new Date().toISOString(),
    updatedAt: vault.updatedAt || new Date().toISOString(),
    entries: Array.isArray(vault.entries) ? vault.entries.map(normalizeEntry) : [],
  };
}

function normalizeEntry(entry) {
  return {
    id: entry.id || crypto.randomUUID(),
    name: entry.name || "",
    login: entry.login || "",
    password: entry.password || "",
    totpSecret: entry.totpSecret || "",
    recoveryCodes: entry.recoveryCodes || "",
    backupEmail: entry.backupEmail || "",
    backupPhone: entry.backupPhone || "",
    tags: entry.tags || "",
    notes: entry.notes || "",
    favorite: Boolean(entry.favorite),
    lastUsedAt: entry.lastUsedAt || "",
    customFields: normalizeCustomFields(entry.customFields),
    passwordHistory: normalizePasswordHistory(entry.passwordHistory),
    createdAt: entry.createdAt || new Date().toISOString(),
    updatedAt: entry.updatedAt || new Date().toISOString(),
  };
}

function normalizeCustomFields(fields) {
  if (!Array.isArray(fields)) return [];
  return fields
    .map((field) => ({
      id: field?.id || crypto.randomUUID(),
      label: String(field?.label || field?.name || "").trim(),
      value: String(field?.value ?? "").trim(),
    }))
    .filter((field) => field.label || field.value);
}

function normalizePasswordHistory(history) {
  if (!Array.isArray(history)) return [];
  return history
    .map((item) => ({
      id: item?.id || crypto.randomUUID(),
      password: String(item?.password ?? ""),
      changedAt: item?.changedAt || new Date().toISOString(),
    }))
    .filter((item) => item.password)
    .slice(0, PASSWORD_HISTORY_LIMIT);
}

function addPasswordHistoryEntry(history, password, changedAt = new Date().toISOString()) {
  const value = String(password ?? "");
  if (!value) return normalizePasswordHistory(history);
  const existing = normalizePasswordHistory(history).filter((item) => item.password !== value);
  return [{ id: crypto.randomUUID(), password: value, changedAt }, ...existing].slice(0, PASSWORD_HISTORY_LIMIT);
}

function parseSearchQuery(value) {
  const tokens = String(value || "").match(/"[^"]+"|\S+/g) || [];
  const search = { terms: [], tags: [], login: [], name: [], has: [], missing: [], risk: null };
  for (const rawToken of tokens) {
    const token = stripSearchQuotes(rawToken);
    const separator = token.indexOf(":");
    if (separator <= 0) {
      search.terms.push(token.toLowerCase());
      continue;
    }
    const key = token.slice(0, separator).toLowerCase();
    const rawValue = stripSearchQuotes(token.slice(separator + 1)).toLowerCase();
    if (!rawValue) continue;
    if (key === "tag") search.tags.push(rawValue);
    else if (key === "login") search.login.push(rawValue);
    else if (key === "name") search.name.push(rawValue);
    else if (key === "has") search.has.push(rawValue);
    else if (key === "missing") search.missing.push(rawValue);
    else if (key === "risk") search.risk = ["1", "true", "yes", "y"].includes(rawValue);
    else search.terms.push(token.toLowerCase());
  }
  return search;
}

function stripSearchQuotes(value) {
  const text = String(value || "").trim();
  return text.length >= 2 && text.startsWith('"') && text.endsWith('"') ? text.slice(1, -1) : text;
}

function entryMatchesSearch(entry, search, vault) {
  const parsed = typeof search === "string" ? parseSearchQuery(search) : search || parseSearchQuery("");
  const tags = parseEntryTags(entry.tags);
  const customText = normalizeCustomFields(entry.customFields)
    .map((field) => `${field.label} ${field.value}`)
    .join(" ");
  const haystack = [entry.name, entry.login, entry.backupEmail, entry.backupPhone, entry.tags, entry.notes, customText]
    .join(" ")
    .toLowerCase();
  if (parsed.risk === true && !entryHasRisk(entry, vault)) return false;
  if (parsed.risk === false && entryHasRisk(entry, vault)) return false;
  if (parsed.tags.some((tag) => !tags.includes(tag))) return false;
  if (parsed.login.some((value) => !String(entry.login || "").toLowerCase().includes(value))) return false;
  if (parsed.name.some((value) => !String(entry.name || "").toLowerCase().includes(value))) return false;
  if (parsed.has.some((field) => !entryHasField(entry, field))) return false;
  if (parsed.missing.some((field) => entryHasField(entry, field))) return false;
  return parsed.terms.every((term) => haystack.includes(term));
}

function entryHasField(entry, field) {
  const normalized = normalizeSearchField(field);
  if (normalized === "password") return Boolean(String(entry.password || "").trim());
  if (normalized === "2fa") return Boolean(String(entry.totpSecret || "").trim());
  if (normalized === "recovery") return Boolean(String(entry.recoveryCodes || "").trim());
  if (normalized === "backup") return Boolean(String(entry.backupEmail || entry.backupPhone || "").trim());
  if (normalized === "notes") return Boolean(String(entry.notes || "").trim());
  if (normalized === "login") return Boolean(String(entry.login || "").trim());
  if (normalized === "custom") return normalizeCustomFields(entry.customFields).length > 0;
  if (normalized === "favorite") return Boolean(entry.favorite);
  return false;
}

function normalizeSearchField(field) {
  const value = String(field || "").toLowerCase();
  if (["totp", "otp", "mfa", "2fa"].includes(value)) return "2fa";
  if (["recovery", "codes", "code", "recoverycodes"].includes(value)) return "recovery";
  if (["backup", "backupemail", "backupphone", "phone", "email"].includes(value)) return "backup";
  if (["note", "notes"].includes(value)) return "notes";
  if (["custom", "field", "fields", "extra"].includes(value)) return "custom";
  if (["favorite", "star", "pinned", "pin"].includes(value)) return "favorite";
  if (["password", "pass", "pwd"].includes(value)) return "password";
  if (["login", "account", "username"].includes(value)) return "login";
  return value;
}

function getRiskEntryCount(vault) {
  const entries = Array.isArray(vault?.entries) ? vault.entries : [];
  return entries.filter((entry) => entryHasRisk(entry, vault)).length;
}

function getVaultTags(vault) {
  return Array.from(new Set((vault?.entries || []).flatMap((entry) => parseEntryTags(entry.tags)))).sort((a, b) =>
    a.localeCompare(b),
  );
}

function parseEntryTags(value) {
  return String(value || "")
    .split(/[,\s]+/)
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);
}

function getVaultOverview(vault, lastBackupAt = "", cacheDisabled = false, autoLockMinutes = 5) {
  const totalEntries = Array.isArray(vault?.entries) ? vault.entries.length : 0;
  const backupStale = isBackupStale(lastBackupAt);
  const backupTimeText = lastBackupAt ? formatDateTime(lastBackupAt) || "未知时间" : "";
  const health = getVaultHealth(vault, lastBackupAt);
  return {
    totalEntries,
    riskEntries: getRiskEntryCount(vault),
    health,
    backupStale,
    backupDetail: lastBackupAt
      ? `上次导出：${backupTimeText}。${backupStale ? `已超过 ${BACKUP_REMINDER_DAYS} 天。` : "当前备份正常。"}`
      : "还没有导出备份，建议先保存一份离线副本。",
    localCacheLabel: cacheDisabled ? "已关闭" : "已开启",
    autoLockLabel: autoLockMinutes > 0 ? `${autoLockMinutes} 分钟` : "已关闭",
  };
}

function getVaultHealth(vault, lastBackupAt = "") {
  const report = analyzeVaultSecurity(vault);
  if (!report.totalEntries) return { score: 0, level: "empty", label: "尚未开始", reasons: ["添加账号后开始评分"] };
  const penalties = [
    { count: report.emptyPasswords.length, weight: 18, label: "缺少密码" },
    { count: report.weakPasswords.length, weight: 12, label: "弱密码" },
    { count: report.duplicatePasswordGroups.length, weight: 15, label: "重复密码" },
    { count: report.missingTotp.length, weight: 8, label: "缺少 2FA" },
    { count: report.missingRecovery.length, weight: 6, label: "缺少恢复码" },
    { count: isBackupStale(lastBackupAt) ? 1 : 0, weight: 10, label: "备份过期或缺失" },
  ];
  const score = Math.max(0, Math.min(100, 100 - penalties.reduce((sum, item) => sum + item.count * item.weight, 0)));
  const level = score >= 85 ? "good" : score >= 60 ? "warning" : "danger";
  const reasons = penalties.filter((item) => item.count > 0).map((item) => `${item.label} ${item.count} 项`);
  return { score, level, label: healthLabel(level), reasons };
}

function healthLabel(level) {
  if (level === "good") return "状态良好";
  if (level === "warning") return "建议处理";
  if (level === "danger") return "需要尽快处理";
  return "尚未开始";
}

function analyzeVaultSecurity(vault) {
  const entries = Array.isArray(vault?.entries) ? vault.entries : [];
  const emptyPasswords = [];
  const weakPasswords = [];
  const missingTotp = [];
  const missingRecovery = [];
  const passwordGroups = new Map();
  for (const entry of entries) {
    const password = String(entry.password || "");
    if (!password) emptyPasswords.push(entry);
    else {
      if (scorePassword(password).level === "weak") weakPasswords.push(entry);
      if (!passwordGroups.has(password)) passwordGroups.set(password, []);
      passwordGroups.get(password).push(entry);
    }
    if (!String(entry.totpSecret || "").trim()) missingTotp.push(entry);
    if (!String(entry.recoveryCodes || "").trim()) missingRecovery.push(entry);
  }
  const duplicatePasswordGroups = Array.from(passwordGroups.values())
    .filter((group) => group.length > 1)
    .map((entries) => ({ password: entries[0].password, entries }));
  return {
    totalEntries: entries.length,
    totalIssues: emptyPasswords.length + weakPasswords.length + duplicatePasswordGroups.length + missingTotp.length + missingRecovery.length,
    emptyPasswords,
    weakPasswords,
    duplicatePasswordGroups,
    missingTotp,
    missingRecovery,
  };
}

function getEntryRiskScore(entry, vault) {
  let score = 0;
  const password = String(entry.password || "");
  if (!password) score += 40;
  else if (scorePassword(password).level === "weak") score += 24;
  if (password && hasDuplicatePassword(entry, vault)) score += 30;
  if (!String(entry.totpSecret || "").trim()) score += 18;
  if (!String(entry.recoveryCodes || "").trim()) score += 12;
  return score;
}

function entryHasRisk(entry, vault) {
  return getEntryRiskScore(entry, vault) > 0;
}

function hasDuplicatePassword(entry, vault) {
  const password = String(entry.password || "");
  if (!password) return false;
  return (vault?.entries || []).some((item) => item.id !== entry.id && item.password && item.password === password);
}

function summarizeImportDiff(currentVault, incomingVault) {
  const currentEntries = Array.isArray(currentVault?.entries) ? currentVault.entries : [];
  const incomingEntries = Array.isArray(incomingVault?.entries) ? incomingVault.entries : [];
  const currentNames = new Set(currentEntries.map(importEntryKey));
  const incomingNames = new Set(incomingEntries.map(importEntryKey));
  let matched = 0;
  let added = 0;
  let removed = 0;
  for (const key of incomingNames) currentNames.has(key) ? (matched += 1) : (added += 1);
  for (const key of currentNames) if (!incomingNames.has(key)) removed += 1;
  return { currentTotal: currentEntries.length, incomingTotal: incomingEntries.length, added, matched, removed };
}

function summarizeBackupVerification(currentVault, backupVault) {
  const currentEntries = Array.isArray(currentVault?.entries) ? currentVault.entries : [];
  const backupEntries = Array.isArray(backupVault?.entries) ? backupVault.entries : [];
  const currentKeys = new Set(currentEntries.map(importEntryKey));
  const backupKeys = new Set(backupEntries.map(importEntryKey));
  return {
    ...summarizeImportDiff(currentVault, backupVault),
    backupUpdatedAt: backupVault?.updatedAt || "",
    addedEntries: backupEntries.filter((entry) => !currentKeys.has(importEntryKey(entry))).map(entryPreviewLabel),
    matchedEntries: backupEntries.filter((entry) => currentKeys.has(importEntryKey(entry))).map(entryPreviewLabel),
    removedEntries: currentEntries.filter((entry) => !backupKeys.has(importEntryKey(entry))).map(entryPreviewLabel),
  };
}

function formatImportConfirmation(fileName, diff, importMode) {
  const safeName = fileName || "备份文件";
  if (importMode === "replace") {
    return `将整体替换为“${safeName}”：备份包含 ${diff.incomingTotal} 个账号，当前 ${diff.currentTotal} 个账号会被替换；其中 ${diff.removed} 个当前账号不在备份中。替换后仍会用当前主密码重新加密并同步。继续？`;
  }
  return `将合并导入“${safeName}”：新增 ${diff.added} 个，重名覆盖 ${diff.matched} 个，当前独有 ${diff.removed} 个会保留。导入后仍会用当前主密码重新加密并同步。继续？`;
}

function entryPreviewLabel(entry) {
  return entry.name || entry.login || "未命名账号";
}

function mergeImportedVault(currentVault, incomingVault) {
  const current = normalizeVault(currentVault);
  const incoming = normalizeVault(incomingVault);
  const incomingKeys = new Set(incoming.entries.map(importEntryKey));
  const keptCurrentEntries = current.entries.filter((entry) => !incomingKeys.has(importEntryKey(entry)));
  return normalizeVault({ version: 1, createdAt: current.createdAt || incoming.createdAt, updatedAt: new Date().toISOString(), entries: [...incoming.entries, ...keptCurrentEntries] });
}

function importEntryKey(entry) {
  return normalizeEmail(entry.login) || String(entry.name || "").trim().toLowerCase() || entry.id || "";
}

async function makeAuthSecret(email, password) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(`account-secret-vault auth v2\n${normalizeEmail(email)}`),
      iterations: AUTH_KDF_ITERATIONS,
      hash: "SHA-256",
    },
    material,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

function isBackupStale(value) {
  if (!value) return true;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return true;
  return Date.now() - date.getTime() > BACKUP_REMINDER_MS;
}

function formatDateTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return `${date.getMonth() + 1}/${date.getDate()} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function generateTotp(secret, timestamp = Date.now()) {
  const key = await crypto.subtle.importKey("raw", base32ToBytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = Math.floor(timestamp / 1000 / 30);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

function base32ToBytes(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(input || "").replace(/\s|=|-/g, "").toUpperCase();
  let bits = "";
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("2FA 种子不是有效的 Base32。外部链接需要包含 secret 参数。");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) bytes.push(parseInt(bits.slice(index, index + 8), 2));
  if (!bytes.length) throw new Error("2FA 种子不是有效的 Base32。外部链接需要包含 secret 参数。");
  return new Uint8Array(bytes);
}

function parseTotpInput(input) {
  const value = String(input || "").trim();
  if (!value) return { secret: "", label: "" };
  if (!value.toLowerCase().startsWith("otpauth://")) return { secret: value.replace(/\s+/g, "").toUpperCase(), label: "" };
  try {
    const url = new URL(value);
    return {
      secret: String(url.searchParams.get("secret") || "").replace(/\s+/g, "").toUpperCase(),
      label: url.searchParams.get("issuer") || decodeURIComponent(url.pathname.split("/").pop() || ""),
    };
  } catch {
    return { secret: value.replace(/\s+/g, "").toUpperCase(), label: "" };
  }
}

function normalizePasswordLength(length) {
  const value = Number(length);
  if (!Number.isFinite(value)) return GENERATED_PASSWORD_LENGTH;
  return Math.min(64, Math.max(12, Math.round(value)));
}

function normalizePasswordOptions(lengthOrOptions = GENERATED_PASSWORD_LENGTH) {
  if (typeof lengthOrOptions === "object" && lengthOrOptions !== null) {
    return { length: normalizePasswordLength(lengthOrOptions.length), symbols: lengthOrOptions.symbols !== false, readable: lengthOrOptions.readable !== false };
  }
  return { length: normalizePasswordLength(lengthOrOptions), symbols: true, readable: true };
}

function generatePassword(lengthOrOptions = GENERATED_PASSWORD_LENGTH) {
  const options = normalizePasswordOptions(lengthOrOptions);
  const lower = options.readable ? "abcdefghjkmnpqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz";
  const upper = options.readable ? "ABCDEFGHJKMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = options.readable ? "23456789" : "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.?";
  const groups = [lower, upper, digits, ...(options.symbols ? [symbols] : [])];
  const all = groups.join("");
  const bytes = crypto.getRandomValues(new Uint8Array(options.length));
  const chars = groups.map((group, index) => group[bytes[index] % group.length]);
  for (let index = chars.length; index < options.length; index += 1) chars.push(all[bytes[index] % all.length]);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swap = bytes[index] % (index + 1);
    [chars[index], chars[swap]] = [chars[swap], chars[index]];
  }
  return chars.join("");
}

function scorePassword(password) {
  const value = String(password || "");
  let score = 0;
  if (value.length >= 12) score += 1;
  if (value.length >= 16) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  if (/(.)\1{2,}/.test(value)) score -= 1;
  if (score >= 5) return { level: "strong", label: "强密码" };
  if (score >= 3) return { level: "medium", label: "中等强度" };
  return { level: "weak", label: "弱密码" };
}

function formatMasterPasswordStrength(password) {
  const strength = scorePassword(password);
  if (strength.level === "strong") return "主密码强度：强密码。";
  if (strength.level === "medium") return "主密码强度：中等强度，建议增加长度或混合字符。";
  return "主密码强度：弱密码，建议使用更长的短语并混合数字或符号。";
}

function isVaultEnvelope(value) {
  const schemaOk = value?.schemaVersion === undefined || value.schemaVersion === 1;
  return Boolean(value && typeof value === "object" && schemaOk && value.version === 1 && value.kdf?.name === "PBKDF2-SHA256" && Number.isInteger(value.kdf.iterations) && value.kdf.iterations >= 100000 && typeof value.kdf.salt === "string" && value.cipher?.name === "AES-GCM" && typeof value.cipher.iv === "string" && typeof value.cipher.data === "string");
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export {
  analyzeVaultSecurity,
  addPasswordHistoryEntry,
  base32ToBytes,
  base64ToBytes,
  bytesToBase64,
  entryHasRisk,
  entryMatchesSearch,
  formatImportConfirmation,
  formatMasterPasswordStrength,
  formatDateTime,
  generatePassword,
  generateTotp,
  getEntryRiskScore,
  getRiskEntryCount,
  getVaultHealth,
  getVaultOverview,
  getVaultTags,
  isBackupStale,
  isVaultEnvelope,
  makeAuthSecret,
  mergeImportedVault,
  normalizeCustomFields,
  normalizeEntry,
  normalizeEmail,
  normalizePasswordHistory,
  normalizePasswordLength,
  normalizePasswordOptions,
  normalizeVault,
  parseSearchQuery,
  parseEntryTags,
  parseTotpInput,
  scorePassword,
  summarizeBackupVerification,
  summarizeImportDiff,
};
