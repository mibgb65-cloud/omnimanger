const SOURCE_TAGS = {
  bitwarden: "bitwarden",
  browser: "browser",
  onePassword: "1password",
  csv: "csv",
  json: "json",
};

function parseExternalVaultImport(text, fileName = "") {
  const content = String(text || "").replace(/^\uFEFF/, "").trim();
  if (!content) throw new Error("导入文件为空。");

  const parsed = looksLikeJson(content)
    ? parseJsonImport(JSON.parse(content))
    : parseCsvImport(content, fileName);
  const now = new Date().toISOString();
  const entries = parsed.entries.filter(hasImportValue).map((entry) => normalizeImportedEntry(entry, parsed.source, now));
  if (!entries.length) throw new Error("没有找到可导入的账号。");

  return {
    version: 1,
    importSource: parsed.source,
    createdAt: now,
    updatedAt: now,
    entries,
  };
}

function looksLikeJson(content) {
  return content.startsWith("{") || content.startsWith("[");
}

function parseJsonImport(data) {
  if (Array.isArray(data)) return { source: SOURCE_TAGS.json, entries: data.map(genericRecordToEntry) };
  if (Array.isArray(data?.items)) return { source: SOURCE_TAGS.bitwarden, entries: data.items.map(bitwardenItemToEntry) };

  const onePasswordItems = collectOnePasswordItems(data);
  if (onePasswordItems.length) {
    return { source: SOURCE_TAGS.onePassword, entries: onePasswordItems.map(onePasswordItemToEntry) };
  }

  if (Array.isArray(data?.entries)) return { source: SOURCE_TAGS.json, entries: data.entries.map(genericRecordToEntry) };
  throw new Error("不支持的 JSON 导入格式。");
}

function parseCsvImport(content, fileName) {
  const rows = parseCsvRows(content).filter((row) => row.some((value) => cleanText(value)));
  if (rows.length < 2) throw new Error("CSV 文件缺少账号数据。");

  const headers = rows[0].map(normalizeHeader);
  const records = rows.slice(1).map((row) =>
    Object.fromEntries(headers.map((header, index) => [header, cleanText(row[index])])),
  );
  const source = detectCsvSource(headers, fileName);
  return { source, entries: records.map((record) => csvRecordToEntry(record, source)) };
}

function parseCsvRows(content) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    if (quoted) {
      if (char === '"' && content[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') quoted = false;
      else field += char;
      continue;
    }

    if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (char !== "\r") field += char;
  }

  row.push(field);
  rows.push(row);
  return rows;
}

function detectCsvSource(headers, fileName) {
  const headerSet = new Set(headers);
  const name = String(fileName || "").toLowerCase();
  if (headerSet.has("login_username") || headerSet.has("login_password")) return SOURCE_TAGS.bitwarden;
  if (headerSet.has("website") || headerSet.has("otp auth") || name.includes("1password")) return SOURCE_TAGS.onePassword;
  if (headerSet.has("url") && headerSet.has("username") && headerSet.has("password")) return SOURCE_TAGS.browser;
  return SOURCE_TAGS.csv;
}

function csvRecordToEntry(record, source) {
  const url = pick(record, ["login_uri", "url", "website", "uri"]);
  return {
    name: pick(record, ["name", "title", "item name"]) || nameFromUrl(url),
    login: pick(record, ["login_username", "username", "user name", "email", "login"]),
    password: pick(record, ["login_password", "password"]),
    totpSecret: pick(record, ["login_totp", "totp", "otp", "otp auth", "2fa", "one-time password"]),
    tags: joinTags([pick(record, ["folder", "category"]), source]),
    notes: joinNotes([pick(record, ["notes", "note"]), url ? `URL: ${url}` : ""]),
  };
}

function bitwardenItemToEntry(item) {
  const login = item?.login || {};
  const url = Array.isArray(login.uris) ? login.uris.map((uri) => uri?.uri).filter(Boolean).join("\n") : "";
  return {
    name: item?.name,
    login: login.username,
    password: login.password,
    totpSecret: login.totp,
    notes: joinNotes([item?.notes, url ? `URL: ${url}` : "", formatCustomFields(item?.fields)]),
    tags: SOURCE_TAGS.bitwarden,
  };
}

function onePasswordItemToEntry(item) {
  const fields = collectOnePasswordFields(item);
  const url = firstValue(item?.overview?.urls, "url") || firstValue(item?.urls, "url");
  return {
    name: item?.overview?.title || item?.title,
    login: fieldByName(fields, ["username", "email", "user name"]),
    password: fieldByName(fields, ["password"]),
    totpSecret: fieldByName(fields, ["one-time password", "otp", "totp", "2fa"]),
    notes: joinNotes([item?.details?.notesPlain || item?.notesPlain || item?.notes, url ? `URL: ${url}` : ""]),
    tags: SOURCE_TAGS.onePassword,
  };
}

function genericRecordToEntry(record) {
  const login = record?.login && typeof record.login === "object" ? record.login : {};
  const url = pick(record, ["url", "website", "uri", "login_uri"]);
  return {
    name: pick(record, ["name", "title", "itemName"]) || nameFromUrl(url),
    login: login.username || pick(record, ["username", "email", "user", "login"]),
    password: login.password || pick(record, ["password"]),
    totpSecret: login.totp || pick(record, ["totpSecret", "totp", "otp", "otpauth"]),
    recoveryCodes: pick(record, ["recoveryCodes", "recovery", "backupCodes"]),
    tags: pick(record, ["tags", "folder", "category"]),
    notes: joinNotes([pick(record, ["notes", "note"]), url ? `URL: ${url}` : ""]),
  };
}

function normalizeImportedEntry(entry, source, now) {
  const name = cleanText(entry.name) || cleanText(entry.login) || "未命名账号";
  return {
    id: crypto.randomUUID(),
    name,
    login: cleanText(entry.login),
    password: cleanText(entry.password),
    totpSecret: normalizeTotpSecret(entry.totpSecret),
    recoveryCodes: cleanText(entry.recoveryCodes),
    backupEmail: "",
    backupPhone: "",
    tags: joinTags(["imported", source, entry.tags]),
    notes: cleanText(entry.notes),
    createdAt: now,
    updatedAt: now,
  };
}

function collectOnePasswordItems(data) {
  return (data?.accounts || []).flatMap((account) => (account.vaults || []).flatMap((vault) => vault.items || []));
}

function collectOnePasswordFields(item) {
  const detailFields = item?.details?.loginFields || [];
  const sectionFields = (item?.details?.sections || []).flatMap((section) => section.fields || []);
  return [...detailFields, ...sectionFields];
}

function fieldByName(fields, names) {
  const normalized = names.map(normalizeHeader);
  const field = fields.find((item) => normalized.includes(normalizeHeader(item?.designation || item?.name || item?.label || item?.title)));
  return fieldValue(field);
}

function fieldValue(field) {
  const value = field?.value;
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (typeof value?.concealed === "string") return value.concealed;
  if (typeof value?.string === "string") return value.string;
  return "";
}

function firstValue(items, key) {
  return Array.isArray(items) ? cleanText(items.find((item) => item?.[key])?.[key]) : "";
}

function formatCustomFields(fields) {
  if (!Array.isArray(fields)) return "";
  return fields
    .map((field) => [cleanText(field?.name), cleanText(field?.value)].filter(Boolean).join(": "))
    .filter(Boolean)
    .join("\n");
}

function pick(record, keys) {
  for (const key of keys) {
    const value = cleanText(record?.[normalizeHeader(key)] ?? record?.[key]);
    if (value) return value;
  }
  return "";
}

function normalizeTotpSecret(value) {
  const text = cleanText(value);
  if (!text) return "";
  if (!text.toLowerCase().startsWith("otpauth://")) return text.replace(/\s+/g, "").toUpperCase();
  try {
    return cleanText(new URL(text).searchParams.get("secret")).replace(/\s+/g, "").toUpperCase();
  } catch {
    return text.replace(/\s+/g, "").toUpperCase();
  }
}

function nameFromUrl(value) {
  try {
    return new URL(cleanText(value)).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function joinNotes(parts) {
  return parts.map(cleanText).filter(Boolean).join("\n");
}

function joinTags(parts) {
  return Array.from(new Set(parts.flatMap((part) => cleanText(part).split(/[,\s]+/)).filter(Boolean))).join(" ");
}

function hasImportValue(entry) {
  return Boolean(entry.name || entry.login || entry.password || entry.totpSecret || entry.notes);
}

function normalizeHeader(value) {
  return cleanText(value).toLowerCase().replace(/\s+/g, " ");
}

function cleanText(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return "";
  return String(value).trim();
}

export { parseExternalVaultImport };
