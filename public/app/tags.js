function updateVaultTag(vault, oldTag, nextTag) {
  const source = normalizeTag(oldTag);
  const target = normalizeTag(nextTag);
  if (!vault || !Array.isArray(vault.entries) || !source || source === target) return { changed: 0 };

  const now = new Date().toISOString();
  let changed = 0;
  for (const entry of vault.entries) {
    const tags = parseTags(entry.tags);
    if (!tags.includes(source)) continue;
    const nextTags = Array.from(new Set(tags.flatMap((tag) => (tag === source ? [target] : [tag])).filter(Boolean)));
    entry.tags = nextTags.join(" ");
    entry.updatedAt = now;
    changed += 1;
  }
  return { changed };
}

function parseTags(value) {
  return String(value || "")
    .split(/[,\s]+/)
    .map(normalizeTag)
    .filter(Boolean);
}

function normalizeTag(value) {
  return String(value || "").trim().toLowerCase();
}

export { normalizeTag, updateVaultTag };
