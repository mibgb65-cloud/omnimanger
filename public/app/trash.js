function getTrashEntries(vault) {
  return Array.isArray(vault?.trash) ? vault.trash : [];
}

function moveEntryToTrash(vault, entryId, deletedAt = new Date().toISOString()) {
  const entries = Array.isArray(vault?.entries) ? vault.entries : [];
  const index = entries.findIndex((entry) => entry.id === entryId);
  if (index < 0) return null;
  const [entry] = entries.splice(index, 1);
  const trashed = { ...entry, deletedAt };
  vault.entries = entries;
  vault.trash = [trashed, ...getTrashEntries(vault).filter((item) => item.id !== entry.id)];
  return trashed;
}

function restoreTrashEntry(vault, entryId, restoredAt = new Date().toISOString()) {
  const trash = getTrashEntries(vault);
  const index = trash.findIndex((entry) => entry.id === entryId);
  if (index < 0) return null;
  const [{ deletedAt, ...entry }] = trash.splice(index, 1);
  const entries = Array.isArray(vault.entries) ? vault.entries.filter((item) => item.id !== entryId) : [];
  const restored = { ...entry, updatedAt: restoredAt };
  vault.trash = trash;
  vault.entries = [restored, ...entries];
  return restored;
}

function deleteTrashEntry(vault, entryId) {
  const trash = getTrashEntries(vault);
  const index = trash.findIndex((entry) => entry.id === entryId);
  if (index < 0) return null;
  const [entry] = trash.splice(index, 1);
  vault.trash = trash;
  return entry;
}

export { deleteTrashEntry, getTrashEntries, moveEntryToTrash, restoreTrashEntry };
