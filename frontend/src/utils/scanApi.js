export function normalizeBase(base) {
  return base.trim().replace(/\/+$/, "");
}

export function parseExtraFields(raw) {
  if (!raw.trim()) return {};
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("Extra fields must be a JSON object.");
    }
    return parsed;
  } catch (err) {
    throw new Error(`Invalid Extra Fields JSON: ${err.message}`);
  }
}

export async function startScanRequest(apiBase, payload) {
  const res = await fetch(`${apiBase}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Scan start failed — HTTP ${res.status}`);
  return res.json();
}

export async function fetchScanStatus(apiBase, scanId) {
  const res = await fetch(`${apiBase}/scan/${scanId}`);
  if (!res.ok) throw new Error(`Poll failed — HTTP ${res.status}`);
  return res.json();
}