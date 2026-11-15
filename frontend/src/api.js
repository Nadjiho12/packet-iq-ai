// Thin fetch wrapper. Base URL is empty in dev (Vite proxy); set VITE_API_BASE for other setups.
const BASE = import.meta.env?.VITE_API_BASE ?? "";

async function request(path, options) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, options);
  } catch {
    throw new Error("Cannot reach the backend. Is it running on port 8000?");
  }
  if (!res.ok) {
    let detail = `Request failed (HTTP ${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join("; ");
    } catch {
      /* non-JSON error body: keep the generic message */
    }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

export const getMetrics = () => request("/api/v1/metrics");
export const getAlerts = (limit = 50) => request(`/api/v1/alerts?limit=${limit}`);

export function uploadPcap(file, { ai = false, notify = false } = {}) {
  const body = new FormData();
  body.append("file", file);
  return request(`/api/v1/upload?ai=${ai}&notify=${notify}`, { method: "POST", body });
}

export const clearData = () => request("/api/v1/data", { method: "DELETE" });

export const getAiSettings = () => request("/api/v1/settings/ai");
export const saveAiSettings = (settings) =>
  request("/api/v1/settings/ai", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  });
export const removeAiSettings = () => request("/api/v1/settings/ai", { method: "DELETE" });

export const investigateAlert = (id) => request(`/api/v1/alerts/${id}/investigate`, { method: "POST" });

// Downloads one investigated alert. The server answers 409 until the alert has been investigated.
export async function exportAlert(id, format) {
  let res;
  try {
    res = await fetch(`${BASE}/api/v1/alerts/${id}/export?format=${format}`);
  } catch {
    throw new Error("Cannot reach the backend. Is it running on port 8000?");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : `Export failed (HTTP ${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `alert-${id}-investigation.${format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}