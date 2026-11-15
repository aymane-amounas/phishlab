// Thin API client. All calls are same-origin (dev proxy -> backend).
const base = "/api";

async function req(path, opts = {}) {
  const res = await fetch(base + path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res;
}

export const api = {
  health: () => req("/health"),
  stats: () => req("/stats"),
  listCases: (q = "") => req(`/cases${q ? `?q=${encodeURIComponent(q)}` : ""}`),
  getCase: (id) => req(`/cases/${id}`),
  createCaseFile: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return req("/cases", { method: "POST", body: fd });
  },
  createCaseText: (field, value) => {
    const fd = new FormData();
    fd.append(field, value);
    return req("/cases", { method: "POST", body: fd });
  },
  setDisposition: (id, disposition, rationale) =>
    req(`/cases/${id}/disposition`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ disposition, rationale }),
    }),
  setNotes: (id, notes) =>
    req(`/cases/${id}/notes`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notes }),
    }),
  deleteCase: (id) => req(`/cases/${id}`, { method: "DELETE" }),
  reportJsonUrl: (id, redact) => `${base}/cases/${id}/report.json?redact=${redact}`,
  reportPdfUrl: (id, redact) => `${base}/cases/${id}/report.pdf?redact=${redact}`,
};
