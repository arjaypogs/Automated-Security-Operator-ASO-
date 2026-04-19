const BASE = import.meta.env.VITE_API_URL || "";

async function request(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(err || res.statusText);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  scans: {
    list: () => request("GET", "/api/scans"),
    get: (id) => request("GET", `/api/scans/${id}`),
    create: (data) => request("POST", "/api/scans", data),
    delete: (id) => request("DELETE", `/api/scans/${id}`),
  },
};

export function createScanWS(scanId, onMessage) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const host = import.meta.env.VITE_WS_URL || location.host;
  const ws = new WebSocket(`${proto}://${host}/api/scans/${scanId}/ws`);
  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)); } catch {}
  };
  return ws;
}
