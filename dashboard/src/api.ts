/**
 * api.ts — Service layer for communicating with the Python API sidecar.
 * All REST calls and WebSocket connections go through here.
 */

const API_BASE = "http://127.0.0.1:8642";
const WS_BASE = "ws://127.0.0.1:8642";

// ─── Types ───────────────────────────────────────────────────

export interface StatusResponse {
  status: string;
  timestamp: string;
  usb_detected: boolean;
  usb_path: string | null;
  db_path: string;
  monitoring_active: boolean;
  autoscan_enabled: boolean;
  autoscan_detector_running: boolean;
  platform: string;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  event_type: string;
  file_path: string;
  file_size: number | null;
  sha256: string | null;
  tag: string;
  severity: number;
  category: string;
  action: string;
  description: string;
  quarantine_path: string | null;
}

export interface QuarantineItem {
  id: number;
  timestamp: string;
  original_path: string;
  quarantine_path: string;
  meta_path: string;
  tag: string;
  severity: number;
  category: string;
}

export interface DashboardStats {
  total_events: number;
  threats_detected: number;
  quarantined_files: number;
  severity_distribution: { critical: number; medium: number; low: number };
  events_by_type: Record<string, number>;
  top_categories: { category: string; count: number }[];
  recent_activity: {
    timestamp: string;
    event_type: string;
    file_path: string;
    tag: string;
    severity: number;
    category: string;
  }[];
}

export interface ScanResult {
  summary: { detected: number; clean: number };
  scan_path: string;
  details: {
    timestamp: string;
    file_path: string;
    tag: string;
    severity: number;
    category: string;
    action: string;
    description: string;
  }[];
}

export interface QuarantineSummary {
  generated_at?: string;
  stats: {
    total_quarantined: number;
    total_severity_score?: number;
    daily_quarantined?: number;
    weekly_quarantined?: number;
  };
  top_threats: { tag: string; count: number }[];
}

// ─── REST helpers ────────────────────────────────────────────

async function fetchJSON<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", ...opts?.headers },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

// ─── Public API ──────────────────────────────────────────────

export const api = {
  /** Health check */
  status: () => fetchJSON<StatusResponse>("/api/status"),

  /** Dashboard aggregate stats */
  stats: () => fetchJSON<DashboardStats>("/api/stats"),

  /** Trigger a one-time scan */
  scan: (path: string) =>
    fetchJSON<ScanResult>(`/api/scan?path=${encodeURIComponent(path)}`, {
      method: "POST",
    }),

  /** Get event logs */
  logs: (params?: { event?: string; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params?.event) q.set("event", params.event);
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return fetchJSON<{ total: number; logs: LogEntry[] }>(
      `/api/logs?${q.toString()}`
    );
  },

  /** List quarantined files */
  quarantine: () =>
    fetchJSON<{ total: number; items: QuarantineItem[] }>("/api/quarantine"),

  /** Restore a quarantined file */
  quarantineRestore: (id: number) =>
    fetchJSON<{ status: string }>(`/api/quarantine/${id}/restore`, {
      method: "POST",
    }),

  /** Delete a quarantined file */
  quarantineDelete: (id: number) =>
    fetchJSON<{ status: string }>(`/api/quarantine/${id}`, {
      method: "DELETE",
    }),

  /** Get quarantine summary */
  quarantineSummary: () =>
    fetchJSON<QuarantineSummary>("/api/quarantine/summary"),

  /** Get current signatures */
  signatures: () => fetchJSON<any>("/api/signatures"),

  /** Enable auto-scan on USB insertion */
  autoscanEnable: () =>
    fetchJSON<{ status: string; message: string }>("/api/autoscan/enable", {
      method: "POST",
    }),

  /** Disable auto-scan */
  autoscanDisable: () =>
    fetchJSON<{ status: string; message: string }>("/api/autoscan/disable", {
      method: "POST",
    }),

  /** Get auto-scan status and history */
  autoscanStatus: () =>
    fetchJSON<{
      enabled: boolean;
      detector_running: boolean;
      platform: string;
      history: {
        timestamp: string;
        mount_path: string;
        summary: { detected: number; clean: number };
        status: string;
      }[];
    }>("/api/autoscan/status"),
};

// ─── WebSocket for real-time monitor ─────────────────────────

export function connectMonitorWS(
  usbPath: string,
  onEvent: (data: any) => void,
  onStatus: (msg: string) => void,
  onError: (err: string) => void
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/monitor`);

  ws.onopen = () => {
    ws.send(JSON.stringify({ path: usbPath }));
    onStatus("Connected — monitoring " + usbPath);
  };

  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.type === "status") {
        onStatus(data.message);
      } else if (data.type === "event") {
        onEvent(data.data);
      }
    } catch {
      onError("Failed to parse WebSocket message");
    }
  };

  ws.onerror = () => onError("WebSocket connection error");
  ws.onclose = () => onStatus("Disconnected");

  return ws;
}
