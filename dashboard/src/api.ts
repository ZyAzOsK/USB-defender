/**
 * api.ts — Service layer for communicating with the Python API sidecar.
 * All REST calls and WebSocket connections go through here.
 */

const API_BASE = "http://127.0.0.1:8642";
const WS_BASE = "ws://127.0.0.1:8642";

/** Displayed in the sidebar. Kept in step with tauri.conf.json + app/api.py. */
export const APP_VERSION = "1.0.3";

// ─── Types ───────────────────────────────────────────────────

export interface StatusResponse {
  status: string;
  version: string;
  timestamp: string;
  usb_detected: boolean;
  usb_path: string | null;
  usb_mounts: string[];
  db_path: string;
  data_dir: string;
  monitoring_active: boolean;
  monitored_paths: string[];
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
  summary: {
    detected: number;
    clean: number;
    quarantined?: number;
    errors?: number;
    total?: number;
  };
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
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...opts,
      headers: { "Content-Type": "application/json", ...opts?.headers },
    });
  } catch {
    // fetch only rejects on network failure, which here means the sidecar
    // is not up. Surface that rather than a bare "Failed to fetch".
    throw new Error(
      "Cannot reach the USB Defender engine on 127.0.0.1:8642. It may still be starting."
    );
  }

  if (!res.ok) {
    // FastAPI reports problems as {"detail": "..."}; showing the raw JSON
    // envelope to the user is noise.
    let message = `Request failed (HTTP ${res.status})`;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") {
        message = body.detail;
      } else if (Array.isArray(body?.detail)) {
        message = body.detail.map((d: any) => d?.msg ?? String(d)).join("; ");
      }
    } catch {
      /* non-JSON body — keep the generic message */
    }
    throw new Error(message);
  }

  return res.json();
}

// ─── Public API ──────────────────────────────────────────────

export const api = {
  /** Health check */
  status: () => fetchJSON<StatusResponse>("/api/status"),

  /** Currently mounted removable volumes, for the drive picker */
  mounts: () =>
    fetchJSON<{ platform: string; mounts: string[] }>("/api/mounts"),

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

  /** Deploy portable scanner to USB */
  armUsb: (usbPath: string) =>
    fetchJSON<{ status: string; message: string; deployed?: string[] }>("/api/arm-usb", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ usb_path: usbPath })
    }),
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
      } else if (data.type === "error" || data.error) {
        // The server refuses unsafe or nonexistent paths; report the reason
        // instead of leaving the UI stuck on "Connected".
        onError(data.error || "Monitoring could not start");
      }
    } catch {
      onError("Failed to parse WebSocket message");
    }
  };

  ws.onerror = () => onError("WebSocket connection error");
  ws.onclose = () => onStatus("Disconnected");

  return ws;
}
