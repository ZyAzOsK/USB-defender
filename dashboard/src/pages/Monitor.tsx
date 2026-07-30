import { useEffect, useRef, useState } from "react";
import {
  Radio, ShieldCheck, ShieldAlert, Wifi, WifiOff,
} from "lucide-react";
import { api, connectMonitorWS } from "../api";
import { normalizePath, severityClass } from "../utils";

interface MonitorEvent {
  id: number;
  timestamp: string;
  event_type: string;
  file_path: string;
  tag: string;
  severity: number;
  category: string;
  action: string;
  description: string;
}

export default function Monitor() {
  const [connected, setConnected] = useState(false);
  const [statusMsg, setStatusMsg] = useState("Idle — not monitoring");
  const [events, setEvents] = useState<MonitorEvent[]>([]);
  const [usbPath, setUsbPath] = useState("");
  const [autoDetected, setAutoDetected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  // Auto-detect USB on mount
  useEffect(() => {
    api.status().then((s) => {
      if (s.usb_path) {
        setUsbPath(normalizePath(s.usb_path));
        setAutoDetected(true);
      }
    }).catch(() => {});
  }, []);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [events]);

  // Close the socket if the user navigates away mid-session, otherwise the
  // server keeps a watchdog observer alive for a client that is gone.
  useEffect(() => {
    return () => {
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  function startMonitor() {
    const normalized = normalizePath(usbPath);
    if (!normalized.trim()) return;

    const ws = connectMonitorWS(
      normalized,
      (data: MonitorEvent) => {
        setEvents((prev) => [data, ...prev].slice(0, 200));
      },
      (msg) => {
        setStatusMsg(msg);
        if (msg.startsWith("Connected") || msg.includes("started")) {
          setConnected(true);
        }
        if (msg === "Disconnected") {
          setConnected(false);
        }
      },
      (err) => {
        setStatusMsg("Error: " + err);
        setConnected(false);
        // A rejected path (unsafe or missing) leaves a socket the server has
        // already finished with; drop it so Start works again.
        wsRef.current?.close();
        wsRef.current = null;
      }
    );

    wsRef.current = ws;
  }

  function stopMonitor() {
    wsRef.current?.close();
    wsRef.current = null;
    setConnected(false);
    setStatusMsg("Monitoring stopped");
  }

  return (
    <>
      <div className="page-header">
        <h2>Live Monitor</h2>
        <p>Real-time filesystem surveillance via WebSocket</p>
      </div>

      <div className="page-body">
        {/* Controls */}
        <div className="card mb-16">
          <div className="flex items-center gap-16">
            <div style={{ flex: 1 }}>
              <label className="text-sm text-muted" style={{ display: "block", marginBottom: 6 }}>
                USB Mount Path {autoDetected && "(auto-detected)"}
              </label>
              <input
                className="input"
                placeholder="/run/media/user/USB_DRIVE"
                value={usbPath}
                onChange={(e) => setUsbPath(e.target.value)}
                disabled={connected}
              />
            </div>
            {!connected ? (
              <button
                className="btn btn-primary"
                onClick={startMonitor}
                disabled={!usbPath.trim()}
                style={{ marginTop: 20 }}
              >
                <Radio size={16} /> Start Monitoring
              </button>
            ) : (
              <button
                className="btn btn-danger"
                onClick={stopMonitor}
                style={{ marginTop: 20 }}
              >
                <WifiOff size={16} /> Stop
              </button>
            )}
          </div>

          {/* Status indicator */}
          <div className="flex items-center gap-8" style={{ marginTop: 12 }}>
            <div className={`status-dot ${connected ? "online" : "offline"}`} />
            <span className="text-sm text-muted">{statusMsg}</span>
          </div>
        </div>

        {/* Event feed */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Event Feed</span>
            <span className="card-subtitle">{events.length} events captured</span>
          </div>

          {events.length === 0 ? (
            <div className="empty-state">
              {connected ? <Wifi /> : <Radio />}
              <h3>{connected ? "Listening..." : "Not monitoring"}</h3>
              <p>
                {connected
                  ? "Waiting for file activity on the USB drive. Try creating or modifying a file."
                  : "Enter a USB mount path above and click Start Monitoring."}
              </p>
            </div>
          ) : (
            <div className="event-feed" ref={feedRef}>
              {events.map((e, i) => {
                const isThreat = e.severity > 0 && e.tag !== "Clean";
                return (
                  <div
                    key={`${e.id}-${i}`}
                    className={`event-item ${isThreat ? "threat" : "clean"}`}
                  >
                    <div className={`event-icon ${isThreat ? "threat" : "clean"}`}>
                      {isThreat ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}
                    </div>
                    <div className="event-details">
                      <div className="event-tag">
                        {e.tag}
                        <span className={`badge ${severityClass(e.severity)}`} style={{ marginLeft: 8 }}>
                          Sev {e.severity}
                        </span>
                      </div>
                      <div className="event-path" title={e.file_path}>
                        {e.file_path}
                      </div>
                      <div className="event-time">
                        {e.timestamp} · {e.event_type} · {e.category}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
