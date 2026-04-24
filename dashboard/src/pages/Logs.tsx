import { useEffect, useState } from "react";
import {
  FileText, RefreshCw, Download, Filter, AlertTriangle,
} from "lucide-react";
import { api, LogEntry } from "../api";

export default function Logs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [eventFilter, setEventFilter] = useState("");
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);

  useEffect(() => { load(); }, [eventFilter, limit, offset]);

  async function load() {
    setLoading(true);
    try {
      const data = await api.logs({
        event: eventFilter || undefined,
        limit,
        offset,
      });
      setLogs(data.logs);
      setTotal(data.total);
      setError("");
    } catch (e: any) {
      setError(e.message || "Failed to load logs");
    } finally {
      setLoading(false);
    }
  }

  function exportCSV() {
    const header = "ID,Timestamp,Event,File,Tag,Severity,Category,Action\n";
    const rows = logs.map((l) =>
      `${l.id},"${l.timestamp}","${l.event_type}","${l.file_path}","${l.tag}",${l.severity},"${l.category}","${l.action}"`
    ).join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `usb-defender-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  }

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <>
      <div className="page-header">
        <h2>Activity Logs</h2>
        <p>Complete event history from the detection engine</p>
      </div>

      <div className="page-body">
        {/* Toolbar */}
        <div className="flex items-center justify-between mb-16">
          <div className="flex items-center gap-12">
            <Filter size={16} style={{ color: "var(--text-muted)" }} />
            <select
              className="input"
              style={{ width: 160 }}
              value={eventFilter}
              onChange={(e) => { setEventFilter(e.target.value); setOffset(0); }}
            >
              <option value="">All Events</option>
              <option value="SCAN">Scan</option>
              <option value="CREATED">Created</option>
              <option value="MODIFIED">Modified</option>
              <option value="DELETED">Deleted</option>
              <option value="MOVED">Moved</option>
            </select>
            <span className="text-sm text-muted">{total} total records</span>
          </div>
          <div className="flex items-center gap-8">
            <button className="btn btn-ghost btn-sm" onClick={load}>
              <RefreshCw size={14} /> Refresh
            </button>
            <button className="btn btn-ghost btn-sm" onClick={exportCSV} disabled={logs.length === 0}>
              <Download size={14} /> Export CSV
            </button>
          </div>
        </div>

        {error && (
          <div className="card mb-16" style={{ borderColor: "var(--severity-critical)" }}>
            <div className="flex items-center gap-12">
              <AlertTriangle size={18} style={{ color: "var(--severity-critical)" }} />
              <span>{error}</span>
            </div>
          </div>
        )}

        {loading ? (
          <div className="empty-state">
            <div className="spinner" />
            <h3>Loading logs...</h3>
          </div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            <FileText />
            <h3>No Logs Found</h3>
            <p>Run a scan or start monitoring to generate activity logs.</p>
          </div>
        ) : (
          <div className="card">
            <div style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Event</th>
                    <th>File</th>
                    <th>SHA256</th>
                    <th>Tag</th>
                    <th>Severity</th>
                    <th>Category</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.id}>
                      <td className="text-mono">#{l.id}</td>
                      <td className="text-mono text-sm">{l.timestamp}</td>
                      <td>{l.event_type}</td>
                      <td title={l.file_path} style={{ maxWidth: 180 }}>
                        {l.file_path.split("/").pop()}
                      </td>
                      <td className="text-mono text-sm" title={l.sha256 || ""} style={{ maxWidth: 100 }}>
                        {l.sha256 ? l.sha256.slice(0, 12) + "…" : "—"}
                      </td>
                      <td>{l.tag}</td>
                      <td>
                        <span className={`badge ${
                          l.severity >= 8 ? "critical" :
                          l.severity >= 5 ? "medium" :
                          l.severity > 0 ? "low" : "clean"
                        }`}>
                          {l.severity}
                        </span>
                      </td>
                      <td>{l.category}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between" style={{ padding: "14px 0 0" }}>
                <span className="text-sm text-muted">
                  Page {currentPage} of {totalPages}
                </span>
                <div className="flex items-center gap-8">
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - limit))}
                  >
                    Previous
                  </button>
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={currentPage >= totalPages}
                    onClick={() => setOffset(offset + limit)}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
