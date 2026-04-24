import { useEffect, useState } from "react";
import {
  Archive, RotateCcw, Trash2, ShieldAlert,
  RefreshCw, AlertTriangle,
} from "lucide-react";
import { api, QuarantineItem } from "../api";

export default function Quarantine() {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionId, setActionId] = useState<number | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const data = await api.quarantine();
      setItems(data.items);
      setError("");
    } catch (e: any) {
      setError(e.message || "Failed to load quarantine");
    } finally {
      setLoading(false);
    }
  }

  async function restore(id: number) {
    if (!confirm("Restore this file to its original location? This will decrypt and replace it.")) return;
    setActionId(id);
    try {
      await api.quarantineRestore(id);
      await load();
    } catch (e: any) {
      alert("Restore failed: " + e.message);
    } finally {
      setActionId(null);
    }
  }

  async function remove(id: number) {
    if (!confirm("Permanently delete this quarantined file? This cannot be undone.")) return;
    setActionId(id);
    try {
      await api.quarantineDelete(id);
      await load();
    } catch (e: any) {
      alert("Delete failed: " + e.message);
    } finally {
      setActionId(null);
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>Quarantine Vault</h2>
        <p>Encrypted isolation of detected threats</p>
      </div>

      <div className="page-body">
        {/* Actions bar */}
        <div className="flex items-center justify-between mb-16">
          <div className="flex items-center gap-8">
            <Archive size={18} style={{ color: "var(--accent-amber)" }} />
            <span className="text-sm text-muted">
              {items.length} file{items.length !== 1 ? "s" : ""} in quarantine
            </span>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={load}>
            <RefreshCw size={14} /> Refresh
          </button>
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
            <h3>Loading quarantine...</h3>
          </div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <Archive />
            <h3>Quarantine Empty</h3>
            <p>No files have been quarantined. High-severity threats are automatically encrypted and stored here.</p>
          </div>
        ) : (
          <div className="card">
            <div style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Original File</th>
                    <th>Tag</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th style={{ textAlign: "right" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id}>
                      <td className="text-mono">#{item.id}</td>
                      <td className="text-mono text-sm">{item.timestamp}</td>
                      <td title={item.original_path} style={{ maxWidth: 220 }}>
                        <div className="flex items-center gap-8">
                          <ShieldAlert size={14} style={{ color: "var(--severity-critical)", flexShrink: 0 }} />
                          {item.original_path.split("/").pop()}
                        </div>
                      </td>
                      <td>{item.tag}</td>
                      <td>
                        <span className={`badge ${
                          item.severity >= 8 ? "critical" :
                          item.severity >= 5 ? "medium" : "low"
                        }`}>
                          {item.severity}
                        </span>
                      </td>
                      <td>{item.category}</td>
                      <td style={{ textAlign: "right" }}>
                        <div className="flex items-center gap-8" style={{ justifyContent: "flex-end" }}>
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => restore(item.id)}
                            disabled={actionId === item.id}
                            title="Decrypt and restore to original location"
                          >
                            <RotateCcw size={14} /> Restore
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => remove(item.id)}
                            disabled={actionId === item.id}
                            title="Permanently delete"
                          >
                            <Trash2 size={14} /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
