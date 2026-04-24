import { useState } from "react";
import { Search, FolderSearch, ShieldAlert, ShieldCheck, Loader } from "lucide-react";
import { api, ScanResult } from "../api";

export default function Scanner() {
  const [path, setPath] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  async function runScan() {
    if (!path.trim()) return;
    setScanning(true);
    setResult(null);
    setError("");

    try {
      const data = await api.scan(path);
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Scan failed");
    } finally {
      setScanning(false);
    }
  }

  const total = result ? result.summary.detected + result.summary.clean : 0;
  const pct = total > 0 ? Math.round((result!.summary.clean / total) * 100) : 0;

  return (
    <>
      <div className="page-header">
        <h2>Scanner</h2>
        <p>On-demand recursive file scanning</p>
      </div>

      <div className="page-body">
        {/* Scan input */}
        <div className="card mb-16">
          <div className="flex items-center gap-16">
            <div style={{ flex: 1 }}>
              <label className="text-sm text-muted" style={{ display: "block", marginBottom: 6 }}>
                Target Path
              </label>
              <input
                className="input"
                placeholder="/run/media/user/USB_DRIVE"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                disabled={scanning}
                onKeyDown={(e) => e.key === "Enter" && runScan()}
              />
            </div>
            <button
              className="btn btn-primary"
              onClick={runScan}
              disabled={scanning || !path.trim()}
              style={{ marginTop: 20 }}
            >
              {scanning ? <Loader size={16} className="spinner" /> : <Search size={16} />}
              {scanning ? "Scanning..." : "Start Scan"}
            </button>
          </div>

          {scanning && (
            <div className="scan-progress-bar">
              <div className="scan-progress-fill" style={{ width: "100%", animation: "pulse-dot 1.5s ease-in-out infinite" }} />
            </div>
          )}
        </div>

        {error && (
          <div className="card mb-16" style={{ borderColor: "var(--severity-critical)", borderLeftWidth: 3 }}>
            <div className="flex items-center gap-12">
              <ShieldAlert size={20} style={{ color: "var(--severity-critical)" }} />
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <>
            {/* Summary cards */}
            <div className="stat-grid">
              <div className="stat-card blue">
                <div className="stat-icon blue"><FolderSearch size={22} /></div>
                <div className="stat-info">
                  <h3>{total}</h3>
                  <span>Total Files Scanned</span>
                </div>
              </div>
              <div className="stat-card rose">
                <div className="stat-icon rose"><ShieldAlert size={22} /></div>
                <div className="stat-info">
                  <h3>{result.summary.detected}</h3>
                  <span>Threats Detected</span>
                </div>
              </div>
              <div className="stat-card emerald">
                <div className="stat-icon emerald"><ShieldCheck size={22} /></div>
                <div className="stat-info">
                  <h3>{pct}%</h3>
                  <span>Clean Rate</span>
                </div>
              </div>
            </div>

            {/* Details table */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Scan Details</span>
                <span className="card-subtitle">{result.scan_path}</span>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>File</th>
                      <th>Tag</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.details.map((d, i) => (
                      <tr key={i}>
                        <td className="text-mono text-sm">{d.timestamp}</td>
                        <td title={d.file_path}>{d.file_path.split("/").pop()}</td>
                        <td>{d.tag}</td>
                        <td>{d.category}</td>
                        <td>
                          <span className={`badge ${
                            d.severity >= 8 ? "critical" :
                            d.severity >= 5 ? "medium" :
                            d.severity > 0 ? "low" : "clean"
                          }`}>
                            {d.severity}
                          </span>
                        </td>
                        <td className="text-sm">{d.action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {!result && !scanning && !error && (
          <div className="empty-state">
            <FolderSearch />
            <h3>Ready to Scan</h3>
            <p>Enter a directory path above and click Start Scan to analyze all files for threats.</p>
          </div>
        )}
      </div>
    </>
  );
}
