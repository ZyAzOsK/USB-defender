import { useEffect, useState } from "react";
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import {
  Activity, ShieldAlert, Archive, Zap,
  AlertTriangle, FileWarning,
} from "lucide-react";
import { api, DashboardStats } from "../api";
import { basename, severityClass } from "../utils";

const SEVERITY_COLORS = ["#ef4444", "#f59e0b", "#3b82f6"];
const PIE_COLORS = ["#ef4444", "#f59e0b", "#3b82f6", "#10b981", "#8b5cf6"];

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 6000);
    return () => clearInterval(interval);
  }, []);

  async function loadStats() {
    try {
      const data = await api.stats();
      setStats(data);
      setError("");
    } catch (e: any) {
      setError("Cannot connect to API — is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="empty-state">
        <div className="spinner" />
        <h3>Loading dashboard...</h3>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="empty-state">
        <AlertTriangle />
        <h3>Backend Offline</h3>
        <p>{error || "Unable to connect to USB Defender API."}</p>
      </div>
    );
  }

  const sevData = [
    { name: "Critical", value: stats.severity_distribution.critical },
    { name: "Medium", value: stats.severity_distribution.medium },
    { name: "Low", value: stats.severity_distribution.low },
  ];

  const catData = stats.top_categories.map((c) => ({
    name: c.category.length > 16 ? c.category.slice(0, 14) + "…" : c.category,
    count: c.count,
  }));

  return (
    <>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Real-time overview of USB security posture</p>
      </div>

      <div className="page-body">
        {/* Stat cards */}
        <div className="stat-grid">
          <div className="stat-card blue">
            <div className="stat-icon blue"><Activity size={22} /></div>
            <div className="stat-info">
              <h3>{stats.total_events}</h3>
              <span>Total Events</span>
            </div>
          </div>
          <div className="stat-card rose">
            <div className="stat-icon rose"><ShieldAlert size={22} /></div>
            <div className="stat-info">
              <h3>{stats.threats_detected}</h3>
              <span>Threats Detected</span>
            </div>
          </div>
          <div className="stat-card emerald">
            <div className="stat-icon emerald"><Archive size={22} /></div>
            <div className="stat-info">
              <h3>{stats.quarantined_files}</h3>
              <span>Quarantined</span>
            </div>
          </div>
          <div className="stat-card amber">
            <div className="stat-icon amber"><Zap size={22} /></div>
            <div className="stat-info">
              <h3>{stats.severity_distribution.critical}</h3>
              <span>Critical Threats</span>
            </div>
          </div>
        </div>

        {/* Charts row */}
        <div className="charts-grid">
          {/* Severity pie chart */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Severity Distribution</span>
            </div>
            {sevData.every((d) => d.value === 0) ? (
              <div className="empty-state" style={{ padding: "32px" }}>
                <FileWarning />
                <p>No threats detected yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={sevData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                    stroke="none"
                  >
                    {sevData.map((_, i) => (
                      <Cell key={i} fill={SEVERITY_COLORS[i]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#111827",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 8,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
            <div className="flex items-center justify-between" style={{ padding: "0 8px" }}>
              {sevData.map((d, i) => (
                <div key={d.name} className="flex items-center gap-8">
                  <div
                    style={{
                      width: 10,
                      height: 10,
                      borderRadius: 3,
                      background: SEVERITY_COLORS[i],
                    }}
                  />
                  <span className="text-sm text-muted">
                    {d.name}: {d.value}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Top categories bar chart */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Top Threat Categories</span>
            </div>
            {catData.length === 0 ? (
              <div className="empty-state" style={{ padding: "32px" }}>
                <FileWarning />
                <p>No categorized threats yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={catData} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={110}
                    tick={{ fill: "#94a3b8", fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#111827",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 8,
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {catData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Recent activity table */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent Activity</span>
            <span className="card-subtitle">Last 10 events</span>
          </div>
          {stats.recent_activity.length === 0 ? (
            <div className="empty-state" style={{ padding: "24px" }}>
              <p>No activity recorded yet. Plug in a USB drive and scan it.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>File</th>
                  <th>Tag</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_activity.map((a, i) => (
                  <tr key={i}>
                    <td className="text-mono text-sm">{a.timestamp}</td>
                    <td>{a.event_type}</td>
                    <td style={{ maxWidth: 200 }} title={a.file_path}>
                      {basename(a.file_path)}
                    </td>
                    <td>{a.tag}</td>
                    <td>
                      <span className={`badge ${severityClass(a.severity)}`}>
                        {a.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
