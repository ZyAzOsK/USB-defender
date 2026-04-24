import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import {
  LayoutDashboard, Radio, Search, Archive,
  FileText, Shield,
} from "lucide-react";
import "./App.css";

import Dashboard from "./pages/Dashboard";
import Monitor from "./pages/Monitor";
import Scanner from "./pages/Scanner";
import Quarantine from "./pages/Quarantine";
import Logs from "./pages/Logs";
import { api } from "./api";

export default function App() {
  const [backendOnline, setBackendOnline] = useState(false);
  const [usbPath, setUsbPath] = useState<string | null>(null);

  useEffect(() => {
    checkBackend();
    const interval = setInterval(checkBackend, 4000);
    return () => clearInterval(interval);
  }, []);

  async function checkBackend() {
    try {
      const status = await api.status();
      setBackendOnline(true);
      setUsbPath(status.usb_path);
    } catch {
      setBackendOnline(false);
      setUsbPath(null);
    }
  }

  return (
    <BrowserRouter>
      <div className="app-layout">
        {/* ── Sidebar ── */}
        <aside className="sidebar">
          <div className="sidebar-header">
            <div className="sidebar-logo">
              <Shield size={20} />
            </div>
            <div className="sidebar-brand">
              <h1>USB Defender</h1>
              <span>v1.0.0</span>
            </div>
          </div>

          <nav className="sidebar-nav">
            <div className="nav-section-title">Overview</div>
            <NavLink
              to="/"
              end
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <LayoutDashboard size={18} />
              Dashboard
            </NavLink>

            <div className="nav-section-title">Operations</div>
            <NavLink
              to="/monitor"
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Radio size={18} />
              Live Monitor
            </NavLink>
            <NavLink
              to="/scanner"
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Search size={18} />
              Scanner
            </NavLink>

            <div className="nav-section-title">Security</div>
            <NavLink
              to="/quarantine"
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Archive size={18} />
              Quarantine
            </NavLink>
            <NavLink
              to="/logs"
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <FileText size={18} />
              Activity Logs
            </NavLink>
          </nav>

          {/* Status footer */}
          <div className="sidebar-status">
            <div className="status-row">
              <div className={`status-dot ${backendOnline ? "online" : "offline"}`} />
              <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
                {backendOnline ? "Engine Online" : "Engine Offline"}
              </span>
            </div>
            {usbPath && (
              <div
                className="text-sm text-muted text-mono"
                style={{ marginTop: 6, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                title={usbPath}
              >
                USB: {usbPath.split("/").pop()}
              </div>
            )}
          </div>
        </aside>

        {/* ── Main content ── */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/monitor" element={<Monitor />} />
            <Route path="/scanner" element={<Scanner />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/logs" element={<Logs />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
