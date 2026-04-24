import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import {
  LayoutDashboard, Radio, Search, Archive,
  FileText, Shield, Zap, ZapOff,
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
  const [autoscanEnabled, setAutoscanEnabled] = useState(false);
  const [autoscanToggling, setAutoscanToggling] = useState(false);

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
      setAutoscanEnabled(status.autoscan_enabled);
    } catch {
      setBackendOnline(false);
      setUsbPath(null);
      setAutoscanEnabled(false);
    }
  }

  async function toggleAutoscan() {
    setAutoscanToggling(true);
    try {
      if (autoscanEnabled) {
        await api.autoscanDisable();
        setAutoscanEnabled(false);
      } else {
        await api.autoscanEnable();
        setAutoscanEnabled(true);
      }
    } catch (e) {
      console.error("Auto-scan toggle failed:", e);
    } finally {
      setAutoscanToggling(false);
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

          {/* Auto-scan toggle */}
          <div className="sidebar-status" style={{ marginBottom: 0 }}>
            <button
              className={`autoscan-toggle ${autoscanEnabled ? "active" : ""}`}
              onClick={toggleAutoscan}
              disabled={!backendOnline || autoscanToggling}
              title={autoscanEnabled ? "Disable auto-scan on USB insert" : "Enable auto-scan on USB insert"}
            >
              <div className="autoscan-toggle-icon">
                {autoscanEnabled ? <Zap size={14} /> : <ZapOff size={14} />}
              </div>
              <div className="autoscan-toggle-label">
                <span className="autoscan-toggle-text">Auto-Scan</span>
                <span className="autoscan-toggle-status">
                  {autoscanToggling ? "Toggling..." : autoscanEnabled ? "Active" : "Disabled"}
                </span>
              </div>
              <div className={`autoscan-toggle-switch ${autoscanEnabled ? "on" : "off"}`}>
                <div className="autoscan-toggle-knob" />
              </div>
            </button>
          </div>

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
