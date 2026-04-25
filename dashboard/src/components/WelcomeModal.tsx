import { useState, useEffect } from "react";
import { Shield, Zap, Play, Check } from "lucide-react";
import { api } from "../api";

export default function WelcomeModal() {
  const [isOpen, setIsOpen] = useState(false);
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const hasSeenWelcome = localStorage.getItem("usb_defender_welcomed");
    if (!hasSeenWelcome) {
      setIsOpen(true);
    }
  }, []);

  const close = () => {
    localStorage.setItem("usb_defender_welcomed", "true");
    setIsOpen(false);
  };

  const enableAutoScan = async () => {
    setLoading(true);
    try {
      await api.autoscanEnable();
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
    setStep(3);
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: 500, padding: 0, overflow: 'hidden' }}>
        
        {/* Header Graphic */}
        <div style={{ background: 'var(--bg-card)', padding: '32px 24px', textAlign: 'center', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ 
            width: 64, height: 64, borderRadius: 16, background: 'var(--severity-critical)', 
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16,
            boxShadow: '0 0 24px rgba(239, 68, 68, 0.4)'
          }}>
            <Shield size={32} color="#fff" />
          </div>
          <h2 style={{ margin: 0, fontSize: 24, fontWeight: 600 }}>Welcome to USB Defender</h2>
          <p style={{ margin: '8px 0 0 0', color: 'var(--text-secondary)' }}>
            Your cross-platform ecosystem for USB threat mitigation.
          </p>
        </div>

        {/* Steps Content */}
        <div style={{ padding: 24 }}>
          {step === 1 && (
            <div className="anim-fade-in">
              <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
                <div style={{ color: 'var(--accent-primary)', marginTop: 2 }}>
                  <Zap size={24} />
                </div>
                <div>
                  <h4 style={{ margin: '0 0 4px 0' }}>Zero-Click Auto-Scan</h4>
                  <p style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    When installed on this PC, USB Defender can automatically detect USB insertions and scan them silently in the background.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
                <div style={{ color: 'var(--accent-primary)', marginTop: 2 }}>
                  <Play size={24} />
                </div>
                <div>
                  <h4 style={{ margin: '0 0 4px 0' }}>The Portable Scanner</h4>
                  <p style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    You can install the standalone scanner directly onto any USB drive via the "Scanner" tab to protect it on untrusted machines.
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 32 }}>
                <button className="btn btn-ghost" onClick={close}>Skip Setup</button>
                <button className="btn btn-primary" onClick={() => setStep(2)}>Next</button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="anim-fade-in">
              <div style={{ textAlign: 'center', padding: '16px 0 32px 0' }}>
                <h3 style={{ margin: '0 0 16px 0' }}>Enable Auto-Scan?</h3>
                <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Would you like to enable the background service now? It will listen for new USB drives and scan them automatically.
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, marginTop: 16 }}>
                <button className="btn btn-ghost" onClick={() => setStep(3)} style={{ flex: 1 }}>Not Now</button>
                <button className="btn btn-primary" onClick={enableAutoScan} disabled={loading} style={{ flex: 1 }}>
                  {loading ? 'Enabling...' : 'Enable Auto-Scan'}
                </button>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="anim-fade-in">
              <div style={{ textAlign: 'center', padding: '16px 0 32px 0' }}>
                <div style={{ 
                  width: 48, height: 48, borderRadius: 24, background: 'var(--severity-clean)', 
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16 
                }}>
                  <Check size={24} color="#10b981" />
                </div>
                <h3 style={{ margin: '0 0 16px 0' }}>You're all set!</h3>
                <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  To arm a USB drive with the portable scanner, plug it in and visit the <strong>Scanner</strong> tab.
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', marginTop: 16 }}>
                <button className="btn btn-primary" onClick={close} style={{ minWidth: 200 }}>
                  Go to Dashboard
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
