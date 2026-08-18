import React, { useEffect, useState, useRef } from 'react';
import { PairedSystem } from '../types';
import { apiRequest } from '../api';
import QRCode from 'qrcode';
import {
  RefreshCw,
  Plus,
  Clock,
  Trash2,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Copy,
  Check,
  Send,
} from 'lucide-react';

export const AdminSystems: React.FC = () => {
  const [systems, setSystems] = useState<PairedSystem[]>([]);

  // System Pairing Modal State
  const [showPairModal, setShowPairModal] = useState(false);
  const [systemType, setSystemType] = useState('kypost');
  const [pairToken, setPairToken] = useState('');
  const [pairPin, setPairPin] = useState('');
  const [pairExpiresAt, setPairExpiresAt] = useState<number | null>(null);
  const [countdown, setCountdown] = useState(90);
  const [pairLoading, setPairLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const qrCanvasRef = useRef<HTMLCanvasElement | null>(null);

  const fetchSystems = async () => {
    try {
      const data = await apiRequest('/api/admin/systems');
      setSystems(data.systems || []);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchSystems();
  }, []);

  // 90s Countdown Timer
  useEffect(() => {
    if (!showPairModal || !pairExpiresAt) return;

    const interval = setInterval(() => {
      const remaining = Math.max(0, Math.floor((pairExpiresAt - Date.now()) / 1000));
      setCountdown(remaining);
      if (remaining <= 0) {
        clearInterval(interval);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [showPairModal, pairExpiresAt]);

  const handleGeneratePairingKey = async () => {
    setPairLoading(true);
    try {
      const data = await apiRequest('/api/admin/systems/pairing-token', {
        method: 'POST',
        body: JSON.stringify({ systemType }),
      });
      setPairToken(data.pairingToken);
      setPairPin(data.pinCode);
      const exp = new Date(data.expiresAt).getTime();
      setPairExpiresAt(exp);
      setCountdown(Math.floor((exp - Date.now()) / 1000));

      if (qrCanvasRef.current && data.qrPayload) {
        QRCode.toCanvas(qrCanvasRef.current, data.qrPayload, {
          width: 200,
          margin: 1,
          color: { dark: '#0d0f14', light: '#4deeea' },
        });
      }
    } catch (err: any) {
      alert(err.message || 'Failed to generate system pairing token');
    } finally {
      setPairLoading(false);
    }
  };

  const handleOpenModal = () => {
    setShowPairModal(true);
    setPairToken('');
    setPairPin('');
    setPairExpiresAt(null);
  };

  const handleTriggerResync = async (s: PairedSystem) => {
    try {
      await apiRequest(`/api/admin/systems/${s.id}/resync`, { method: 'POST' });
      alert(`Full account directory resync queued for '${s.name}'`);
      fetchSystems();
    } catch (err: any) {
      alert(err.message || 'Failed to trigger resync');
    }
  };

  const handleDeleteSystem = async (s: PairedSystem) => {
    if (!confirm(`Disconnect and remove '${s.name}' from KySignOn Suite sync?`)) return;

    try {
      await apiRequest(`/api/admin/systems/${s.id}`, { method: 'DELETE' });
      fetchSystems();
    } catch (err: any) {
      alert(err.message || 'Failed to disconnect system');
    }
  };

  const copyPairingToken = () => {
    navigator.clipboard.writeText(pairToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="admin-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">KySecurity Suite System Pairing & Sync</h1>
          <p className="page-subtitle">
            Connect KyPost, KyPasswords, KyBookmarks, and KyNotes servers using UI pairing keys for automated account replication.
          </p>
        </div>
        <button className="primary-btn sm" onClick={handleOpenModal}>
          <Plus size={14} />
          <span>Pair New Product</span>
        </button>
      </div>

      <div className="table-card">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Connected Product</th>
              <th>Type</th>
              <th>Callback URL</th>
              <th>Sync Status</th>
              <th>Last Synced</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {systems.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-5 text-muted">
                  No downstream KySecurity products paired yet. Click <strong>"Pair New Product"</strong> to connect a server.
                </td>
              </tr>
            ) : (
              systems.map((s) => (
                <tr key={s.id}>
                  <td className="font-bold text-white">{s.name}</td>
                  <td>
                    <span className="font-mono badge-type">{s.systemType.toUpperCase()}</span>
                  </td>
                  <td className="font-mono text-muted text-sm">{s.callbackUrl}</td>
                  <td>
                    {s.status === 'active' && (
                      <span className="status-badge active">
                        <CheckCircle size={12} /> Active
                      </span>
                    )}
                    {s.status === 'failing' && (
                      <span className="status-badge warn">
                        <AlertTriangle size={12} /> Failing
                      </span>
                    )}
                    {s.status === 'disabled' && (
                      <span className="status-badge disabled">
                        <XCircle size={12} /> Disabled
                      </span>
                    )}
                  </td>
                  <td className="text-muted text-sm font-mono">
                    {s.lastSyncedAt ? new Date(s.lastSyncedAt).toLocaleString() : 'Pending'}
                  </td>
                  <td className="text-right">
                    <div className="action-buttons-wrap">
                      <button
                        className="secondary-btn sm"
                        onClick={() => handleTriggerResync(s)}
                        title="Re-replicate all accounts now"
                      >
                        <Send size={13} />
                        <span>Resync Directory</span>
                      </button>
                      <button
                        className="icon-btn danger"
                        onClick={() => handleDeleteSystem(s)}
                        title="Disconnect System"
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* System Pairing Key Generation Modal */}
      {showPairModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Pair KySecurity Product</h3>
              <button className="close-btn" onClick={() => setShowPairModal(false)}>
                ×
              </button>
            </div>
            <div className="modal-body">
              {!pairToken ? (
                <div>
                  <p className="modal-desc">
                    Select the KySecurity product you want to pair with this KySignOn server:
                  </p>

                  <div className="form-group">
                    <label className="form-label">Product Type</label>
                    <select
                      className="form-select"
                      value={systemType}
                      onChange={(e) => setSystemType(e.target.value)}
                    >
                      <option value="kypost">KyPost (IMAP Mail & Security)</option>
                      <option value="kypasswords">KyPasswords (Password Vault)</option>
                      <option value="kybookmarks">KyBookmarks (Encrypted Bookmarks)</option>
                      <option value="kynotes">KyNotes (Encrypted Notes)</option>
                      <option value="scim">Generic SCIM 2.0 Service Provider (RESTful /Users)</option>
                      <option value="custom">Custom KySecurity Microservice</option>
                    </select>
                  </div>

                  <div className="modal-footer">
                    <button type="button" className="secondary-btn" onClick={() => setShowPairModal(false)}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="primary-btn"
                      onClick={handleGeneratePairingKey}
                      disabled={pairLoading}
                    >
                      {pairLoading ? <RefreshCw className="spin" size={14} /> : <span>Generate 90s Pairing Key</span>}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center">
                  <p className="modal-desc">
                    Paste this pairing token or scan the QR code in your target product's settings UI:
                  </p>

                  <div className="qr-container">
                    <canvas ref={qrCanvasRef} />
                  </div>

                  <div className="pin-box">
                    <span className="pin-label">ONE-TIME PAIRING PIN</span>
                    <span className="pin-digits">{pairPin}</span>
                    <div className="pairing-token-text font-mono mt-2">{pairToken}</div>
                    <button className="secondary-btn sm mt-2" onClick={copyPairingToken}>
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copied ? 'Copied Token' : 'Copy Pairing Token'}</span>
                    </button>
                  </div>

                  <div className="timer-bar-wrap mt-3">
                    <div className="timer-info">
                      <Clock size={14} className="icon-cyan" />
                      <span>Expires in {countdown}s</span>
                    </div>
                    <div className="timer-progress-bg">
                      <div
                        className="timer-progress-fill"
                        style={{ width: `${(countdown / 90) * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="modal-footer mt-4">
                    <button
                      className="primary-btn"
                      onClick={() => {
                        setShowPairModal(false);
                        fetchSystems();
                      }}
                    >
                      Done
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
