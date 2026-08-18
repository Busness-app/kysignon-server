import React, { useEffect, useState } from 'react';
import { PairedSystem } from '../types';
import { apiRequest } from '../api';
import {
  RefreshCw,
  Plus,
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

  // Modal State
  const [showPairModal, setShowPairModal] = useState(false);

  // Direct SCIM Form State
  const [targetName, setTargetName] = useState('');
  const [systemType, setSystemType] = useState('kypost');
  const [callbackUrl, setCallbackUrl] = useState('');
  const [bearerToken, setBearerToken] = useState('');
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);

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

  const applyPreset = (type: string, name: string, url: string) => {
    setSystemType(type);
    setTargetName(name);
    setCallbackUrl(url);
    setFormError(null);
  };

  const handleCreateSCIMTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);

    try {
      const data = await apiRequest('/api/admin/systems', {
        method: 'POST',
        body: JSON.stringify({
          name: targetName.trim(),
          systemType,
          callbackUrl: callbackUrl.trim(),
          bearerToken: bearerToken.trim() || undefined,
        }),
      });

      setCreatedToken(data.bearerToken || null);
      fetchSystems();
    } catch (err: any) {
      setFormError(err.message || 'Failed to connect SCIM service');
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenModal = () => {
    setShowPairModal(true);
    setTargetName('KyPost Mail Server');
    setSystemType('kypost');
    setCallbackUrl('https://mail.example.com/scim/v2');
    setBearerToken('');
    setCreatedToken(null);
    setFormError(null);
  };

  const handleCloseModal = () => {
    setShowPairModal(false);
    setCreatedToken(null);
    fetchSystems();
  };

  const handleTriggerResync = async (s: PairedSystem) => {
    try {
      await apiRequest(`/api/admin/systems/${s.id}/resync`, { method: 'POST' });
      alert(`Full account directory resync queued for '${s.name}' via SCIM 2.0`);
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

  const copyCreatedToken = () => {
    if (createdToken) {
      navigator.clipboard.writeText(createdToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="admin-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">SCIM 2.0 Downstream Directory Sync</h1>
          <p className="page-subtitle">
            Connect KySecurity Suite products and 3rd-party services via standard SCIM 2.0 (RFC 7643/7644) for automated account replication.
          </p>
        </div>
        <button className="primary-btn sm" onClick={handleOpenModal}>
          <Plus size={14} />
          <span>Connect SCIM Target</span>
        </button>
      </div>

      <div className="table-card">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Target Service</th>
              <th>Type</th>
              <th>SCIM Base URL</th>
              <th>Sync Status</th>
              <th>Last Synced</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {systems.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-5 text-muted">
                  No downstream SCIM products connected yet. Click <strong>"Connect SCIM Target"</strong> to connect a service.
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
                        title="Re-replicate all accounts via SCIM"
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

      {/* Connect SCIM Target Modal */}
      {showPairModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Connect SCIM 2.0 Service</h3>
              <button className="close-btn" onClick={handleCloseModal}>
                ×
              </button>
            </div>

            {createdToken ? (
              <div className="modal-body text-center">
                <div className="alert-box success">
                  <CheckCircle size={16} />
                  <span>SCIM Target connected successfully!</span>
                </div>
                <div className="form-group mt-3 text-left">
                  <label className="form-label">Bearer API Token</label>
                  <div className="pin-box">
                    <span className="pairing-token-text font-mono">{createdToken}</span>
                    <button className="secondary-btn sm mt-2" onClick={copyCreatedToken}>
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copied ? 'Copied Token' : 'Copy Bearer Token'}</span>
                    </button>
                  </div>
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.35rem', display: 'block' }}>
                    Save this token in your target product's SCIM configuration to authenticate incoming requests from KySignOn.
                  </span>
                </div>
                <div className="modal-footer mt-4">
                  <button className="primary-btn" onClick={handleCloseModal}>
                    Done
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleCreateSCIMTarget} className="modal-body">
                {formError && <div className="alert-box error sm">{formError}</div>}

                <div className="form-group">
                  <label className="form-label">Quick App Preset</label>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kypost', 'KyPost Mail Server', 'https://mail.example.com/scim/v2')}
                    >
                      + KyPost
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kypasswords', 'KyPasswords Vault', 'https://passwords.example.com/scim/v2')}
                    >
                      + KyPasswords
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kybookmarks', 'KyBookmarks', 'https://bookmarks.example.com/scim/v2')}
                    >
                      + KyBookmarks
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kynotes', 'KyNotes', 'https://notes.example.com/scim/v2')}
                    >
                      + KyNotes
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('scim', 'Nextcloud SCIM', 'https://cloud.example.com/apps/user_scim/v2')}
                    >
                      + Generic SCIM
                    </button>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Target Name</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. KyPost Mail Server"
                    value={targetName}
                    onChange={(e) => setTargetName(e.target.value)}
                    required
                    autoFocus
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Product / Service Type</label>
                  <select
                    className="form-select"
                    value={systemType}
                    onChange={(e) => setSystemType(e.target.value)}
                  >
                    <option value="kypost">KyPost (IMAP Mail & Security)</option>
                    <option value="kypasswords">KyPasswords (Password Vault)</option>
                    <option value="kybookmarks">KyBookmarks (Encrypted Bookmarks)</option>
                    <option value="kynotes">KyNotes (Encrypted Notes)</option>
                    <option value="scim">Generic SCIM 2.0 Service Provider</option>
                    <option value="custom">Custom Microservice</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">SCIM Base URL (Destination)</label>
                  <input
                    type="url"
                    className="form-input font-mono"
                    placeholder="https://mail.example.com/scim/v2"
                    value={callbackUrl}
                    onChange={(e) => setCallbackUrl(e.target.value)}
                    required
                  />
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                    KySignOn will send standard RESTful requests: <code>POST /Users</code>, <code>PUT /Users/{'{id}'}</code>, <code>DELETE /Users/{'{id}'}</code>.
                  </span>
                </div>

                <div className="form-group">
                  <label className="form-label">Bearer API Token (Optional)</label>
                  <input
                    type="password"
                    className="form-input font-mono"
                    placeholder="Leave blank to auto-generate a secure token"
                    value={bearerToken}
                    onChange={(e) => setBearerToken(e.target.value)}
                  />
                </div>

                <div className="modal-footer">
                  <button type="button" className="secondary-btn" onClick={handleCloseModal}>
                    Cancel
                  </button>
                  <button type="submit" className="primary-btn" disabled={submitting}>
                    {submitting ? <RefreshCw className="spin" size={14} /> : <span>Connect SCIM Target</span>}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
