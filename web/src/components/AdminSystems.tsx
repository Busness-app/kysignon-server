import React, { useEffect, useState } from 'react';
import { PairedSystem } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { parseCreatedSystem, parsePairedSystems } from '../parsers';
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
  Key,
  Globe,
} from 'lucide-react';

const PRESET_METADATA: Record<
  string,
  { defaultName: string; defaultUrl: string; defaultDesc?: string; defaultIcon?: string }
> = {
  kypost: {
    defaultName: 'KyPost Mail Server',
    defaultUrl: 'https://mail.example.com/scim/v2',
  },
  kypasswords: {
    defaultName: 'KyPasswords Vault',
    defaultUrl: 'https://passwords.example.com/scim/v2',
  },
  kybookmarks: {
    defaultName: 'KyBookmarks',
    defaultUrl: 'https://bookmarks.example.com/scim/v2',
  },
  kynotes: {
    defaultName: 'KyNotes',
    defaultUrl: 'https://notes.example.com/scim/v2',
  },
  scim: {
    defaultName: 'Nextcloud',
    defaultUrl: 'https://cloud.example.com/apps/user_scim/v2',
    defaultDesc: 'Self-hosted cloud storage & collaboration',
    defaultIcon: 'https://nextcloud.com/media/nextcloud-logo-white.svg',
  },
  custom: {
    defaultName: 'Custom SCIM Service',
    defaultUrl: 'https://api.example.com/scim/v2',
    defaultDesc: '',
    defaultIcon: '',
  },
};

export const AdminSystems: React.FC = () => {
  const [systems, setSystems] = useState<PairedSystem[]>([]);

  // Modal State
  const [showPairModal, setShowPairModal] = useState(false);

  // Direct SCIM Form State
  const [targetName, setTargetName] = useState('');
  const [systemType, setSystemType] = useState('kypost');
  const [description, setDescription] = useState('');
  const [iconUrl, setIconUrl] = useState('');
  const [callbackUrl, setCallbackUrl] = useState('');
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);

  const fetchSystems = async () => {
    try {
      setSystems(await apiJson('/api/admin/systems', parsePairedSystems));
    } catch {
      // A failed refresh leaves the previous list on screen.
    }
  };

  useEffect(() => {
    fetchSystems();
  }, []);

  const handleTypeChange = (newType: string) => {
    setSystemType(newType);
    const meta = PRESET_METADATA[newType];
    if (meta) {
      setTargetName(meta.defaultName);
      setCallbackUrl(meta.defaultUrl);
      setDescription(meta.defaultDesc || '');
      setIconUrl(meta.defaultIcon || '');
    }
    setFormError(null);
  };

  // Connecting a system mints a bearer token for the account directory; disconnecting one
  // cuts off replication. Resync is left alone: it is idempotent and carries no secret.
  const { requestGrant, stepUpPrompt } = useStepUp();

  const handleCreateSCIMTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);

    try {
      const grant = await requestGrant(
        `Connecting '${targetName.trim() || 'this system'}' issues a bearer token with access to the account directory.`
      );
      const data = await apiJson('/api/admin/systems', parseCreatedSystem, {
        method: 'POST',
        stepUpToken: grant,
        body: JSON.stringify({
          name: targetName.trim(),
          systemType,
          description: description.trim() || undefined,
          iconUrl: iconUrl.trim() || undefined,
          callbackUrl: callbackUrl.trim(),
        }),
      });

      setCreatedToken(data.bearerToken || null);
      fetchSystems();
    } catch (err) {
      if (isCancelled(err)) return;
      setFormError(errorMessage(err, 'Failed to connect SCIM service'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenModal = () => {
    setShowPairModal(true);
    handleTypeChange('kypost');
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
    } catch (err) {
      alert(errorMessage(err, 'Failed to trigger resync'));
    }
  };

  const handleDeleteSystem = async (s: PairedSystem) => {
    if (!confirm(`Disconnect and remove '${s.name}' from KySignOn Suite sync?`)) return;

    try {
      const grant = await requestGrant(`Disconnecting '${s.name}' stops all account replication to it.`);
      await apiRequest(`/api/admin/systems/${s.id}`, { method: 'DELETE', stepUpToken: grant });
      fetchSystems();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to disconnect system'));
    }
  };

  const copyCreatedToken = () => {
    if (createdToken) {
      navigator.clipboard.writeText(createdToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const isCustomOrGeneric = systemType === 'scim' || systemType === 'custom';

  return (
    <div className="admin-page">
      {stepUpPrompt}
      <div className="page-header">
        <div>
          <h1 className="page-title">Suite sync</h1>
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
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                      {s.iconUrl ? (
                        <img
                          src={s.iconUrl}
                          alt=""
                          style={{
                            width: 24,
                            height: 24,
                            borderRadius: '4px',
                            objectFit: 'contain',
                            background: 'var(--panel-hover)',
                            padding: '2px',
                            border: '1px solid var(--line)',
                          }}
                          onError={(e) => {
                            (e.target as HTMLElement).style.display = 'none';
                          }}
                        />
                      ) : (
                        <div
                          style={{
                            width: 24,
                            height: 24,
                            borderRadius: '4px',
                            background: 'rgba(77, 238, 234, 0.1)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'var(--cyan)',
                          }}
                        >
                          <Globe size={13} />
                        </div>
                      )}
                      <div>
                        <div className="font-bold text-white">{s.name}</div>
                        {s.description && (
                          <div className="text-muted text-xs" style={{ marginTop: '0.15rem' }}>
                            {s.description}
                          </div>
                        )}
                      </div>
                    </div>
                  </td>
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
                  <label className="form-label">Auto-Generated Bearer API Token</label>
                  <div className="pin-box">
                    <span className="pairing-token-text font-mono">{createdToken}</span>
                    <button className="secondary-btn sm mt-2" onClick={copyCreatedToken}>
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copied ? 'Copied Token' : 'Copy Bearer Token'}</span>
                    </button>
                  </div>
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.35rem', display: 'block' }}>
                    Configure this Bearer token in your downstream SCIM target service to authenticate incoming account replication requests from KySignOn.
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
                  <label className="form-label">Product / Service Type</label>
                  <select
                    className="form-select"
                    value={systemType}
                    onChange={(e) => handleTypeChange(e.target.value)}
                    autoFocus
                  >
                    <option value="kypost">KyPost (IMAP Mail & Security)</option>
                    <option value="kypasswords">KyPasswords (Password Vault)</option>
                    <option value="kybookmarks">KyBookmarks (Encrypted Bookmarks)</option>
                    <option value="kynotes">KyNotes (Encrypted Notes)</option>
                    <option value="scim">Generic SCIM 2.0 (Nextcloud, OwnCloud, etc.)</option>
                    <option value="custom">Custom Microservice</option>
                  </select>
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

                {isCustomOrGeneric && (
                  <>
                    <div className="form-group">
                      <label className="form-label">Description (Optional)</label>
                      <input
                        type="text"
                        className="form-input"
                        placeholder="e.g. Self-hosted storage & productivity suite"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                      />
                    </div>

                    <div className="form-group">
                      <label className="form-label">Custom Icon / Image URL (Optional)</label>
                      <input
                        type="url"
                        className="form-input font-mono"
                        placeholder="https://example.com/logo.svg"
                        value={iconUrl}
                        onChange={(e) => setIconUrl(e.target.value)}
                      />
                    </div>
                  </>
                )}

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

                <div className="alert-box info sm" style={{ marginBottom: '1.25rem' }}>
                  <Key size={14} />
                  <span>KySignOn will auto-generate a cryptographically secure 256-bit Bearer API Token.</span>
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
