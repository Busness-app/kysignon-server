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
    defaultUrl: 'https://bookmarks.example.com/api/sync/events',
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
  suite_webhook: {
    defaultName: 'Custom signed webhook',
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
  const [bearerToken, setBearerToken] = useState('');
  const [editing, setEditing] = useState<PairedSystem | null>(null);
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
    setBearerToken('');
    setFormError(null);
  };

  // Connection changes require operation-bound step-up; resync retains its existing gate.
  const { requestGrant, stepUpPrompt } = useStepUp();

  const handleCreateSCIMTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);

    try {
      if (editing) {
        const path = `/api/admin/systems/${editing.id}/connection`;
        const grant = await requestGrant(`Update the connection for '${editing.name}'?`, `PUT ${path}`);
        await apiRequest(path, { method: 'PUT', stepUpToken: grant, body: JSON.stringify({ systemType, bearerToken }) });
        handleCloseModal();
        return;
      }
      const grant = await requestGrant(
        `Connecting '${targetName.trim() || 'this system'}' sends directory accounts to this service.`, 'POST /api/admin/systems');
      const data = await apiJson('/api/admin/systems', parseCreatedSystem, {
        method: 'POST',
        stepUpToken: grant,
        body: JSON.stringify({
          name: targetName.trim(),
          systemType,
          bearerToken: systemType === 'scim' ? bearerToken : undefined,
          description: description.trim() || undefined,
          iconUrl: iconUrl.trim() || undefined,
          callbackUrl: callbackUrl.trim(),
        }),
      });

      setBearerToken('');
      if (data.bearerToken) setCreatedToken(data.bearerToken);
      else handleCloseModal();
      fetchSystems();
    } catch (err) {
      if (isCancelled(err)) return;
      setFormError(errorMessage(err, 'Failed to connect SCIM service'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenModal = () => {
    setEditing(null);
    setShowPairModal(true);
    handleTypeChange('kypost');
    setCreatedToken(null);
    setFormError(null);
  };

  const handleCloseModal = () => {
    setShowPairModal(false);
    setEditing(null);
    setBearerToken('');
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
      const grant = await requestGrant(`Disconnecting '${s.name}' stops all account replication to it.`, `DELETE /api/admin/systems/${s.id}`);
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

  const isCustomOrGeneric = systemType === 'scim' || systemType === 'suite_webhook';
  const needsReview = (s: PairedSystem) => !['scim', 'suite_webhook', 'kypost', 'kypasswords', 'kybookmarks', 'kynotes'].includes(s.systemType);
  const openConnection = (s: PairedSystem) => {
    setEditing(s); setSystemType(s.systemType === 'scim' ? 'scim' : '');
    setTargetName(s.name); setCallbackUrl(s.callbackUrl); setDescription(s.description ?? ''); setIconUrl(s.iconUrl ?? '');
    setBearerToken(''); setCreatedToken(null); setFormError(null); setShowPairModal(true);
  };
  const testConnection = async (s: PairedSystem) => {
    try {
      await apiRequest(`/api/admin/systems/${s.id}/test`, { method: 'POST' });
      alert('SCIM Users lookup succeeded. This does not verify write permissions or provisioning.');
    } catch (err) { alert(errorMessage(err, 'Connection test failed')); }
  };

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
              <th>Destination URL</th>
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
                            e.currentTarget.style.display = 'none';
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
                    {needsReview(s) && <span className="status-badge warn">Protocol review required — delivery paused</span>}
                    {!needsReview(s) && s.status === 'active' && (
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
                      {(needsReview(s) || s.systemType === 'scim') && <button className="secondary-btn sm" onClick={() => openConnection(s)}>{needsReview(s) ? 'Review connection' : 'Replace token'}</button>}
                      {s.systemType === 'scim' && <button className="secondary-btn sm" onClick={() => testConnection(s)}>Test connection</button>}
                      <button
                        className="secondary-btn sm"
                        disabled={needsReview(s)}
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
              <h3>{editing ? 'Configure connection' : 'Connect service'}</h3>
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
                  <label className="form-label">Generated webhook signing secret</label>
                  <div className="pin-box">
                    <span className="pairing-token-text font-mono">{createdToken}</span>
                    <button className="secondary-btn sm mt-2" onClick={copyCreatedToken}>
                      {copied ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copied ? 'Copied Token' : 'Copy signing secret'}</span>
                    </button>
                  </div>
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.35rem', display: 'block' }}>
                    Configure this secret in the downstream suite webhook verifier. KySignOn signs requests and never sends the secret in Authorization.
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
                    onChange={(e) => editing ? setSystemType(e.target.value) : handleTypeChange(e.target.value)}
                    disabled={editing?.systemType === 'scim'}
                    autoFocus
                  >
                    {editing && <option value="">Select the protocol used by this service</option>}
                    {!editing && <>
                    <option value="kypost">KyPost (IMAP Mail & Security)</option>
                    <option value="kypasswords">KyPasswords (Password Vault)</option>
                    <option value="kybookmarks">KyBookmarks (Encrypted Bookmarks)</option>
                    <option value="kynotes">KyNotes (Encrypted Notes)</option>
                    </>}
                    <option value="scim">Generic SCIM 2.0 (Nextcloud, OwnCloud, etc.)</option>
                    <option value="suite_webhook">Custom signed suite webhook</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Target Name</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. KyPost Mail Server"
                    disabled={editing !== null}
                    value={targetName}
                    onChange={(e) => setTargetName(e.target.value)}
                    required
                    autoFocus
                  />
                </div>

                {isCustomOrGeneric && !editing && (
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
                  <label className="form-label">{systemType === 'scim' ? 'SCIM Base URL' : 'Signed webhook URL'}</label>
                  <input
                    type="url"
                    className="form-input font-mono"
                    placeholder="https://mail.example.com/scim/v2"
                    disabled={editing !== null}
                    value={callbackUrl}
                    onChange={(e) => setCallbackUrl(e.target.value)}
                    required
                  />
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                    {systemType === 'scim' ? 'Uses the target’s user IDs for updates and deactivation. Requires externalId filtering, PUT, and PATCH support.' : 'Sends signed SCIM user bodies to this exact webhook URL.'}
                  </span>
                </div>

                {systemType === 'scim' && <div className="form-group">
                  <label className="form-label" htmlFor="scim-bearer">Bearer token issued by the target service</label>
                  <input id="scim-bearer" className="form-input" type="password" autoComplete="new-password" value={bearerToken} onChange={(e) => setBearerToken(e.target.value)} required maxLength={8192} />
                  <span className="muted">Stored encrypted. The saved token is never displayed.</span>
                </div>}
                <div className="alert-box info sm" style={{ marginBottom: '1.25rem' }}>
                  <Key size={14} />
                  <span>{systemType === 'scim' ? 'Use an HTTPS SCIM base URL and the service’s provisioning token.' : editing ? 'The existing webhook signing secret will be retained.' : 'KySignOn generates a signing secret shown once after connection.'}</span>
                </div>

                <div className="modal-footer">
                  <button type="button" className="secondary-btn" onClick={handleCloseModal}>
                    Cancel
                  </button>
                  <button type="submit" className="primary-btn" disabled={submitting || !systemType}>
                    {submitting ? <RefreshCw className="spin" size={14} /> : <span>{editing ? 'Save connection' : 'Connect service'}</span>}
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
