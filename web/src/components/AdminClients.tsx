import React, { useEffect, useState } from 'react';

// Mirrors the server's registration policy. The server is the authority; this only keeps
// the form from offering a choice the API will reject.
const SUITE_CLIENT_IDS = ['kypost', 'kydns', 'kypasswords', 'kynotes', 'kybookmarks'];

const isSuiteClient = (id: string) => SUITE_CLIENT_IDS.includes(id.trim().toLowerCase());
import { OAuthClient } from '../types';
import { apiJson, apiRequest, errorMessage, isRecord } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { parseOAuthClients } from '../parsers';
import { Plus, Trash2, CheckCircle, AlertTriangle } from 'lucide-react';

export const AdminClients: React.FC = () => {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [showModal, setShowModal] = useState(false);

  const [clientId, setClientId] = useState('');
  const [clientName, setClientName] = useState('');
  const [clientType, setClientType] = useState<'public' | 'confidential'>('confidential');
  const [redirectUris, setRedirectUris] = useState('');
  const [launchUrl, setLaunchUrl] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [createdClientId, setCreatedClientId] = useState<string | null>(null);

  const fetchClients = async () => {
    try {
      setClients(await apiJson('/api/admin/clients', parseOAuthClients));
    } catch {
      // A failed refresh leaves the previous list on screen.
    }
  };

  useEffect(() => {
    fetchClients();
  }, []);

  const applyPreset = (presetId: string, presetName: string, defaultPath: string, autoLoginPath?: string) => {
    setClientId(presetId);
    setClientName(presetName);
    setClientType('confidential');
    const domainPrefix = presetId === 'kypasswords' ? 'passwords' : presetId === 'kypost' ? 'mail' : presetId === 'kydns' ? 'dns' : presetId === 'kybookmarks' ? 'bookmarks' : presetId === 'kynotes' ? 'notes' : presetId;
    // HTTPS only, and no loopback. A registered redirect URI is a destination the server
    // will hand an authorization code to, so pre-filling http://localhost:PORT means any
    // process that can bind that port on the user's machine collects codes for this
    // client. Add a loopback URI by hand for local development if you genuinely need one.
    const uris = [
      `https://${domainPrefix}.example.com${defaultPath}`,
      `https://${presetId}.example.com${defaultPath}`,
    ];
    if (defaultPath !== '/api/auth/oidc/callback') {
      uris.push(`https://${domainPrefix}.example.com/api/auth/oidc/callback`);
    }
    setRedirectUris(uris.join('\n'));
    if (autoLoginPath) {
      setLaunchUrl(`https://${domainPrefix}.example.com${autoLoginPath}`);
    } else {
      setLaunchUrl('');
    }
  };

  // Typing a suite service ID pins the client type, matching the server's rule.
  const suiteLocked = isSuiteClient(clientId);

  // Registering a client mints a secret and deleting one revokes every integration using it.
  // Neither should be reachable from a session cookie alone.
  const { requestGrant, stepUpPrompt } = useStepUp();

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientName || !redirectUris) return;

    const uris = redirectUris
      .split('\n')
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    try {
      const grant = await requestGrant(
        `Registering '${clientName}' issues a client secret that can request tokens for your users.`
      );
      const data = await apiRequest('/api/admin/clients', {
        method: 'POST',
        stepUpToken: grant,
        body: JSON.stringify({
          clientId: clientId.trim() || undefined,
          clientName,
          clientType: suiteLocked ? 'confidential' : clientType,
          redirectUris: uris,
          launchUrl: launchUrl.trim() || undefined,
          allowedScopes: ['openid', 'profile', 'email'],
        }),
      });

      const client = isRecord(data) && isRecord(data.client) ? data.client : {};
      setCreatedClientId(typeof client.id === 'string' ? client.id : clientId.trim());
      setCreatedSecret(
        isRecord(data) && typeof data.clientSecret === 'string' && data.clientSecret
          ? data.clientSecret
          : null
      );
      fetchClients();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to create client'));
    }
  };

  const handleDeleteClient = async (id: string) => {
    if (!confirm('Are you sure you want to delete this OAuth/OIDC client?')) return;
    try {
      const grant = await requestGrant(
        `Deleting '${id}' immediately breaks every sign-in that goes through it.`
      );
      await apiRequest(`/api/admin/clients/${id}`, { method: 'DELETE', stepUpToken: grant });
      fetchClients();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to delete client'));
    }
  };

  const resetForm = () => {
    setClientId('');
    setClientName('');
    setClientType('confidential');
    setRedirectUris('');
    setLaunchUrl('');
    setCreatedSecret(null);
    setCreatedClientId(null);
    setShowModal(false);
  };

  return (
    <div className="admin-page">
      {stepUpPrompt}
      <div className="page-header">
        <div>
          <h1 className="page-title">OAuth 2.0 & OpenID Connect Clients</h1>
          <p className="page-subtitle">
            Manage authorized application registrations for Single Sign-On and PKCE authorization-code flows.
          </p>
        </div>
        <button className="primary-btn sm" onClick={() => setShowModal(true)}>
          <Plus size={14} />
          <span>Register Client</span>
        </button>
      </div>

      <div className="table-card">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Client Name</th>
              <th>Client ID</th>
              <th>Type</th>
              <th>Redirect URIs</th>
              <th>Status</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {clients.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-5 text-muted">
                  No OAuth clients registered yet.
                </td>
              </tr>
            ) : (
              clients.map((c) => {
                let uris: string[] = [];
                try {
                  uris = JSON.parse(c.redirectUrisJson);
                } catch {}
                return (
                  <tr key={c.id}>
                    <td className="font-bold text-white">{c.clientName}</td>
                    <td className="font-mono text-cyan text-sm">{c.id}</td>
                    <td>
                      <span className="font-mono badge-type">{c.clientType.toUpperCase()}</span>
                    </td>
                    <td className="font-mono text-sm text-muted">
                      {uris.map((u, i) => (
                        <div key={i}>{u}</div>
                      ))}
                    </td>
                    <td>
                      <span className="status-badge active">
                        <CheckCircle size={12} /> Enabled
                      </span>
                    </td>
                    <td className="text-right">
                      <button
                        className="icon-btn danger"
                        onClick={() => handleDeleteClient(c.id)}
                        title="Delete Client"
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Register OAuth / OIDC Client</h3>
              <button className="close-btn" onClick={resetForm}>
                ×
              </button>
            </div>
            {!createdClientId ? (
              <form onSubmit={handleCreateClient} className="modal-body">
                <div className="form-group">
                  <label className="form-label">Quick App Preset</label>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kydns', 'KyDNS Server', '/auth/sso/callback', '/auth/sso/login')}
                    >
                      + KyDNS
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kypost', 'KyPost Mail Server', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                    >
                      + KyPost
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kypasswords', 'KyPasswords Vault', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                    >
                      + KyPasswords
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kybookmarks', 'KyBookmarks', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                    >
                      + KyBookmarks
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kynotes', 'KyNotes', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                    >
                      + KyNotes
                    </button>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Client ID (optional identifier)</label>
                  <input
                    type="text"
                    className="form-input font-mono"
                    placeholder="e.g. kydns (auto-generated if empty)"
                    value={clientId}
                    onChange={(e) => setClientId(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Client Name</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. KyDNS Server"
                    value={clientName}
                    onChange={(e) => setClientName(e.target.value)}
                    autoFocus
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Client Type</label>
                  <select
                    className="form-select"
                    value={suiteLocked ? 'confidential' : clientType}
                    disabled={suiteLocked}
                    onChange={(e) => setClientType(e.target.value === 'confidential' ? 'confidential' : 'public')}
                  >
                    <option value="confidential">Confidential — server-side, gets a client secret (recommended)</option>
                    <option value="public">Public — no client secret, PKCE only</option>
                  </select>

                  {suiteLocked && (
                    <div className="alert-box sm" style={{ alignItems: 'flex-start' }}>
                      <CheckCircle size={16} />
                      <span>
                        <strong>{clientId.trim()}</strong> is a KySecurity suite service. It runs
                        server-side and can hold a secret, so it is always confidential.
                      </span>
                    </div>
                  )}

                  {!suiteLocked && clientType === 'public' && (
                    <div className="alert-box warn" role="alert" style={{ alignItems: 'flex-start' }}>
                      <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '0.15rem' }} />
                      <span>
                        <strong>No client secret will be issued.</strong> Anyone who obtains an
                        authorization code for this client can redeem it if they also have the PKCE
                        verifier. Choose this only for a single-page app or a native app, which
                        cannot keep a secret. Any server-side service should be confidential.
                      </span>
                    </div>
                  )}
                </div>

                <div className="form-group">
                  <label className="form-label">Allowed Redirect URIs (one per line)</label>
                  <textarea
                    className="form-textarea font-mono"
                    rows={3}
                    placeholder="https://dns.example.com/auth/sso/callback"
                    value={redirectUris}
                    onChange={(e) => setRedirectUris(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Auto-Login / Launch URL (optional deep link for launcher)</label>
                  <input
                    type="url"
                    className="form-input font-mono"
                    placeholder="e.g. https://dns.urlxl.com/auth/sso/login or https://grafana.example.com/login/generic_oauth"
                    value={launchUrl}
                    onChange={(e) => setLaunchUrl(e.target.value)}
                  />
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                    If provided, clicking the app tile in the KySignOn launcher will open this exact auto-login URL.
                  </span>
                </div>

                <div className="modal-footer">
                  <button type="button" className="secondary-btn" onClick={resetForm}>
                    Cancel
                  </button>
                  <button type="submit" className="primary-btn">
                    Register Client
                  </button>
                </div>
              </form>
            ) : (
              <div className="modal-body text-center">
                <div className="alert-box success">
                  <CheckCircle size={16} />
                  <span>Client registered successfully!</span>
                </div>

                <div className="form-group mt-3 text-left">
                  <label className="form-label">Client ID</label>
                  <input type="text" className="form-input font-mono" value={createdClientId} readOnly />
                </div>

                {createdSecret && (
                  <div className="form-group text-left">
                    <label className="form-label">Client Secret (Shown once)</label>
                    <input type="text" className="form-input font-mono" value={createdSecret} readOnly />
                  </div>
                )}

                <div className="modal-footer mt-4">
                  <button className="primary-btn" onClick={resetForm}>
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
