import React, { useEffect, useState } from 'react';
import { OAuthClient } from '../types';
import { apiRequest } from '../api';
import { Plus, Trash2, CheckCircle } from 'lucide-react';

export const AdminClients: React.FC = () => {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [showModal, setShowModal] = useState(false);

  const [clientId, setClientId] = useState('');
  const [clientName, setClientName] = useState('');
  const [clientType, setClientType] = useState<'public' | 'confidential'>('public');
  const [redirectUris, setRedirectUris] = useState('');
  const [launchUrl, setLaunchUrl] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [createdClientId, setCreatedClientId] = useState<string | null>(null);

  const fetchClients = async () => {
    try {
      const data = await apiRequest('/api/admin/clients');
      setClients(data.clients || []);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchClients();
  }, []);

  const applyPreset = (presetId: string, presetName: string, defaultPath: string, autoLoginPath?: string, localPort?: number) => {
    setClientId(presetId);
    setClientName(presetName);
    setClientType('public');
    const port = localPort || 8053;
    const domainPrefix = presetId === 'kypasswords' ? 'passwords' : presetId === 'kypost' ? 'mail' : presetId === 'kydns' ? 'dns' : presetId === 'kybookmarks' ? 'bookmarks' : presetId === 'kynotes' ? 'notes' : presetId;
    const uris = [
      `https://${domainPrefix}.urlxl.com${defaultPath}`,
      `https://${presetId}.urlxl.com${defaultPath}`,
      `http://localhost:${port}${defaultPath}`,
      `http://127.0.0.1:${port}${defaultPath}`,
    ];
    if (defaultPath !== '/api/auth/oidc/callback') {
      uris.push(`https://${domainPrefix}.urlxl.com/api/auth/oidc/callback`);
      uris.push(`http://localhost:${port}/api/auth/oidc/callback`);
      uris.push(`http://127.0.0.1:${port}/api/auth/oidc/callback`);
    }
    setRedirectUris(uris.join('\n'));
    if (autoLoginPath) {
      setLaunchUrl(`https://${domainPrefix}.urlxl.com${autoLoginPath}`);
    } else {
      setLaunchUrl('');
    }
  };

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientName || !redirectUris) return;

    const uris = redirectUris
      .split('\n')
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    try {
      const data = await apiRequest('/api/admin/clients', {
        method: 'POST',
        body: JSON.stringify({
          clientId: clientId.trim() || undefined,
          clientName,
          clientType,
          redirectUris: uris,
          launchUrl: launchUrl.trim() || undefined,
          allowedScopes: ['openid', 'profile', 'email'],
        }),
      });

      setCreatedClientId(data.client.id);
      setCreatedSecret(data.clientSecret || null);
      fetchClients();
    } catch (err: any) {
      alert(err.message || 'Failed to create client');
    }
  };

  const handleDeleteClient = async (id: string) => {
    if (!confirm('Are you sure you want to delete this OAuth/OIDC client?')) return;
    try {
      await apiRequest(`/api/admin/clients/${id}`, { method: 'DELETE' });
      fetchClients();
    } catch (err: any) {
      alert(err.message || 'Failed to delete client');
    }
  };

  const resetForm = () => {
    setClientId('');
    setClientName('');
    setClientType('public');
    setRedirectUris('');
    setLaunchUrl('');
    setCreatedSecret(null);
    setCreatedClientId(null);
    setShowModal(false);
  };

  return (
    <div className="admin-page">
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
                      onClick={() => applyPreset('kydns', 'KyDNS Server', '/auth/sso/callback', '/auth/sso/login', 8053)}
                    >
                      + KyDNS
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kypost', 'KyPost Mail Server', '/api/auth/oidc/callback', '/api/auth/oidc/login', 5866)}
                    >
                      + KyPost
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kypasswords', 'KyPasswords Vault', '/api/auth/oidc/callback', '/api/auth/oidc/login', 5877)}
                    >
                      + KyPasswords
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kybookmarks', 'KyBookmarks', '/api/auth/oidc/callback', '/api/auth/oidc/login', 5869)}
                    >
                      + KyBookmarks
                    </button>
                    <button
                      type="button"
                      className="secondary-btn sm"
                      onClick={() => applyPreset('kynotes', 'KyNotes', '/api/auth/oidc/callback', '/api/auth/oidc/login', 5870)}
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
                    value={clientType}
                    onChange={(e: any) => setClientType(e.target.value)}
                  >
                    <option value="public">Public (SPA, Mobile, PKCE)</option>
                    <option value="confidential">Confidential (Server-Side with Secret)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Allowed Redirect URIs (one per line)</label>
                  <textarea
                    className="form-textarea font-mono"
                    rows={3}
                    placeholder="https://dns.urlxl.com/auth/sso/callback"
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
