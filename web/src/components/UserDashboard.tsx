import React, { useEffect, useState } from 'react';
import { User, Application } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseApplications } from '../parsers';
import { faviconUrl } from '../favicon';
import { Globe, Mail, Lock, Bookmark, FileText, ExternalLink, ShieldCheck, Smartphone, ArrowUpRight, Plus, Pencil } from 'lucide-react';

interface UserDashboardProps {
  user: User;
  onNavigateToDevices: () => void;
}

/** The card being edited, or a blank one when adding. */
interface CardDraft {
  id: string;
  source?: Application['source'];
  name: string;
  url: string;
  description: string;
  iconName: string;
}

const blankDraft: CardDraft = { id: '', name: '', url: '', description: '', iconName: 'favicon' };

/** Mirrors the server's launcherIcons allowlist; anything else is rejected at the API. */
const ICON_OPTIONS: Array<[string, string]> = [
  ['favicon', 'Site favicon (automatic)'],
  ['globe', 'Globe'],
  ['mail', 'Mail'],
  ['lock', 'Lock'],
  ['bookmark', 'Bookmark'],
  ['file-text', 'Document'],
];

export const UserDashboard: React.FC<UserDashboardProps> = ({ user, onNavigateToDevices }) => {
  const [apps, setApps] = useState<Application[]>([]);
  const [failedFavicons, setFailedFavicons] = useState<string[]>([]);
  const [draft, setDraft] = useState<CardDraft | null>(null);

  const fetchApps = () =>
    apiJson('/api/user/applications', parseApplications)
      .then(setApps)
      .catch(() => setApps([]));

  useEffect(() => {
    fetchApps();
  }, []);

  const editCard = (app: Application) =>
    setDraft({
      id: app.id,
      source: app.source,
      name: app.name,
      url: app.url,
      description: app.description ?? '',
      iconName: app.iconName || 'favicon',
    });

  // A client-derived card is presentation over a registered OAuth client, so only its blurb
  // and icon are editable here; its name and URL belong to the client registration.
  const isClientCard = draft?.source === 'client';

  const saveCard = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft) return;
    try {
      if (isClientCard) {
        await apiRequest(`/api/admin/clients/${encodeURIComponent(draft.id)}/launcher`, {
          method: 'PUT',
          body: JSON.stringify({ description: draft.description.trim(), iconName: draft.iconName }),
        });
      } else {
        const body = JSON.stringify({
          name: draft.name.trim(),
          url: draft.url.trim(),
          description: draft.description.trim(),
          iconName: draft.iconName,
        });
        await (draft.id
          ? apiRequest(`/api/admin/applications/${encodeURIComponent(draft.id)}`, { method: 'PUT', body })
          : apiRequest('/api/admin/applications', { method: 'POST', body }));
      }
      setDraft(null);
      setFailedFavicons([]);
      fetchApps();
    } catch (err) {
      alert(errorMessage(err, 'Failed to save application'));
    }
  };

  const iconMap: Record<string, React.FC<{ size?: number; style?: React.CSSProperties; className?: string }>> = {
    globe: Globe,
    mail: Mail,
    lock: Lock,
    bookmark: Bookmark,
    'file-text': FileText,
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h1 className="page-title">Application Launcher</h1>
          <p className="page-subtitle">Access your single sign-on enabled KySecurity Suite and 3rd-party products</p>
        </div>
        {user.role === 'admin' && (
          <button className="primary-btn sm" onClick={() => setDraft({ ...blankDraft })}>
            <Plus size={14} /> Add Application
          </button>
        )}
        <div className="security-status-card" onClick={onNavigateToDevices}>
          <div className="status-indicator-dot" />
          <div className="status-info">
            <span className="status-label">Identity Protection</span>
            <span className="status-val">
              {user.mfaMethods && user.mfaMethods.length > 0 ? 'MFA Active' : 'Configure MFA'}
            </span>
          </div>
          <Smartphone size={16} className="icon-cyan" />
        </div>
      </div>

      {apps.length === 0 && (
        <p className="app-empty">
          No applications yet.
          {user.role === 'admin' ? ' Register an OAuth client or add an external link to fill this page.' : ' An administrator has not published any.'}
        </p>
      )}

      <div className="app-grid">
        {apps.map((app) => {
          const IconComp = iconMap[app.iconName || ''] || ExternalLink;
          const favicon = app.iconName === 'favicon' ? faviconUrl(app.url) : undefined;
          return (
            <div className="app-card-wrap" key={app.id}>
              <a href={app.url} target="_blank" rel="noopener noreferrer" className="app-card">
                <div className="app-card-top">
                  <div className="app-icon-wrapper">
                    {favicon && !failedFavicons.includes(app.id) ? (
                      <img
                        className="app-favicon"
                        src={favicon}
                        alt=""
                        referrerPolicy="no-referrer"
                        onError={() => setFailedFavicons((ids) => [...ids, app.id])}
                      />
                    ) : (
                      <IconComp size={24} className="icon-cyan" />
                    )}
                  </div>
                  <ArrowUpRight size={18} className="app-launch-arrow" />
                </div>
                <div className="app-card-body">
                  <h3 className="app-name">{app.name}</h3>
                  {app.description && <p className="app-desc">{app.description}</p>}
                </div>
              </a>
              {user.role === 'admin' && (
                <button
                  className="app-edit-btn"
                  onClick={() => editCard(app)}
                  aria-label={`Edit ${app.name}`}
                  title="Edit this card"
                >
                  <Pencil size={14} />
                </button>
              )}
            </div>
          );
        })}
      </div>

      {draft && (
        <div className="modal-backdrop" onMouseDown={() => setDraft(null)}>
          <div className="modal-card" onMouseDown={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h3>{draft.id ? `Edit ${draft.name}` : 'Add external application'}</h3>
              <button className="close-btn" onClick={() => setDraft(null)} aria-label="Close">
                ×
              </button>
            </div>
            <form className="modal-body" onSubmit={saveCard}>
              {!isClientCard && (
                <>
                  <div className="form-group">
                    <label className="form-label" htmlFor="app-name">Application name</label>
                    <input
                      id="app-name"
                      className="form-input"
                      value={draft.name}
                      onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                      required
                      autoFocus
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label" htmlFor="app-url">Application URL</label>
                    <input
                      id="app-url"
                      className="form-input font-mono"
                      type="url"
                      value={draft.url}
                      onChange={(event) => setDraft({ ...draft, url: event.target.value })}
                      placeholder="https://portainer.example.com"
                      required
                    />
                  </div>
                </>
              )}
              {isClientCard && (
                <p className="form-hint">
                  Name and sign-in URL come from this app&apos;s OAuth client registration. Change them
                  under Admin → OAuth Clients.
                </p>
              )}
              <div className="form-group">
                <label className="form-label" htmlFor="app-description">Description (optional)</label>
                <input
                  id="app-description"
                  className="form-input"
                  value={draft.description}
                  onChange={(event) => setDraft({ ...draft, description: event.target.value })}
                  maxLength={200}
                  placeholder="What this app is for"
                  autoFocus={isClientCard}
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="app-icon">Icon</label>
                <select
                  id="app-icon"
                  className="form-select"
                  value={draft.iconName}
                  onChange={(event) => setDraft({ ...draft, iconName: event.target.value })}
                >
                  {ICON_OPTIONS.map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>
              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setDraft(null)}>Cancel</button>
                <button type="submit" className="primary-btn">{draft.id ? 'Save Changes' : 'Add Application'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="profile-overview-box">
        <div className="box-header">
          <ShieldCheck size={20} className="icon-cyan" />
          <h2>Single Sign-On Identity Overview</h2>
        </div>
        <div className="profile-details-grid">
          <div className="detail-item">
            <span className="detail-label">Subject Account</span>
            <span className="detail-value">{user.username}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Display Name</span>
            <span className="detail-value">{user.displayName || user.username}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Primary Email</span>
            <span className="detail-value">{user.email}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Organization Role</span>
            <span className="detail-value role-text">{user.role.toUpperCase()}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
