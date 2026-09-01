import React, { useEffect, useState } from 'react';
import { User, Application } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseApplications } from '../parsers';
import { faviconUrl } from '../favicon';
import { Globe, Mail, Lock, Bookmark, FileText, ExternalLink, ShieldCheck, Smartphone, ArrowUpRight, Plus } from 'lucide-react';

interface UserDashboardProps {
  user: User;
  onNavigateToDevices: () => void;
}

export const UserDashboard: React.FC<UserDashboardProps> = ({ user, onNavigateToDevices }) => {
  const [apps, setApps] = useState<Application[]>([]);
  const [failedFavicons, setFailedFavicons] = useState<string[]>([]);
  const [showAddApp, setShowAddApp] = useState(false);
  const [appName, setAppName] = useState('');
  const [appUrl, setAppUrl] = useState('');
  const [appDescription, setAppDescription] = useState('');
  const [appIcon, setAppIcon] = useState('favicon');

  const fetchApps = () =>
    apiJson('/api/user/applications', parseApplications)
      .then(setApps)
      .catch(() => setApps([]));

  useEffect(() => {
    fetchApps();
  }, []);

  const addApplication = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      await apiRequest('/api/admin/applications', {
        method: 'POST',
        body: JSON.stringify({
          name: appName.trim(),
          url: appUrl.trim(),
          description: appDescription.trim(),
          iconName: appIcon,
        }),
      });
      setShowAddApp(false);
      setAppName('');
      setAppUrl('');
      setAppDescription('');
      setAppIcon('favicon');
      fetchApps();
    } catch (err) {
      alert(errorMessage(err, 'Failed to add application'));
    }
  };

  const getDomainUrl = (subdomain: string, localPort: number, fallback: string) => {
    const host = window.location.hostname;
    const protocol = window.location.protocol;
    if (host === 'localhost' || host === '127.0.0.1') {
      return `http://localhost:${localPort}`;
    }
    if (host.startsWith('auth.')) {
      const base = host.replace(/^auth\./, '');
      return `${protocol}//${subdomain}.${base}`;
    }
    return fallback;
  };

  const iconMap: Record<string, React.FC<{ size?: number; style?: React.CSSProperties; className?: string }>> = {
    globe: Globe,
    mail: Mail,
    lock: Lock,
    bookmark: Bookmark,
    'file-text': FileText,
  };

  const defaultKyApps: Application[] = [
    {
      id: 'kydns',
      name: 'KyDNS',
      description: 'Homelab DNS server with subnet views & blackhole filtering',
      iconName: 'globe',
      url: getDomainUrl('dns', 8053, 'https://dns.example.com'),
      enabled: true,
    },
    {
      id: 'kypost',
      name: 'KyPost',
      description: 'Encrypted IMAP webmail & identity communication',
      iconName: 'mail',
      url: getDomainUrl('mail', 5866, 'https://mail.example.com'),
      enabled: true,
    },
    {
      id: 'kypasswords',
      name: 'KyPasswords',
      description: 'Zero-knowledge encrypted password vault',
      iconName: 'lock',
      url: getDomainUrl('passwords', 5877, 'https://passwords.example.com'),
      enabled: true,
    },
    {
      id: 'kybookmarks',
      name: 'KyBookmarks',
      description: 'Privacy-focused secure bookmark organizer',
      iconName: 'bookmark',
      url: getDomainUrl('bookmarks', 5869, 'https://bookmarks.example.com'),
      enabled: true,
    },
    {
      id: 'kynotes',
      name: 'KyNotes',
      description: 'End-to-end encrypted notes & documentation',
      iconName: 'file-text',
      url: getDomainUrl('notes', 5870, 'https://notes.example.com'),
      enabled: true,
    },
  ];

  const displayApps = apps.length > 0 ? apps : defaultKyApps;

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h1 className="page-title">Application Launcher</h1>
          <p className="page-subtitle">Access your single sign-on enabled KySecurity Suite and 3rd-party products</p>
        </div>
        {user.role === 'admin' && (
          <button className="primary-btn sm" onClick={() => setShowAddApp(true)}>
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

      <div className="app-grid">
        {displayApps.map((app) => {
          const IconComp = iconMap[app.iconName || ''] || ExternalLink;
          const favicon = app.iconName === 'favicon' ? faviconUrl(app.url) : undefined;
          return (
            <a
              key={app.id}
              href={app.url}
              target="_blank"
              rel="noopener noreferrer"
              className="app-card"
            >
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
                <p className="app-desc">{app.description || 'Single Sign-On Application'}</p>
              </div>
              <div className="app-card-footer">
                <span className="sso-badge">OIDC SSO Ready</span>
              </div>
            </a>
          );
        })}
      </div>

      {showAddApp && (
        <div className="modal-backdrop" onMouseDown={() => setShowAddApp(false)}>
          <div className="modal-card" onMouseDown={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h3>Add external application</h3>
              <button className="close-btn" onClick={() => setShowAddApp(false)} aria-label="Close">
                ×
              </button>
            </div>
            <form className="modal-body" onSubmit={addApplication}>
              <div className="form-group">
                <label className="form-label">Application name</label>
                <input className="form-input" value={appName} onChange={(event) => setAppName(event.target.value)} required autoFocus />
              </div>
              <div className="form-group">
                <label className="form-label">Application URL</label>
                <input className="form-input font-mono" type="url" value={appUrl} onChange={(event) => setAppUrl(event.target.value)} placeholder="https://portainer.example.com" required />
              </div>
              <div className="form-group">
                <label className="form-label">Description (optional)</label>
                <input className="form-input" value={appDescription} onChange={(event) => setAppDescription(event.target.value)} />
              </div>
              <div className="form-group">
                <label className="form-label">Icon</label>
                <select className="form-select" value={appIcon} onChange={(event) => setAppIcon(event.target.value)}>
                  <option value="favicon">Site favicon (automatic)</option>
                  <option value="globe">Globe</option>
                  <option value="mail">Mail</option>
                  <option value="lock">Lock</option>
                  <option value="bookmark">Bookmark</option>
                  <option value="file-text">Document</option>
                </select>
              </div>
              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowAddApp(false)}>Cancel</button>
                <button type="submit" className="primary-btn">Add Application</button>
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
