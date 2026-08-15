import React, { useEffect, useState } from 'react';
import { User, Application } from '../types';
import { apiRequest } from '../api';
import { Mail, Lock, Bookmark, FileText, ExternalLink, ShieldCheck, Smartphone, ArrowUpRight } from 'lucide-react';

interface UserDashboardProps {
  user: User;
  onNavigateToDevices: () => void;
}

export const UserDashboard: React.FC<UserDashboardProps> = ({ user, onNavigateToDevices }) => {
  const [apps, setApps] = useState<Application[]>([]);

  useEffect(() => {
    apiRequest('/api/user/applications')
      .then((data) => {
        setApps(data.applications || []);
      })
      .catch(() => {});
  }, []);

  const defaultKyApps = [
    {
      id: 'kypost',
      name: 'KyPost',
      description: 'Encrypted IMAP webmail & identity communication',
      icon: Mail,
      url: 'https://mail.local.kysecurity',
      color: '#4deeea',
    },
    {
      id: 'kypasswords',
      name: 'KyPasswords',
      description: 'Zero-knowledge encrypted password vault',
      icon: Lock,
      url: 'https://passwords.local.kysecurity',
      color: '#4deeea',
    },
    {
      id: 'kybookmarks',
      name: 'KyBookmarks',
      description: 'Privacy-focused secure bookmark organizer',
      icon: Bookmark,
      url: 'https://bookmarks.local.kysecurity',
      color: '#4deeea',
    },
    {
      id: 'kynotes',
      name: 'KyNotes',
      description: 'End-to-end encrypted notes & documentation',
      icon: FileText,
      url: 'https://notes.local.kysecurity',
      color: '#4deeea',
    },
  ];

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h1 className="page-title">Application Launcher</h1>
          <p className="page-subtitle">Access your single sign-on enabled KySecurity Suite products</p>
        </div>
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
        {defaultKyApps.map((app) => {
          const IconComp = app.icon;
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
                  <IconComp size={24} style={{ color: app.color }} />
                </div>
                <ArrowUpRight size={18} className="app-launch-arrow" />
              </div>
              <div className="app-card-body">
                <h3 className="app-name">{app.name}</h3>
                <p className="app-desc">{app.description}</p>
              </div>
              <div className="app-card-footer">
                <span className="sso-badge">OIDC SSO Ready</span>
              </div>
            </a>
          );
        })}

        {apps.map((app) => (
          <a
            key={app.id}
            href={app.url}
            target="_blank"
            rel="noopener noreferrer"
            className="app-card"
          >
            <div className="app-card-top">
              <div className="app-icon-wrapper">
                <ExternalLink size={24} className="icon-cyan" />
              </div>
              <ArrowUpRight size={18} className="app-launch-arrow" />
            </div>
            <div className="app-card-body">
              <h3 className="app-name">{app.name}</h3>
              <p className="app-desc">{app.description || 'Connected service'}</p>
            </div>
            <div className="app-card-footer">
              <span className="sso-badge">OAuth 2.0</span>
            </div>
          </a>
        ))}
      </div>

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
