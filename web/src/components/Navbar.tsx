import React from 'react';
import { User } from '../types';
import { Shield, LayoutGrid, Smartphone, Users, RefreshCw, Key, FileText, LogOut } from 'lucide-react';

interface NavbarProps {
  user: User;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, activeTab, setActiveTab, onLogout }) => {
  return (
    <header className="navbar-container">
      <div className="navbar-content">
        <div className="navbar-brand" onClick={() => setActiveTab('dashboard')}>
          <div className="brand-icon">
            <Shield className="icon-cyan" size={20} />
          </div>
          <div className="brand-text">
            <span className="brand-name">KySignOn</span>
            <span className="brand-tag">ID AUTHORITY</span>
          </div>
        </div>

        <nav className="navbar-links">
          <button
            className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <LayoutGrid size={16} />
            <span>Applications</span>
          </button>

          <button
            className={`nav-btn ${activeTab === 'devices' ? 'active' : ''}`}
            onClick={() => setActiveTab('devices')}
          >
            <Smartphone size={16} />
            <span>Security & Devices</span>
          </button>

          {user.role === 'admin' && (
            <>
              <div className="nav-divider" />
              <button
                className={`nav-btn ${activeTab === 'admin-users' ? 'active' : ''}`}
                onClick={() => setActiveTab('admin-users')}
              >
                <Users size={16} />
                <span>Users</span>
              </button>

              <button
                className={`nav-btn ${activeTab === 'admin-systems' ? 'active' : ''}`}
                onClick={() => setActiveTab('admin-systems')}
              >
                <RefreshCw size={16} />
                <span>Suite Sync</span>
              </button>

              <button
                className={`nav-btn ${activeTab === 'admin-clients' ? 'active' : ''}`}
                onClick={() => setActiveTab('admin-clients')}
              >
                <Key size={16} />
                <span>OAuth Clients</span>
              </button>

              <button
                className={`nav-btn ${activeTab === 'admin-audit' ? 'active' : ''}`}
                onClick={() => setActiveTab('admin-audit')}
              >
                <FileText size={16} />
                <span>Audit Logs</span>
              </button>
            </>
          )}
        </nav>

        <div className="navbar-actions">
          <div className="user-badge">
            <span className="user-name">{user.displayName || user.username}</span>
            <span className={`role-pill ${user.role}`}>{user.role.toUpperCase()}</span>
          </div>
          <button className="logout-btn" onClick={onLogout} title="Sign Out">
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
};
