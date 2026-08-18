import React, { useEffect, useState } from 'react';
import { User } from './types';
import { apiRequest } from './api';
import { Navbar } from './components/Navbar';
import { LoginView } from './components/LoginView';
import { UserDashboard } from './components/UserDashboard';
import { DeviceSettings } from './components/DeviceSettings';
import { AdminUsers } from './components/AdminUsers';
import { AdminSystems } from './components/AdminSystems';
import { AdminClients } from './components/AdminClients';
import { AdminAudit } from './components/AdminAudit';
import { AdminBackup } from './components/AdminBackup';
import { RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');

  const checkSession = async () => {
    try {
      const data = await apiRequest('/api/auth/me');
      setCurrentUser(data);
    } catch {
      setCurrentUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkSession();

    const handleUnauthorized = () => {
      setCurrentUser(null);
    };

    window.addEventListener('kysignon:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('kysignon:unauthorized', handleUnauthorized);
  }, []);

  const handleLogout = async () => {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // ignore
    }
    setCurrentUser(null);
    setActiveTab('dashboard');
  };

  if (loading) {
    return (
      <div className="loading-screen">
        <RefreshCw className="spin icon-cyan" size={32} />
        <p className="loading-text">Authenticating with KySignOn...</p>
      </div>
    );
  }

  if (!currentUser) {
    return <LoginView onLoginSuccess={(u) => { setCurrentUser(u); checkSession(); }} />;
  }

  return (
    <div className="app-layout">
      <Navbar
        user={currentUser}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onLogout={handleLogout}
      />

      <main className="main-content">
        {activeTab === 'dashboard' && (
          <UserDashboard
            user={currentUser}
            onNavigateToDevices={() => setActiveTab('devices')}
          />
        )}

        {activeTab === 'devices' && (
          <DeviceSettings user={currentUser} onUserUpdate={checkSession} />
        )}

        {currentUser.role === 'admin' && (
          <>
            {activeTab === 'admin-users' && <AdminUsers />}
            {activeTab === 'admin-systems' && <AdminSystems />}
            {activeTab === 'admin-clients' && <AdminClients />}
            {activeTab === 'admin-audit' && <AdminAudit />}
            {activeTab === 'admin-backup' && <AdminBackup />}
          </>
        )}
      </main>
    </div>
  );
};
