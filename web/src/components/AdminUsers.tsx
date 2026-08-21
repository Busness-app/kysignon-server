import React, { useEffect, useState } from 'react';
import { User } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { parseUsers } from '../parsers';
import { Plus, RefreshCw, KeyRound, LogOut, Trash2, Edit, CheckCircle, XCircle } from 'lucide-react';

export const AdminUsers: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  // Form State
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'user' | 'admin'>('user');
  const [status, setStatus] = useState<'active' | 'disabled'>('active');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const fetchUsers = async () => {
    try {
      setUsers(await apiJson('/api/admin/users', parseUsers));
    } catch {
      // A failed refresh leaves the previous list on screen.
    }
  };

  // Creating, editing, resetting MFA for, or deleting an account are all things a stolen
  // session must not be able to do on its own, so each one re-proves the operator first.
  const { requestGrant, stepUpPrompt } = useStepUp();

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);

    try {
      const grant = await requestGrant(
        `Creating '${username || 'a new account'}' adds a credential to this directory` +
          (role === 'admin' ? ', with administrator rights.' : '.')
      );
      await apiRequest('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username, displayName, email, password, role, status }),
        stepUpToken: grant,
      });
      setShowCreateModal(false);
      resetForm();
      fetchUsers();
    } catch (err) {
      if (isCancelled(err)) return;
      setFormError(errorMessage(err, 'Failed to create user'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    setFormError(null);
    setSubmitting(true);

    try {
      const grant = await requestGrant(
        `Changing '${selectedUser.username}' can alter their password, role, or access.`
      );
      await apiRequest(`/api/admin/users/${selectedUser.id}`, {
        method: 'PUT',
        body: JSON.stringify({ displayName, email, role, status, password: password || undefined }),
        stepUpToken: grant,
      });
      setShowEditModal(false);
      resetForm();
      fetchUsers();
    } catch (err) {
      if (isCancelled(err)) return;
      setFormError(errorMessage(err, 'Failed to update user'));
    } finally {
      setSubmitting(false);
    }
  };

  const resetForm = () => {
    setUsername('');
    setDisplayName('');
    setEmail('');
    setPassword('');
    setRole('user');
    setStatus('active');
    setSelectedUser(null);
    setFormError(null);
  };

  const openEditModal = (u: User) => {
    setSelectedUser(u);
    setUsername(u.username);
    setDisplayName(u.displayName || u.username);
    setEmail(u.email);
    setPassword('');
    setRole(u.role);
    setStatus(u.status || 'active');
    setShowEditModal(true);
  };

  const handleResetMFA = async (u: User) => {
    if (!confirm(`Are you sure you want to reset MFA for '${u.username}'? This will revoke active sessions and require re-enrollment.`)) return;

    try {
      const grant = await requestGrant(
        `Resetting MFA for '${u.username}' removes every factor protecting that account.`
      );
      await apiRequest(`/api/admin/users/${u.id}/reset-mfa`, { method: 'POST', stepUpToken: grant });
      alert(`MFA reset successfully for ${u.username}`);
      fetchUsers();
    } catch (err) {
      if (isCancelled(err)) return;
      // The server now fails closed rather than reporting an unearned success, so this
      // message means nothing was changed.
      alert(errorMessage(err, 'Failed to reset MFA'));
    }
  };

  const handleRevokeSessions = async (u: User) => {
    if (!confirm(`Revoke all active sessions for '${u.username}'?`)) return;

    try {
      await apiRequest(`/api/admin/users/${u.id}/revoke-sessions`, { method: 'POST' });
      alert(`Sessions revoked for ${u.username}`);
    } catch (err) {
      alert(errorMessage(err, 'Failed to revoke sessions'));
    }
  };

  const handleDeleteUser = async (u: User) => {
    if (!confirm(`Permanently delete account '${u.username}'? This will also replicate deletion to paired products.`)) return;

    try {
      const grant = await requestGrant(`Deleting '${u.username}' cannot be undone from here.`);
      await apiRequest(`/api/admin/users/${u.id}`, { method: 'DELETE', stepUpToken: grant });
      fetchUsers();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to delete user'));
    }
  };

  return (
    <div className="admin-page">
      {stepUpPrompt}
      <div className="page-header">
        <div>
          <h1 className="page-title">User Directory & Replication</h1>
          <p className="page-subtitle">
            Central source of truth for accounts. New accounts and changes automatically replicate to paired KySecurity products.
          </p>
        </div>
        <button
          className="primary-btn sm"
          onClick={() => {
            resetForm();
            setShowCreateModal(true);
          }}
        >
          <Plus size={14} />
          <span>Create User</span>
        </button>
      </div>

      <div className="table-card">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Account</th>
              <th>Display Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td className="font-mono font-bold text-cyan">{u.username}</td>
                <td>{u.displayName || u.username}</td>
                <td className="text-muted">{u.email}</td>
                <td>
                  <span className={`role-pill ${u.role}`}>{u.role.toUpperCase()}</span>
                </td>
                <td>
                  {u.status === 'active' ? (
                    <span className="status-badge active">
                      <CheckCircle size={12} /> Active
                    </span>
                  ) : (
                    <span className="status-badge disabled">
                      <XCircle size={12} /> Disabled
                    </span>
                  )}
                </td>
                <td className="text-right">
                  <div className="action-buttons-wrap">
                    <button className="icon-btn" onClick={() => openEditModal(u)} title="Edit User">
                      <Edit size={15} />
                    </button>
                    <button className="icon-btn" onClick={() => handleResetMFA(u)} title="Reset MFA">
                      <KeyRound size={15} />
                    </button>
                    <button className="icon-btn" onClick={() => handleRevokeSessions(u)} title="Revoke Sessions">
                      <LogOut size={15} />
                    </button>
                    <button className="icon-btn danger" onClick={() => handleDeleteUser(u)} title="Delete User">
                      <Trash2 size={15} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Create User Account</h3>
              <button className="close-btn" onClick={() => setShowCreateModal(false)}>
                ×
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="modal-body">
              {formError && <div className="alert-box error sm">{formError}</div>}

              <div className="form-group">
                <label className="form-label">Username</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. bob"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoFocus
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Display Name</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Bob Builder"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Email</label>
                <input
                  type="email"
                  className="form-input"
                  placeholder="bob@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Initial Password (min 12 chars)</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              <div className="form-row">
                <div className="form-group flex-1">
                  <label className="form-label">Role</label>
                  <select
                    className="form-select"
                    value={role}
                    onChange={(e) => setRole(e.target.value as User['role'])}
                  >
                    <option value="user">User</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
                <div className="form-group flex-1">
                  <label className="form-label">Status</label>
                  <select
                    className="form-select"
                    value={status}
                    onChange={(e) => setStatus(e.target.value === 'disabled' ? 'disabled' : 'active')}
                  >
                    <option value="active">Active</option>
                    <option value="disabled">Disabled</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={submitting}>
                  {submitting ? <RefreshCw className="spin" size={14} /> : <span>Create & Replicate</span>}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {showEditModal && selectedUser && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Edit User: {selectedUser.username}</h3>
              <button className="close-btn" onClick={() => setShowEditModal(false)}>
                ×
              </button>
            </div>
            <form onSubmit={handleUpdateUser} className="modal-body">
              {formError && <div className="alert-box error sm">{formError}</div>}

              <div className="form-group">
                <label className="form-label">Display Name</label>
                <input
                  type="text"
                  className="form-input"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Email</label>
                <input
                  type="email"
                  className="form-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Reset Password (leave blank to keep current)</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="New password (optional)"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              <div className="form-row">
                <div className="form-group flex-1">
                  <label className="form-label">Role</label>
                  <select
                    className="form-select"
                    value={role}
                    onChange={(e) => setRole(e.target.value as User['role'])}
                  >
                    <option value="user">User</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
                <div className="form-group flex-1">
                  <label className="form-label">Status</label>
                  <select
                    className="form-select"
                    value={status}
                    onChange={(e) => setStatus(e.target.value === 'disabled' ? 'disabled' : 'active')}
                  >
                    <option value="active">Active</option>
                    <option value="disabled">Disabled</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowEditModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={submitting}>
                  {submitting ? <RefreshCw className="spin" size={14} /> : <span>Save Changes</span>}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
