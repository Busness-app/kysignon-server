import React, { useEffect, useState } from 'react';
import { AuditEvent } from '../types';
import { apiRequest } from '../api';
import { RefreshCw, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

export const AdminAudit: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const data = await apiRequest('/api/admin/audit-events?limit=150');
      setEvents(data.auditEvents || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  return (
    <div className="admin-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security & Audit Event Stream</h1>
          <p className="page-subtitle">
            Content-blind security audit records for authentication, administrative actions, and suite events.
          </p>
        </div>
        <button className="secondary-btn sm" onClick={fetchEvents} disabled={loading}>
          <RefreshCw className={loading ? 'spin' : ''} size={14} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="table-card">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Target</th>
              <th>IP Address</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-5 text-muted">
                  No audit events recorded yet.
                </td>
              </tr>
            ) : (
              events.map((e) => (
                <tr key={e.id}>
                  <td className="font-mono text-sm text-muted">
                    {new Date(e.createdAt).toLocaleString()}
                  </td>
                  <td className="font-mono font-bold text-cyan">{e.action}</td>
                  <td>{e.actorUsername || e.actorId || 'system'}</td>
                  <td className="text-muted text-sm">{e.targetType ? `${e.targetType}:${e.targetId}` : '—'}</td>
                  <td className="font-mono text-sm text-muted">{e.ipAddress}</td>
                  <td>
                    {e.outcome === 'success' && (
                      <span className="status-badge active">
                        <CheckCircle size={12} /> Success
                      </span>
                    )}
                    {e.outcome === 'failure' && (
                      <span className="status-badge warn">
                        <AlertTriangle size={12} /> Failure
                      </span>
                    )}
                    {e.outcome === 'denied' && (
                      <span className="status-badge disabled">
                        <XCircle size={12} /> Denied
                      </span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
