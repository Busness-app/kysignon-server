import React, { useEffect, useState } from 'react';
import { BackupDrillResult, BackupStatus } from '../types';
import { apiRequest } from '../api';
import {
  Archive,
  Play,
  Download,
  CheckCircle2,
  XCircle,
  Loader2,
  Link2,
  ShieldCheck,
  Key,
  Server,
  Send,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';

export const AdminBackup: React.FC = () => {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);
  const [runningDrill, setRunningDrill] = useState<boolean>(false);
  const [drillResult, setDrillResult] = useState<BackupDrillResult | null>(null);

  const [remoteUrl, setRemoteUrl] = useState<string>('');
  const [pairCode, setPairCode] = useState<string>('');
  const [pairStatus, setPairStatus] = useState<string>('');
  const [pairError, setPairError] = useState<string>('');
  const [pairingLoading, setPairingLoading] = useState<boolean>(false);

  const [pushLoading, setPushLoading] = useState<boolean>(false);
  const [pushResult, setPushResult] = useState<string>('');
  const [pushError, setPushError] = useState<string>('');

  const fetchStatus = async () => {
    setLoadingStatus(true);
    try {
      const data = await apiRequest('/api/admin/backup/status');
      setStatus(data);
      if (data.recovery_url) {
        setRemoteUrl(data.recovery_url);
      }
    } catch {
      // ignore
    } finally {
      setLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const runDrill = async () => {
    setRunningDrill(true);
    setDrillResult(null);
    try {
      const data = await apiRequest('/api/admin/backup/drill', { method: 'POST' });
      setDrillResult(data);
    } catch (err: any) {
      setDrillResult({
        passed: false,
        duration_ms: 0,
        error_message: err.message || 'Restore drill execution failed',
        checks: [
          {
            name: 'Execution',
            passed: false,
            message: err.message || 'Connection or execution failure',
          },
        ],
      });
    } finally {
      setRunningDrill(false);
    }
  };

  const handlePairRemote = async (e: React.FormEvent) => {
    e.preventDefault();
    setPairingLoading(true);
    setPairStatus('');
    setPairError('');
    try {
      const data = await apiRequest('/api/admin/backup/pair-remote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recovery_url: remoteUrl,
          pairing_code: pairCode,
        }),
      });
      setPairStatus(`Successfully paired with KyRecovery instance (${data.recovery_url})`);
      setPairCode('');
      await fetchStatus();
    } catch (err: any) {
      setPairError(err.message || 'Failed to pair with KyRecovery instance');
    } finally {
      setPairingLoading(false);
    }
  };

  const handlePushBackup = async () => {
    setPushLoading(true);
    setPushResult('');
    setPushError('');
    try {
      const resp = await apiRequest('/api/admin/backup/push', { method: 'POST' });
      setPushResult(`Backup capsule pushed! ID: ${resp.capsule_id} (${resp.size_bytes} bytes)`);
    } catch (err: any) {
      setPushError(err.message || 'Failed to push backup payload to remote instance');
    } finally {
      setPushLoading(false);
    }
  };

  const handleDownloadRecoveryKit = () => {
    window.open('/api/admin/backup/recovery-kit', '_blank');
  };

  return (
    <div className="admin-view">
      <div className="view-header">
        <div className="header-title-group">
          <div className="title-with-icon">
            <Archive className="icon-cyan" size={24} />
            <h2>KyBackup & Disaster Recovery</h2>
          </div>
          <p className="view-description">
            Feature 0 continuous disaster recovery, sandboxed automated restore verification, Shamir $(k=2, n=3)$ custodian key management, and KyRecovery replication.
          </p>
        </div>
        <div className="header-actions">
          <button
            type="button"
            className="secondary-btn"
            onClick={fetchStatus}
            disabled={loadingStatus}
            title="Refresh Status"
          >
            <RefreshCw size={16} className={loadingStatus ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Feature 0 Readiness Banner */}
      <div className="panel" style={{ marginBottom: '1.5rem', background: 'linear-gradient(180deg, rgba(77,238,234,0.05) 0%, rgba(22,26,34,0.8) 100%)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ background: 'var(--accent-soft)', border: '1px solid var(--panel-border)', borderRadius: '8px', padding: '0.75rem', display: 'flex' }}>
              <ShieldCheck className="icon-cyan" size={28} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Feature 0 Capsule Engine</h3>
                <span className="badge badge-success" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  ACTIVE &bull; AES-256-GCM
                </span>
              </div>
              <p style={{ margin: 0, color: 'var(--ink)', fontSize: '0.875rem' }}>
                Self-contained capsule encapsulation includes SQLite database, RSA discovery keys, and configuration manifest.
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button type="button" className="primary-btn" onClick={runDrill} disabled={runningDrill}>
              {runningDrill ? <Loader2 size={16} className="spin" /> : <Play size={16} />}
              <span>{runningDrill ? 'Running Drill...' : 'Run Live Drill'}</span>
            </button>
            <button type="button" className="secondary-btn" onClick={handleDownloadRecoveryKit}>
              <Download size={16} />
              <span>Download Recovery Kit</span>
            </button>
          </div>
        </div>
      </div>

      <div className="grid-2-col" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
        {/* On-Demand Sandboxed Restore Drill Card */}
        <div className="panel">
          <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Play size={16} className="icon-cyan" />
                <span>Automated Restore Drill</span>
              </h3>
              <p style={{ margin: '0.25rem 0 0 0', color: 'var(--ink)', fontSize: '0.8125rem' }}>
                Extracts capsule into an ephemeral 0700 sandbox and tests DB integrity.
              </p>
            </div>
            <button type="button" className="primary-btn" onClick={runDrill} disabled={runningDrill} style={{ padding: '0.4rem 0.8rem', fontSize: '0.8125rem' }}>
              {runningDrill ? <Loader2 size={14} className="spin" /> : <Play size={14} />}
              <span>{runningDrill ? 'Verifying...' : 'Run Drill'}</span>
            </button>
          </div>

          {drillResult ? (
            <div style={{ background: 'var(--bg)', border: '1px solid var(--line)', borderRadius: '8px', padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', paddingBottom: '0.75rem', borderBottom: '1px solid var(--line)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>Drill Result:</span>
                  <span className={`badge ${drillResult.passed ? 'badge-success' : 'badge-danger'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                    {drillResult.passed ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                    <span>{drillResult.passed ? 'ALL CHECKS PASSED' : 'DRILL FAILED'}</span>
                  </span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--ink-muted)' }}>
                  {drillResult.duration_ms} ms
                </span>
              </div>

              {drillResult.error_message && (
                <div style={{ background: 'var(--danger-soft)', border: '1px solid var(--danger)', color: 'var(--danger)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8125rem', marginBottom: '0.75rem' }}>
                  {drillResult.error_message}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {drillResult.checks.map((c, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', padding: '0.5rem', background: 'var(--panel)', borderRadius: '6px', border: '1px solid var(--line)' }}>
                    <div style={{ marginTop: '2px' }}>
                      {c.passed ? <CheckCircle2 size={15} style={{ color: 'var(--success)' }} /> : <XCircle size={15} style={{ color: 'var(--danger)' }} />}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--ink-strong)' }}>{c.name}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--ink)', wordBreak: 'break-word', fontFamily: 'var(--font-mono)' }}>{c.message}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ background: 'var(--bg)', border: '1px dashed var(--line)', borderRadius: '8px', padding: '2rem', textAlign: 'center', color: 'var(--ink-muted)', fontSize: '0.875rem' }}>
              <Archive size={28} style={{ margin: '0 auto 0.5rem', opacity: 0.4 }} />
              <p style={{ margin: 0 }}>Click "Run Drill" to test automated sandbox restore verification.</p>
            </div>
          )}
        </div>

        {/* Offline Emergency Recovery Kit Card */}
        <div className="panel">
          <div className="panel-header" style={{ marginBottom: '1rem' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Key size={16} className="icon-cyan" />
              <span>Offline Disaster Recovery Kit</span>
            </h3>
            <p style={{ margin: '0.25rem 0 0 0', color: 'var(--ink)', fontSize: '0.8125rem' }}>
              Self-contained emergency restore kit with Shamir $(k=2, n=3)$ custodian shards.
            </p>
          </div>

          <div style={{ background: 'var(--bg)', border: '1px solid var(--line)', borderRadius: '8px', padding: '1rem', marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.8125rem', color: 'var(--ink)', lineHeight: '1.5', marginBottom: '1rem' }}>
              The Recovery Kit contains 3 separate custodian key shards generated via Shamir Secret Sharing over GF(256). Any 2 shards can reconstruct the capsule decryption key offline without KySignOn running.
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem', background: 'var(--panel)', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--ink-muted)' }}>Quorum Threshold:</span>
                <span style={{ color: 'var(--accent)' }}>2 of 3 Custodians Required</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem', background: 'var(--panel)', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: 'var(--ink-muted)' }}>Encryption Standard:</span>
                <span style={{ color: 'var(--ink-strong)' }}>AES-256-GCM + SHA-256 Checksum</span>
              </div>
            </div>

            <button type="button" className="secondary-btn" onClick={handleDownloadRecoveryKit} style={{ width: '100%', justifyContent: 'center' }}>
              <Download size={16} />
              <span>Download Printable Kit (.html)</span>
            </button>
          </div>
        </div>
      </div>

      {/* Remote KyRecovery Pairing Card */}
      <div className="panel">
        <div className="panel-header" style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Server size={16} className="icon-cyan" />
                <span>KyRecovery Server Link</span>
              </h3>
              <p style={{ margin: '0.25rem 0 0 0', color: 'var(--ink)', fontSize: '0.8125rem' }}>
                Continuous disaster recovery vault pairing via 6-digit ephemeral PIN.
              </p>
            </div>
            {status && (
              <span className={`badge ${status.paired ? 'badge-success' : 'badge-neutral'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: status.paired ? 'var(--success)' : 'var(--ink-muted)' }} />
                <span>{status.paired ? 'PAIRED & LINKED' : 'UNPAIRED'}</span>
              </span>
            )}
          </div>
        </div>

        {pairStatus && (
          <div style={{ background: 'var(--success-soft)', border: '1px solid var(--success)', color: 'var(--success)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.875rem', marginBottom: '1rem' }}>
            {pairStatus}
          </div>
        )}

        {pairError && (
          <div style={{ background: 'var(--danger-soft)', border: '1px solid var(--danger)', color: 'var(--danger)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.875rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={16} />
            <span>{pairError}</span>
          </div>
        )}

        {pushResult && (
          <div style={{ background: 'var(--success-soft)', border: '1px solid var(--success)', color: 'var(--success)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.875rem', marginBottom: '1rem' }}>
            {pushResult}
          </div>
        )}

        {pushError && (
          <div style={{ background: 'var(--danger-soft)', border: '1px solid var(--danger)', color: 'var(--danger)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.875rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={16} />
            <span>{pushError}</span>
          </div>
        )}

        <form onSubmit={handlePairRemote} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="grid-2-col" style={{ display: 'grid', gridTemplateColumns: '1fr 200px', gap: '1rem' }}>
            <div className="form-group">
              <label className="form-label" htmlFor="rec-url">KyRecovery Server URL</label>
              <input
                id="rec-url"
                type="url"
                className="form-input"
                placeholder="https://recovery.kysecurity.org"
                value={remoteUrl}
                onChange={(e) => setRemoteUrl(e.target.value)}
                required
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="rec-code">6-Digit Pairing PIN</label>
              <input
                id="rec-code"
                type="text"
                className="form-input"
                placeholder="123456"
                maxLength={8}
                value={pairCode}
                onChange={(e) => setPairCode(e.target.value)}
                required={!status?.paired}
              />
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            {status?.paired && (
              <button
                type="button"
                className="secondary-btn"
                onClick={handlePushBackup}
                disabled={pushLoading}
              >
                {pushLoading ? <Loader2 size={16} className="spin" /> : <Send size={16} />}
                <span>{pushLoading ? 'Pushing Capsule...' : 'Push Backup to KyRecovery'}</span>
              </button>
            )}
            <button
              type="submit"
              className="primary-btn"
              disabled={pairingLoading || !remoteUrl}
            >
              {pairingLoading ? <Loader2 size={16} className="spin" /> : <Link2 size={16} />}
              <span>{pairingLoading ? 'Pairing...' : status?.paired ? 'Update Pairing' : 'Claim Pairing'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
