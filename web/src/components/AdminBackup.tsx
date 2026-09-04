import React, { useEffect, useState } from 'react';
import { BackupDrillResult, BackupStatus } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { parseBackupStatus, parseDrillResult, parseDepositReceipt } from '../parsers';
import {
  Archive,
  Play,
  Download,
  CheckCircle2,
  XCircle,
  Loader2,
  Link2,
  ShieldCheck,
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

  const [depositLoading, setDepositLoading] = useState<boolean>(false);
  const [depositResult, setDepositResult] = useState<string>('');
  const [depositError, setDepositError] = useState<string>('');
  const [exportError, setExportError] = useState<string>('');

  // Every artifact here is either a secret or the means to reach one, so each is fetched
  // with its own single-use step-up grant rather than on the session cookie alone.
  const { requestGrant, stepUpPrompt } = useStepUp();

  const fetchStatus = async () => {
    setLoadingStatus(true);
    try {
      const data = await apiJson('/api/admin/backup/status', parseBackupStatus);
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
      const data = await apiJson('/api/admin/backup/drill', parseDrillResult, { method: 'POST' });
      setDrillResult(data);
    } catch (err) {
      const message = errorMessage(err, 'Restore drill execution failed');
      setDrillResult({
        passed: false,
        duration_ms: 0,
        error_message: message,
        checks: [{ name: 'Execution', passed: false, message }],
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
      const grant = await requestGrant(
        'Pairing pins the suite recovery key every future backup is sealed to, and stores a standing credential for the service that will hold them.'
      );
      await apiRequest('/api/admin/backup/pair-remote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recovery_url: remoteUrl.trim(),
          pairing_code: pairCode,
        }),
        stepUpToken: grant,
      });
      setPairStatus(`Paired with KyRecovery (${remoteUrl.trim()})`);
      setPairCode('');
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setPairError(errorMessage(err, 'Failed to pair with KyRecovery'));
    } finally {
      setPairingLoading(false);
    }
  };

  const handleDeposit = async () => {
    setDepositLoading(true);
    setDepositResult('');
    setDepositError('');
    try {
      const grant = await requestGrant('Depositing sends a capsule sealed to the suite recovery key to the paired KyRecovery.');
      const rcpt = await apiJson('/api/admin/backup/deposit', parseDepositReceipt, {
        method: 'POST',
        stepUpToken: grant,
      });
      setDepositResult(`Deposited ${rcpt.capsuleId} (${rcpt.sizeBytes} bytes) at ${rcpt.depositedAt}`);
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setDepositError(errorMessage(err, 'Failed to deposit the capsule'));
    } finally {
      setDepositLoading(false);
    }
  };

  /**
   * Downloads the sealed capsule under a fresh step-up grant.
   *
   * A plain link cannot carry the grant header, so the response is fetched and saved from a
   * blob instead. The step-up header doubles as the CSRF defence on this state-changing GET.
   */
  const handleExportCapsule = async () => {
    setExportError('');
    try {
      const grant = await requestGrant('The capsule holds your entire directory and its keys, sealed to the suite recovery key.');
      const res = await fetch('/api/admin/backup/export-capsule', {
        credentials: 'same-origin',
        headers: { 'X-KySignOn-StepUp': grant },
      });
      if (!res.ok) {
        const body: unknown = await res.json().catch(() => ({}));
        const message =
          typeof body === 'object' && body !== null && 'error' in body
            ? String((body as { error: unknown }).error)
            : `Download failed (HTTP ${res.status})`;
        throw new Error(message);
      }
      const disposition = res.headers.get('Content-Disposition') ?? '';
      const match = /filename="([^"]+)"/.exec(disposition);
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement('a');
      a.href = url;
      a.download = match ? match[1] : 'kysignon.kycap';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      if (isCancelled(err)) return;
      setExportError(errorMessage(err, 'Failed to export the capsule'));
    }
  };

  const paired = status?.paired ?? false;

  return (
    <div className="admin-view">
      {stepUpPrompt}
      <div className="view-header">
        <div className="header-title-group">
          <div className="title-with-icon">
            <Archive className="icon-cyan" size={24} />
            <h2>KyBackup & Disaster Recovery</h2>
          </div>
          <p className="view-description">
            Capsules sealed to the suite recovery key, sandboxed restore verification, and scheduled deposit to KyRecovery.
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

      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ background: 'var(--accent-soft)', border: '1px solid var(--panel-border)', borderRadius: '8px', padding: '0.75rem', display: 'flex' }}>
              <ShieldCheck className="icon-cyan" size={28} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Sealed Capsule</h3>
                <span className={`badge ${paired ? 'badge-success' : 'badge-warning'}`} style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {paired ? 'Paired' : 'Not paired'}
                </span>
              </div>
              <p style={{ margin: 0, color: 'var(--ink)', fontSize: '0.875rem' }}>
                The capsule carries the SQLite database, the RSA signing key, the deployment encryption and
                session keys, and the configuration manifest. Only the suite custodians' shares open it; this
                server holds no key that does.
              </p>
              {status?.recovery_key_id && (
                <p style={{ margin: '0.25rem 0 0 0', color: 'var(--ink)', fontSize: '0.8125rem', fontFamily: 'var(--font-mono)' }}>
                  recovery key {status.recovery_key_id}
                  {status.threshold && status.total_shares ? ` · ${status.threshold}-of-${status.total_shares} custodians` : ''}
                </p>
              )}
              {status?.last_deposit && (
                <p style={{ margin: '0.25rem 0 0 0', color: 'var(--ink)', fontSize: '0.8125rem' }}>
                  Last deposit {status.last_deposit.capsuleId} ({status.last_deposit.sizeBytes} bytes) at {status.last_deposit.depositedAt}
                </p>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button type="button" className="primary-btn" onClick={handleDeposit} disabled={depositLoading || !paired}>
              {depositLoading ? <Loader2 size={16} className="spin" /> : <Send size={16} />}
              <span>{depositLoading ? 'Depositing...' : 'Deposit to KyRecovery now'}</span>
            </button>
            <button type="button" className="secondary-btn" onClick={handleExportCapsule} disabled={!paired}>
              <Download size={16} />
              <span>Download sealed capsule</span>
            </button>
          </div>
        </div>
        {(depositResult || depositError || exportError) && (
          <p style={{ margin: '0.75rem 0 0 0', fontSize: '0.8125rem', color: depositResult ? 'var(--success)' : 'var(--danger)' }}>
            {depositResult || depositError || exportError}
          </p>
        )}
        {status?.deposit_interval_sec ? (
          <p style={{ margin: '0.5rem 0 0 0', color: 'var(--ink)', fontSize: '0.75rem' }}>
            Paired instances also deposit every {Math.round(status.deposit_interval_sec / 3600)}h (KYSIGNON_BACKUP_DEPOSIT_INTERVAL).
          </p>
        ) : null}
      </div>

      <div className="grid-2-col" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <div className="panel">
          <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Play size={16} className="icon-cyan" />
                <span>Automated Restore Drill</span>
              </h3>
              <p style={{ margin: '0.25rem 0 0 0', color: 'var(--ink)', fontSize: '0.8125rem' }}>
                Seals to a throwaway key, opens the capsule in an ephemeral 0700 sandbox, then proves the
                restore is usable: MFA secrets decrypt and the signing key issues a verifiable token.
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
                    {drillResult.passed ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                    {drillResult.passed ? 'PASSED' : 'FAILED'}
                  </span>
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--ink)' }}>{drillResult.duration_ms} ms</span>
              </div>
              {drillResult.error_message && (
                <p style={{ margin: '0 0 0.75rem 0', color: 'var(--danger)', fontSize: '0.8125rem' }}>{drillResult.error_message}</p>
              )}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                {drillResult.checks.map((check, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.8125rem' }}>
                    {check.passed ? (
                      <CheckCircle2 size={14} style={{ color: 'var(--success)', flexShrink: 0, marginTop: 2 }} />
                    ) : (
                      <XCircle size={14} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
                    )}
                    <span style={{ fontWeight: 500 }}>{check.name}:</span>
                    <span style={{ color: 'var(--ink)' }}>{check.message}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p style={{ color: 'var(--ink)', fontSize: '0.8125rem', margin: 0 }}>No drill has run in this session.</p>
          )}
        </div>

        <div className="panel">
          <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Link2 size={16} className="icon-cyan" />
            <span>Pair with KyRecovery</span>
          </h3>
          <p style={{ margin: '0.25rem 0 1rem 0', color: 'var(--ink)', fontSize: '0.8125rem' }}>
            Enter the six-digit code generated in the KyRecovery dashboard. Pairing hands this server the
            suite recovery public key; every capsule from then on is sealed to it.
          </p>
          <form onSubmit={handlePairRemote} style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={16} className="icon-cyan" />
              <input
                type="url"
                placeholder="https://recovery.example.com"
                value={remoteUrl}
                onChange={(e) => setRemoteUrl(e.target.value)}
                required
                style={{ flex: 1 }}
              />
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="text"
                placeholder="6-digit code"
                value={pairCode}
                onChange={(e) => setPairCode(e.target.value)}
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: '2px', flex: 1 }}
                required
              />
              <button type="submit" className="primary-btn" disabled={pairingLoading} style={{ flexShrink: 0 }}>
                {pairingLoading ? <Loader2 size={14} className="spin" /> : <Link2 size={14} />}
                <span>{pairingLoading ? 'Pairing...' : 'Claim & Pair'}</span>
              </button>
            </div>
          </form>
          {pairStatus && (
            <p style={{ margin: '0.75rem 0 0 0', fontSize: '0.8125rem', color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <CheckCircle2 size={14} /> {pairStatus}
            </p>
          )}
          {pairError && (
            <p style={{ margin: '0.75rem 0 0 0', fontSize: '0.8125rem', color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <AlertCircle size={14} /> {pairError}
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
