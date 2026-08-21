import React, { useEffect, useState } from 'react';
import { BackupDrillResult, BackupStatus, RecoveryKit } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import {
  parseBackupStatus,
  parseDrillResult,
  parsePushResult,
  parseRecoveryKit,
} from '../parsers';
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

  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [kitLoading, setKitLoading] = useState<boolean>(false);
  const [kitError, setKitError] = useState<string>('');
  const [collected, setCollected] = useState<number[]>([]);
  const [capsuleTaken, setCapsuleTaken] = useState<boolean>(false);

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
        'Pairing stores a standing credential for the service that will hold every future backup.'
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
      setPairStatus(`Successfully paired with KyRecovery instance (${remoteUrl.trim()})`);
      setPairCode('');
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setPairError(errorMessage(err, 'Failed to pair with KyRecovery instance'));
    } finally {
      setPairingLoading(false);
    }
  };

  const handlePushBackup = async () => {
    setPushLoading(true);
    setPushResult('');
    setPushError('');
    try {
      const grant = await requestGrant('Pushing a backup sends your identity directory to the paired recovery service.');
      const resp = await apiJson('/api/admin/backup/push', parsePushResult, {
        method: 'POST',
        stepUpToken: grant,
      });
      setPushResult(`Backup capsule pushed! ID: ${resp.capsuleId} (${resp.sizeBytes} bytes)`);
    } catch (err) {
      if (isCancelled(err)) return;
      setPushError(errorMessage(err, 'Failed to push backup payload to remote instance'));
    } finally {
      setPushLoading(false);
    }
  };

  // Building the kit hands back only metadata. The capsule and each custodian shard are
  // fetched one at a time below, so no single download ever holds a reconstruction quorum.
  const handleCreateRecoveryKit = async () => {
    setKitLoading(true);
    setKitError('');
    setCollected([]);
    setCapsuleTaken(false);
    try {
      const grant = await requestGrant('Building a recovery kit produces the key shards that can restore this server.');
      setKit(
        await apiJson('/api/admin/backup/recovery-kit', parseRecoveryKit, {
          method: 'POST',
          stepUpToken: grant,
        })
      );
    } catch (err) {
      if (isCancelled(err)) {
        setKitLoading(false);
        return;
      }
      setKit(null);
      setKitError(errorMessage(err, 'Failed to build the recovery kit'));
    } finally {
      setKitLoading(false);
    }
  };

  /**
   * Downloads one artifact under a fresh step-up grant.
   *
   * A plain link cannot carry the grant header, so the response is fetched and saved from a
   * blob instead. The grant is what a stolen session cannot produce, which is the only thing
   * standing between a session cookie and the recovery quorum.
   */
  const downloadArtifact = async (path: string, filename: string, reason: string) => {
    const grant = await requestGrant(reason);
    // The step-up header doubles as the CSRF defence on these state-changing GETs: a
    // cross-site caller cannot set a custom header without a preflight, and this server
    // sends no CORS headers to permit one.
    const res = await fetch(path, {
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
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCapsule = async () => {
    if (!kit) return;
    setKitError('');
    try {
      await downloadArtifact(
        `/api/admin/backup/recovery-kit/${kit.kitId}/capsule`,
        `${kit.capsuleId}.kycap`,
        'The capsule holds your entire encrypted directory, including the keys needed to read it.'
      );
      setCapsuleTaken(true);
    } catch (err) {
      if (isCancelled(err)) return;
      setKitError(errorMessage(err, 'Failed to download the capsule'));
    }
  };

  // Each shard is served exactly once, and no administrator may collect enough of them to
  // rebuild the key alone, so a refusal here means a different custodian has to sign in.
  const handleDownloadShard = async (index: number) => {
    if (!kit || collected.includes(index)) return;
    setKitError('');
    try {
      await downloadArtifact(
        `/api/admin/backup/recovery-kit/${kit.kitId}/shard/${index}`,
        `kysignon-custodian-shard-${index}.html`,
        `Shard #${index} is one custodian's piece of the key that decrypts the capsule.`
      );
      setCollected((prev) => [...prev, index]);
    } catch (err) {
      if (isCancelled(err)) return;
      setKitError(errorMessage(err, `Failed to download shard #${index}`));
    }
  };

  const handleDiscardKit = async () => {
    if (!kit) return;
    try {
      await apiRequest(`/api/admin/backup/recovery-kit/${kit.kitId}`, { method: 'DELETE' });
    } catch {
      // The kit expires on its own; a failed discard is not worth blocking the operator.
    }
    setKit(null);
    setCollected([]);
    setCapsuleTaken(false);
  };

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
                Capsule encapsulation includes the SQLite database, the RSA signing key, the
                deployment encryption and session keys, and the configuration manifest &mdash; everything
                a restored server needs to read its own data.
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button type="button" className="primary-btn" onClick={runDrill} disabled={runningDrill}>
              {runningDrill ? <Loader2 size={16} className="spin" /> : <Play size={16} />}
              <span>{runningDrill ? 'Running Drill...' : 'Run Live Drill'}</span>
            </button>
            <button type="button" className="secondary-btn" onClick={handleCreateRecoveryKit} disabled={kitLoading}>
              {kitLoading ? <Loader2 size={16} className="spin" /> : <Key size={16} />}
              <span>{kitLoading ? 'Building Kit...' : 'Build Recovery Kit'}</span>
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
                Extracts the capsule into an ephemeral 0700 sandbox, then proves the restore is
              usable: MFA secrets decrypt and the signing key issues a verifiable token.
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
              A kit is two kinds of artifact: the encrypted <code>.kycap</code> container, and
              one document per custodian holding a single Shamir shard. They are downloaded
              separately and each shard is served only once, so no single file can ever
              reconstruct the key on its own.
            </div>

            {kitError && (
              <div style={{ background: 'var(--danger-soft)', border: '1px solid var(--danger)', color: 'var(--danger)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8125rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertCircle size={16} />
                <span>{kitError}</span>
              </div>
            )}

            {!kit ? (
              <button type="button" className="secondary-btn" onClick={handleCreateRecoveryKit} disabled={kitLoading} style={{ width: '100%', justifyContent: 'center' }}>
                {kitLoading ? <Loader2 size={16} className="spin" /> : <Key size={16} />}
                <span>{kitLoading ? 'Building Kit...' : 'Build Recovery Kit'}</span>
              </button>
            ) : (
              <>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem', background: 'var(--panel)', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--ink-muted)' }}>Capsule ID:</span>
                    <span style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>{kit.capsuleId}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem', background: 'var(--panel)', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--ink-muted)' }}>Quorum Threshold:</span>
                    <span style={{ color: 'var(--accent)' }}>{kit.threshold} of {kit.totalShares} Custodians Required</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem', background: 'var(--panel)', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--ink-muted)' }}>Encryption Standard:</span>
                    <span style={{ color: 'var(--ink-strong)' }}>AES-256-GCM + SHA-256 Checksum</span>
                  </div>
                </div>

                <button type="button" className="primary-btn" onClick={handleDownloadCapsule} style={{ width: '100%', justifyContent: 'center', marginBottom: '0.75rem' }}>
                  <Download size={16} />
                  <span>{capsuleTaken ? 'Download Capsule Again' : `Download Encrypted Capsule (${Math.round(kit.capsuleSize / 1024)} KB)`}</span>
                </button>

                {kit.soleCustodian ? (
                  <div style={{ background: 'var(--danger-soft)', border: '1px solid var(--danger)', color: 'var(--danger)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.75rem', marginBottom: '0.75rem', display: 'flex', gap: '0.5rem' }}>
                    <AlertCircle size={16} style={{ flexShrink: 0 }} />
                    <span>
                      This server has one administrator, so you can collect every shard yourself
                      &mdash; which means the {kit.threshold}-of-{kit.totalShares} custody split is
                      not actually in effect, and each collection is recorded as such. Add a second
                      administrator to restore it.
                    </span>
                  </div>
                ) : (
                  <div style={{ fontSize: '0.75rem', color: 'var(--ink-muted)', marginBottom: '0.5rem' }}>
                    Each shard is downloadable once, and you may collect at most{' '}
                    {kit.maxPerCustodian} of {kit.totalShares}. The rest must be collected by a
                    different administrator signed in as themselves, so no one person ever holds
                    enough to rebuild the key.
                  </div>
                )}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  {kit.shards.map((shard) => {
                    const taken = collected.includes(shard.index) || shard.collected;
                    const heldHere = collected.length;
                    const atCap = !kit.soleCustodian && heldHere >= kit.maxPerCustodian;
                    return (
                      <button
                        key={shard.index}
                        type="button"
                        className="secondary-btn"
                        onClick={() => handleDownloadShard(shard.index)}
                        disabled={taken || atCap}
                        title={atCap ? 'Another administrator must collect this shard' : undefined}
                        style={{ width: '100%', justifyContent: 'space-between' }}
                      >
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Key size={14} />
                          <span>Custodian Shard #{shard.index}</span>
                        </span>
                        {taken ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: 'var(--success)' }}>
                            <CheckCircle2 size={14} />
                            <span>Collected</span>
                          </span>
                        ) : atCap ? (
                          <span style={{ color: 'var(--ink-muted)', fontSize: '0.75rem' }}>
                            Needs another custodian
                          </span>
                        ) : (
                          <Download size={14} />
                        )}
                      </button>
                    );
                  })}
                </div>

                <button type="button" className="secondary-btn" onClick={handleDiscardKit} style={{ width: '100%', justifyContent: 'center' }}>
                  <XCircle size={16} />
                  <span>Discard Uncollected Shards</span>
                </button>
              </>
            )}
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
