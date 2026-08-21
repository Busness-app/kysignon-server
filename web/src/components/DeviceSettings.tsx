import React, { useEffect, useState, useRef } from 'react';
import { NativeDevice, User } from '../types';
import { apiJson, apiRequest, errorMessage, isStepUpRequired } from '../api';
import {
  parseDevices,
  parsePairingToken,
  parseRecoveryCodes,
  parseStepUpGrant,
  parseTOTPSetup,
} from '../parsers';
import QRCode from 'qrcode';
import {
  Smartphone,
  KeyRound,
  ShieldAlert,
  Trash2,
  CheckCircle,
  Clock,
  Copy,
  Check,
  Plus,
  Lock,
} from 'lucide-react';

/** Which account-security change the step-up prompt is currently gating. */
type PendingAction = 'totp' | 'recovery-codes';

interface DeviceSettingsProps {
  user: User;
  onUserUpdate: () => void;
}

export const DeviceSettings: React.FC<DeviceSettingsProps> = ({ user, onUserUpdate }) => {
  const [devices, setDevices] = useState<NativeDevice[]>([]);
  const [pairDeviceIdsBefore, setPairDeviceIdsBefore] = useState<Set<string>>(new Set());

  // Device Pairing State
  const [showPairModal, setShowPairModal] = useState(false);
  const [pairPin, setPairPin] = useState('');
  const [pairExpiresAt, setPairExpiresAt] = useState<number | null>(null);
  const [pairStartedAt, setPairStartedAt] = useState<number | null>(null);
  const [countdown, setCountdown] = useState(90);
  const qrCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // TOTP Setup State
  const [showTotpModal, setShowTotpModal] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [totpError, setTotpError] = useState<string | null>(null);
  const totpCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // Recovery Codes Modal
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);

  // Step-up re-authentication. Replacing a factor or reissuing recovery codes needs proof
  // that this is the account holder, not just a live session.
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [stepUpPassword, setStepUpPassword] = useState('');
  const [stepUpCode, setStepUpCode] = useState('');
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [stepUpBusy, setStepUpBusy] = useState(false);

  const hasExistingMFA = (user.mfaMethods?.length ?? 0) > 0;

  const fetchDevices = async () => {
    try {
      setDevices(await apiJson('/api/user/devices', parseDevices));
    } catch {
      // A failed refresh leaves the previous list on screen; nothing is lost.
    }
  };

  const closePairModal = () => {
    setShowPairModal(false);
    setPairStartedAt(null);
    fetchDevices();
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  // 90s Countdown Timer for Device Pairing
  useEffect(() => {
    if (!showPairModal || !pairExpiresAt) return;

    const interval = setInterval(() => {
      const remaining = Math.max(0, Math.floor((pairExpiresAt - Date.now()) / 1000));
      setCountdown(remaining);
      if (remaining <= 0) {
        clearInterval(interval);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [showPairModal, pairExpiresAt]);

  useEffect(() => {
    if (!showPairModal || !pairStartedAt || !pairExpiresAt) return;

    const interval = setInterval(async () => {
      if (Date.now() >= pairExpiresAt) {
        clearInterval(interval);
        return;
      }
      try {
        const nextDevices = await apiJson('/api/user/devices', parseDevices);
        setDevices(nextDevices);
        const paired = nextDevices.some((dev) => {
          if (!pairDeviceIdsBefore.has(dev.id) && dev.pushToken) return true;
          const seenAt = new Date(dev.lastSeenAt || dev.createdAt).getTime();
          return Boolean(dev.pushToken) && Number.isFinite(seenAt) && seenAt >= pairStartedAt - 2000;
        });
        if (paired) {
          closePairModal();
          onUserUpdate();
        }
      } catch {
        // Keep the QR/PIN visible; the normal countdown still expires it.
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [showPairModal, pairStartedAt, pairExpiresAt, pairDeviceIdsBefore, onUserUpdate]);

  const handleStartDevicePairing = async () => {
    setShowPairModal(true);
    setPairStartedAt(Date.now());
    setPairDeviceIdsBefore(new Set(devices.map((dev) => dev.id)));
    try {
      const data = await apiJson('/api/user/devices/pairing-token', parsePairingToken, { method: 'POST' });
      setPairPin(data.pinCode);
      const exp = new Date(data.expiresAt).getTime();
      setPairExpiresAt(exp);
      setCountdown(Math.floor((exp - Date.now()) / 1000));

      if (qrCanvasRef.current && data.qrPayload) {
        QRCode.toCanvas(qrCanvasRef.current, data.qrPayload, {
          width: 200,
          margin: 1,
          color: { dark: '#0d0f14', light: '#4deeea' },
        });
      }
    } catch (err) {
      alert(errorMessage(err, 'Failed to generate pairing token'));
      closePairModal();
    }
  };

  // Both account-security changes go through the same prompt; nothing starts until the
  // account holder has re-proved who they are.
  const requestStepUp = (action: PendingAction) => {
    setPendingAction(action);
    setStepUpPassword('');
    setStepUpCode('');
    setStepUpError(null);
  };

  const submitStepUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pendingAction || !stepUpPassword) return;
    setStepUpBusy(true);
    setStepUpError(null);
    try {
      const grant = await apiJson('/api/auth/step-up', parseStepUpGrant, {
        method: 'POST',
        body: JSON.stringify({ password: stepUpPassword, code: stepUpCode }),
      });
      const action = pendingAction;
      setPendingAction(null);
      setStepUpPassword('');
      setStepUpCode('');
      if (action === 'totp') {
        await startTOTPSetup(grant.stepUpToken);
      } else {
        await generateRecoveryCodes(grant.stepUpToken);
      }
    } catch (err) {
      setStepUpError(errorMessage(err, 'Re-authentication failed'));
    } finally {
      setStepUpBusy(false);
    }
  };

  // The grant is held only for as long as this flow runs, and is spent by the enable step.
  const [totpGrant, setTotpGrant] = useState('');

  const startTOTPSetup = async (grant: string) => {
    setShowTotpModal(true);
    setTotpError(null);
    setTotpGrant(grant);
    try {
      const data = await apiJson('/api/user/mfa/totp/setup', parseTOTPSetup, {
        method: 'POST',
        stepUpToken: grant,
      });
      setTotpSecret(data.secret);

      if (totpCanvasRef.current) {
        QRCode.toCanvas(totpCanvasRef.current, data.uri, {
          width: 200,
          margin: 1,
          color: { dark: '#0d0f14', light: '#4deeea' },
        });
      }
    } catch (err) {
      setTotpError(errorMessage(err, 'Failed to initialize TOTP'));
    }
  };

  const handleEnableTOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode || totpCode.length < 6) return;

    try {
      const codes = await apiJson('/api/user/mfa/totp/enable', parseRecoveryCodes, {
        method: 'POST',
        body: JSON.stringify({ secret: totpSecret, code: totpCode }),
        stepUpToken: totpGrant,
      });
      setShowTotpModal(false);
      setTotpGrant('');
      setRecoveryCodes(codes);
      setShowRecoveryModal(true);
      onUserUpdate();
    } catch (err) {
      if (isStepUpRequired(err)) {
        setShowTotpModal(false);
        setTotpGrant('');
        requestStepUp('totp');
        return;
      }
      setTotpError(errorMessage(err, 'Invalid code'));
    }
  };

  const generateRecoveryCodes = async (grant: string) => {
    try {
      const codes = await apiJson('/api/user/recovery-codes', parseRecoveryCodes, {
        method: 'POST',
        stepUpToken: grant,
      });
      setRecoveryCodes(codes);
      setShowRecoveryModal(true);
    } catch (err) {
      if (isStepUpRequired(err)) {
        requestStepUp('recovery-codes');
        return;
      }
      alert(errorMessage(err, 'Failed to generate recovery codes'));
    }
  };

  const handleDeleteDevice = async (deviceId: string) => {
    if (!confirm('Are you sure you want to disconnect this device?')) return;
    try {
      await apiRequest(`/api/user/devices/${deviceId}`, { method: 'DELETE' });
      fetchDevices();
    } catch (err) {
      alert(errorMessage(err, 'Failed to delete device'));
    }
  };

  const copyRecoveryCodes = () => {
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="settings-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security & Authenticator Devices</h1>
          <p className="page-subtitle">
            Manage multi-factor authentication, paired mobile devices, and recovery backup keys
          </p>
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <Smartphone className="icon-cyan" size={20} />
            <h2>Paired Authenticator Devices</h2>
          </div>
          <button className="primary-btn sm" onClick={handleStartDevicePairing}>
            <Plus size={14} />
            <span>Pair New Device</span>
          </button>
        </div>

        <p className="section-desc">
          Paired devices receive push notifications for instantaneous sign-in approval with 2-digit number matching. Pairing a different device keeps the devices shown here; pairing the same device identifier updates that device.
        </p>

        <div className="device-list">
          {devices.length === 0 ? (
            <div className="empty-box">
              <Smartphone size={32} className="empty-icon" />
              <p>No paired authenticator devices yet.</p>
              <button className="secondary-btn sm" onClick={handleStartDevicePairing}>
                Pair KySecurity Authenticator
              </button>
            </div>
          ) : (
            devices.map((dev) => (
              <div key={dev.id} className="device-card">
                <div className="device-icon-box">
                  <Smartphone size={20} className="icon-cyan" />
                </div>
                <div className="device-info">
                  <span className="device-name">{dev.deviceName}</span>
                  <span className="device-id-mono">{dev.deviceIdentifier}</span>
                </div>
                <div className="device-status">
                  <span className="badge-approver">
                    <CheckCircle size={12} /> Push Approver
                  </span>
                </div>
                <button
                  className="icon-danger-btn"
                  onClick={() => handleDeleteDevice(dev.id)}
                  title="Remove Device"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <KeyRound className="icon-cyan" size={20} />
            <h2>Time-Based One-Time Password (TOTP)</h2>
          </div>
          <button className="secondary-btn sm" onClick={() => requestStepUp('totp')}>
            <span>Configure TOTP</span>
          </button>
        </div>
        <p className="section-desc">
          {user.mfaMethods?.includes('totp')
            ? 'One TOTP credential is configured for this account. Any authenticator app that scanned its QR code can generate codes; KySignOn cannot see those individual app copies. Configuring TOTP again replaces the current credential and invalidates its existing codes.'
            : 'No TOTP credential is configured. Generate 6-digit codes using a standard authenticator app (e.g., KySecurity Authenticator, Aegis, 1Password).'}
        </p>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <ShieldAlert className="icon-cyan" size={20} />
            <h2>Emergency Recovery Codes</h2>
          </div>
          <button className="secondary-btn sm" onClick={() => requestStepUp('recovery-codes')}>
            <span>Generate New Codes</span>
          </button>
        </div>
        <p className="section-desc">
          One-time backup codes can be used to log in if you lose access to your primary authenticator device.
        </p>
      </div>

      {/* Device Pairing Modal (90s Ephemeral Key / QR) */}
      {pendingAction && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Confirm It's You</h3>
              <button className="close-btn" onClick={() => setPendingAction(null)}>
                ×
              </button>
            </div>
            <form onSubmit={submitStepUp}>
              <div className="modal-body">
                <p className="modal-desc">
                  {pendingAction === 'totp'
                    ? 'Replacing your authenticator changes how this account is protected, so re-enter your credentials first.'
                    : 'New recovery codes invalidate the ones you already stored, so re-enter your credentials first.'}
                </p>

                <label className="field-label" htmlFor="stepup-password">Password</label>
                <input
                  id="stepup-password"
                  type="password"
                  className="text-input"
                  autoComplete="current-password"
                  autoFocus
                  value={stepUpPassword}
                  onChange={(e) => setStepUpPassword(e.target.value)}
                  required
                />

                {hasExistingMFA && (
                  <>
                    <label className="field-label" htmlFor="stepup-code" style={{ marginTop: '0.75rem' }}>
                      Current authenticator code (or a recovery code)
                    </label>
                    <input
                      id="stepup-code"
                      type="text"
                      className="text-input"
                      inputMode="text"
                      autoComplete="one-time-code"
                      placeholder="123456"
                      value={stepUpCode}
                      onChange={(e) => setStepUpCode(e.target.value)}
                    />
                  </>
                )}

                {stepUpError && <div className="form-error">{stepUpError}</div>}
              </div>
              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setPendingAction(null)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={stepUpBusy || !stepUpPassword}>
                  <Lock size={16} />
                  <span>{stepUpBusy ? 'Verifying...' : 'Continue'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showPairModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Pair KySecurity Authenticator</h3>
              <button className="close-btn" onClick={closePairModal}>
                ×
              </button>
            </div>
            <div className="modal-body text-center">
              <p className="modal-desc">
                Open the <strong>KySecurity Authenticator</strong> app on your mobile device and scan the QR code or enter the pairing PIN.
              </p>
              <p className="modal-desc">
                This adds a different device without removing the paired devices listed above. Pairing the same device identifier updates that device.
              </p>

              <div className="qr-container">
                <canvas ref={qrCanvasRef} />
              </div>

              <div className="pin-box">
                <span className="pin-label">PAIRING PIN</span>
                <span className="pin-digits">{pairPin || '••••••'}</span>
              </div>

              <div className="timer-bar-wrap">
                <div className="timer-info">
                  <Clock size={14} className="icon-cyan" />
                  <span>Valid for {countdown}s</span>
                </div>
                <div className="timer-progress-bg">
                  <div
                    className="timer-progress-fill"
                    style={{ width: `${(countdown / 90) * 100}%` }}
                  />
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="secondary-btn" onClick={closePairModal}>
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TOTP Setup Modal */}
      {showTotpModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Configure TOTP Authenticator</h3>
              <button className="close-btn" onClick={() => setShowTotpModal(false)}>
                ×
              </button>
            </div>
            <form onSubmit={handleEnableTOTP} className="modal-body">
              <p className="modal-desc">
                Scan this QR code in your authenticator app, then enter the generated 6-digit verification code below. This replaces the account's current TOTP credential, if any.
              </p>

              <div className="qr-container">
                <canvas ref={totpCanvasRef} />
              </div>

              <div className="secret-key-display">
                <span className="secret-label">Secret:</span>
                <code className="secret-code">{totpSecret}</code>
              </div>

              {totpError && <div className="alert-box error sm">{totpError}</div>}

              <div className="form-group mt-3">
                <label className="form-label">6-Digit Verification Code</label>
                <input
                  type="text"
                  className="form-input text-center text-mono text-large"
                  placeholder="000000"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  autoFocus
                  required
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowTotpModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={totpCode.length < 6}>
                  Verify & Enable
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Recovery Codes Modal */}
      {showRecoveryModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Backup Recovery Codes</h3>
              <button className="close-btn" onClick={() => setShowRecoveryModal(false)}>
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="alert-box warn">
                <ShieldAlert size={16} />
                <span>Save these backup codes securely. Each code can be used exactly once.</span>
              </div>

              <div className="recovery-codes-grid">
                {recoveryCodes.map((c, i) => (
                  <div key={i} className="recovery-code-item">
                    <code>{c}</code>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-footer">
              <button className="secondary-btn" onClick={copyRecoveryCodes}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? 'Copied' : 'Copy All'}</span>
              </button>
              <button className="primary-btn" onClick={() => setShowRecoveryModal(false)}>
                I Have Saved Them
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
