import React, { useEffect, useState, useRef } from 'react';
import { NativeDevice, User } from '../types';
import { apiRequest } from '../api';
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
} from 'lucide-react';

interface DeviceSettingsProps {
  user: User;
  onUserUpdate: () => void;
}

export const DeviceSettings: React.FC<DeviceSettingsProps> = ({ user, onUserUpdate }) => {
  const [devices, setDevices] = useState<NativeDevice[]>([]);

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

  const fetchDevices = async () => {
    try {
      const data = await apiRequest('/api/user/devices');
      setDevices(data.devices || []);
    } catch {
      // ignore
    }
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
    if (!showPairModal || !pairStartedAt || countdown <= 0) return;

    const interval = setInterval(async () => {
      try {
        const data = await apiRequest('/api/user/devices');
        const nextDevices: NativeDevice[] = data.devices || [];
        setDevices(nextDevices);
        const paired = nextDevices.some((dev) => {
          const seenAt = new Date(dev.lastSeenAt || dev.createdAt).getTime();
          return Number.isFinite(seenAt) && seenAt >= pairStartedAt - 2000;
        });
        if (paired) {
          setShowPairModal(false);
          setPairStartedAt(null);
          onUserUpdate();
        }
      } catch {
        // Keep the QR/PIN visible; the normal countdown still expires it.
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [showPairModal, pairStartedAt, countdown, onUserUpdate]);

  const handleStartDevicePairing = async () => {
    setShowPairModal(true);
    setPairStartedAt(Date.now());
    try {
      const data = await apiRequest('/api/user/devices/pairing-token', { method: 'POST' });
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
    } catch (err: any) {
      alert(err.message || 'Failed to generate pairing token');
      setShowPairModal(false);
    }
  };

  const handleStartTOTPSetup = async () => {
    setShowTotpModal(true);
    setTotpError(null);
    try {
      const data = await apiRequest('/api/user/mfa/totp/setup', { method: 'POST' });
      setTotpSecret(data.secret);

      if (totpCanvasRef.current) {
        QRCode.toCanvas(totpCanvasRef.current, data.uri, {
          width: 200,
          margin: 1,
          color: { dark: '#0d0f14', light: '#4deeea' },
        });
      }
    } catch (err: any) {
      setTotpError(err.message || 'Failed to initialize TOTP');
    }
  };

  const handleEnableTOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode || totpCode.length < 6) return;

    try {
      const data = await apiRequest('/api/user/mfa/totp/enable', {
        method: 'POST',
        body: JSON.stringify({ secret: totpSecret, code: totpCode }),
      });
      setShowTotpModal(false);
      setRecoveryCodes(data.recoveryCodes || []);
      setShowRecoveryModal(true);
      onUserUpdate();
    } catch (err: any) {
      setTotpError(err.message || 'Invalid code');
    }
  };

  const handleGenerateRecoveryCodes = async () => {
    try {
      const data = await apiRequest('/api/user/recovery-codes', { method: 'POST' });
      setRecoveryCodes(data.recoveryCodes || []);
      setShowRecoveryModal(true);
    } catch (err: any) {
      alert(err.message || 'Failed to generate recovery codes');
    }
  };

  const handleDeleteDevice = async (deviceId: string) => {
    if (!confirm('Are you sure you want to disconnect this device?')) return;
    try {
      await apiRequest(`/api/user/devices/${deviceId}`, { method: 'DELETE' });
      fetchDevices();
    } catch (err: any) {
      alert(err.message || 'Failed to delete device');
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
          <button className="secondary-btn sm" onClick={handleStartTOTPSetup}>
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
          <button className="secondary-btn sm" onClick={handleGenerateRecoveryCodes}>
            <span>Generate New Codes</span>
          </button>
        </div>
        <p className="section-desc">
          One-time backup codes can be used to log in if you lose access to your primary authenticator device.
        </p>
      </div>

      {/* Device Pairing Modal (90s Ephemeral Key / QR) */}
      {showPairModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Pair KySecurity Authenticator</h3>
              <button className="close-btn" onClick={() => setShowPairModal(false)}>
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
              <button className="secondary-btn" onClick={() => setShowPairModal(false)}>
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
