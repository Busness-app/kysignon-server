import React, { useState, useEffect } from 'react';
import { apiRequest } from '../api';
import { Shield, Smartphone, KeyRound, ArrowRight, RefreshCw, AlertCircle } from 'lucide-react';

interface LoginViewProps {
  onLoginSuccess: (user: any) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA State
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaMode, setMfaMode] = useState<'push' | 'totp' | 'recovery'>('push');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [challengeId, setChallengeId] = useState('');
  const [matchDigits, setMatchDigits] = useState('');

  const returnTo = new URLSearchParams(window.location.search).get('return_to');

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) return;

    setLoading(true);
    setError(null);

    try {
      const resp = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });

      if (resp.mfaRequired) {
        setMfaRequired(true);
        setMfaToken(resp.mfaToken);
        if (resp.challengeId && resp.matchDigits) {
          setChallengeId(resp.challengeId);
          setMatchDigits(resp.matchDigits);
          setMfaMode('push');
        } else {
          setMfaMode('totp');
        }
      } else if (resp.success) {
        finishLogin(resp.user);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const finishLogin = (user: any) => {
    if (returnTo) {
      window.location.href = decodeURIComponent(returnTo);
    } else {
      onLoginSuccess(user);
    }
  };

  // Push Challenge Poller
  useEffect(() => {
    if (!mfaRequired || mfaMode !== 'push' || !challengeId) return;

    let isMounted = true;
    const interval = setInterval(async () => {
      try {
        const poll = await apiRequest('/api/auth/mfa/push/poll', {
          method: 'POST',
          body: JSON.stringify({ challengeId }),
        });

        if (!isMounted) return;

        if (poll.status === 'approved') {
          clearInterval(interval);
          // Complete login
          const finish = await apiRequest('/api/auth/mfa/push/finish', {
            method: 'POST',
            body: JSON.stringify({ mfaToken, challengeId }),
          });
          if (finish.success) {
            finishLogin(finish.user);
          }
        } else if (poll.status === 'denied' || poll.status === 'expired') {
          clearInterval(interval);
          setError(`Push challenge ${poll.status}. Please try again or use TOTP.`);
        }
      } catch {
        // keep polling
      }
    }, 2000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [mfaRequired, mfaMode, challengeId, mfaToken]);

  const handleTOTPSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode || totpCode.length < 6) return;

    setLoading(true);
    setError(null);

    try {
      const resp = await apiRequest('/api/auth/mfa/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ mfaToken, code: totpCode }),
      });
      if (resp.success) {
        finishLogin(resp.user);
      }
    } catch (err: any) {
      setError(err.message || 'Invalid TOTP code');
    } finally {
      setLoading(false);
    }
  };

  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoveryCode) return;

    setLoading(true);
    setError(null);

    try {
      const resp = await apiRequest('/api/auth/mfa/recovery/verify', {
        method: 'POST',
        body: JSON.stringify({ mfaToken, code: recoveryCode }),
      });
      if (resp.success) {
        finishLogin(resp.user);
      }
    } catch (err: any) {
      setError(err.message || 'Invalid recovery code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <div className="login-logo">
            <Shield className="icon-cyan" size={32} />
          </div>
          <h1 className="login-title">KySignOn</h1>
          <p className="login-subtitle">KySecurity Suite Single Sign-On</p>
        </div>

        {error && (
          <div className="alert-box error">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {!mfaRequired ? (
          <form onSubmit={handlePasswordSubmit} className="login-form">
            <div className="form-group">
              <label className="form-label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                type="text"
                className="form-input"
                placeholder="e.g. alice"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                className="form-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <button type="submit" className="primary-btn full-width" disabled={loading}>
              {loading ? <RefreshCw className="spin" size={16} /> : <span>Sign In</span>}
              {!loading && <ArrowRight size={16} />}
            </button>
          </form>
        ) : (
          <div className="mfa-challenge-container">
            {mfaMode === 'push' && (
              <div className="mfa-push-box">
                <div className="push-icon-circle">
                  <Smartphone size={28} className="icon-cyan" />
                </div>
                <h3>Authenticator Challenge</h3>
                <p className="mfa-desc">
                  Open your <strong>KySecurity Authenticator</strong> app and tap the matching number:
                </p>
                <div className="match-digits-display">
                  <span className="match-digits">{matchDigits}</span>
                </div>
                <div className="poll-status">
                  <RefreshCw className="spin icon-cyan" size={14} />
                  <span>Waiting for mobile approval...</span>
                </div>
                <div className="mfa-alt-links">
                  <button type="button" className="text-btn" onClick={() => setMfaMode('totp')}>
                    Use 6-digit TOTP code instead
                  </button>
                </div>
              </div>
            )}

            {mfaMode === 'totp' && (
              <form onSubmit={handleTOTPSubmit} className="login-form">
                <div className="push-icon-circle">
                  <KeyRound size={28} className="icon-cyan" />
                </div>
                <h3>Enter Authenticator Code</h3>
                <p className="mfa-desc">Provide the 6-digit code from your authenticator app.</p>

                <div className="form-group">
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    className="form-input text-center text-mono text-large"
                    placeholder="000000"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    autoFocus
                    required
                  />
                </div>

                <button type="submit" className="primary-btn full-width" disabled={loading || totpCode.length < 6}>
                  {loading ? <RefreshCw className="spin" size={16} /> : <span>Verify & Continue</span>}
                </button>

                <div className="mfa-alt-links">
                  {matchDigits && (
                    <button type="button" className="text-btn" onClick={() => setMfaMode('push')}>
                      Switch back to Push notification
                    </button>
                  )}
                  <button type="button" className="text-btn" onClick={() => setMfaMode('recovery')}>
                    Use emergency recovery code
                  </button>
                </div>
              </form>
            )}

            {mfaMode === 'recovery' && (
              <form onSubmit={handleRecoverySubmit} className="login-form">
                <h3>Emergency Recovery Code</h3>
                <p className="mfa-desc">Enter an unused 8-character recovery code.</p>

                <div className="form-group">
                  <input
                    type="text"
                    className="form-input text-center text-mono"
                    placeholder="XXXX-XXXX"
                    value={recoveryCode}
                    onChange={(e) => setRecoveryCode(e.target.value)}
                    autoFocus
                    required
                  />
                </div>

                <button type="submit" className="primary-btn full-width" disabled={loading || !recoveryCode}>
                  {loading ? <RefreshCw className="spin" size={16} /> : <span>Redeem Recovery Code</span>}
                </button>

                <div className="mfa-alt-links">
                  <button type="button" className="text-btn" onClick={() => setMfaMode('totp')}>
                    Back to TOTP code
                  </button>
                </div>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
