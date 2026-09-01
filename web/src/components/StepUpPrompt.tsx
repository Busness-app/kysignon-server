import React, { useCallback, useRef, useState } from 'react';
import { Lock } from 'lucide-react';
import { apiJson, errorMessage } from '../api';
import { parseStepUpGrant } from '../parsers';

/**
 * Re-authentication for one destructive or secret-bearing operation.
 *
 * The server spends a step-up grant on every admin route that creates an identity, resets a
 * factor, rotates a secret, or exports recovery material. A stolen session cannot produce
 * one, which is the point: "is this session an admin" is the wrong question for those
 * operations. One grant authorizes exactly one call, so this prompt runs per action rather
 * than once per sitting.
 */
export function useStepUp() {
  const [prompt, setPrompt] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<{
    resolve: (grant: string) => void;
    reject: (reason: Error) => void;
  } | null>(null);

  /** Prompts for credentials and resolves with a single-use grant. Rejects if cancelled. */
  const requestGrant = useCallback((reason: string): Promise<string> => {
    setPassword('');
    setCode('');
    setError(null);
    setPrompt(reason);
    return new Promise<string>((resolve, reject) => {
      pending.current = { resolve, reject };
    });
  }, []);

  const cancel = useCallback(() => {
    pending.current?.reject(new Error('cancelled'));
    pending.current = null;
    setPrompt(null);
    setPassword('');
    setCode('');
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      const grant = await apiJson('/api/auth/step-up', parseStepUpGrant, {
        method: 'POST',
        body: JSON.stringify({ password, code }),
      });
      pending.current?.resolve(grant.stepUpToken);
      pending.current = null;
      setPrompt(null);
      setPassword('');
      setCode('');
    } catch (err) {
      setError(errorMessage(err, 'Re-authentication failed'));
    } finally {
      setBusy(false);
    }
  };

  const element = prompt ? (
    <div className="modal-backdrop step-up-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <h3>Confirm It's You</h3>
          <button className="close-btn" onClick={cancel} aria-label="Cancel">
            ×
          </button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <p className="modal-desc">{prompt}</p>

            <div className="form-group">
              <label className="form-label" htmlFor="admin-stepup-password">
                Password
              </label>
              <input
                id="admin-stepup-password"
                type="password"
                className="form-input"
                autoComplete="current-password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="admin-stepup-code">
                Authenticator code (or a recovery code), if you have one enrolled
              </label>
              <input
                id="admin-stepup-code"
                type="text"
                className="form-input"
                inputMode="text"
                autoComplete="one-time-code"
                placeholder="123456"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>

            {error && (
              <div className="alert-box error" role="alert">
                {error}
              </div>
            )}
          </div>
          <div className="modal-footer">
            <button type="button" className="secondary-btn" onClick={cancel}>
              Cancel
            </button>
            <button type="submit" className="primary-btn" disabled={busy || !password}>
              <Lock size={16} />
              <span>{busy ? 'Verifying...' : 'Continue'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  ) : null;

  return { requestGrant, stepUpPrompt: element };
}

/** True when the user dismissed the prompt rather than failing it. */
export function isCancelled(err: unknown): boolean {
  return err instanceof Error && err.message === 'cancelled';
}
