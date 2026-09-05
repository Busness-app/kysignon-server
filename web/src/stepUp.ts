import { apiJson, apiRequest, isRecord } from './api';
import { parseBeginLogin, parseStepUpGrant } from './parsers';
import { getPasskeyAssertion, type BeginLogin } from './webauthn';

export type StepUpMethod = 'totp' | 'push' | 'webauthn' | 'recovery';
export const methodLabels: Record<StepUpMethod, string> = {
  totp: 'Authenticator code', push: 'Approve on your phone',
  webauthn: 'Passkey', recovery: 'Recovery code (replacement factor only)',
};
function method(value: unknown): StepUpMethod {
  if (value === 'totp' || value === 'push' || value === 'webauthn' || value === 'recovery') return value;
  throw new Error('Unknown verification method');
}
export function parseStepUpMethods(value: unknown): StepUpMethod[] {
  if (!isRecord(value) || !Array.isArray(value.methods)) throw new Error('Invalid verification methods');
  return value.methods.map(method);
}
type Reply =
  | { kind: 'grant'; stepUpToken: string; expiresAt: string }
  | { kind: 'pending' }
  | { kind: 'challenge'; challengeToken: string; expiresAt: string; method: 'push'; matchDigits: string }
  | { kind: 'challenge'; challengeToken: string; expiresAt: string; method: 'webauthn'; passkey: BeginLogin };
export function parseStepUpReply(value: unknown): Reply {
  if (!isRecord(value)) throw new Error('Invalid verification response');
  if (value.kind === 'grant') return { kind: 'grant', ...parseStepUpGrant(value) };
  if (value.kind === 'pending') return { kind: 'pending' };
  if (value.kind === 'challenge' && typeof value.challengeToken === 'string' && value.challengeToken &&
      typeof value.expiresAt === 'string' && Number.isFinite(Date.parse(value.expiresAt))) {
    const common = { kind: 'challenge' as const, challengeToken: value.challengeToken, expiresAt: value.expiresAt };
    if (value.method === 'push' && typeof value.matchDigits === 'string' && /^\d{2}$/.test(value.matchDigits)) {
      return { ...common, method: 'push', matchDigits: value.matchDigits };
    }
    if (value.method === 'webauthn') return { ...common, method: 'webauthn', passkey: parseBeginLogin(value.passkey) };
  }
  throw new Error('Invalid verification response');
}
export async function cancelStepUp(token: string): Promise<void> {
  await apiRequest('/api/auth/step-up/cancel', {
    method: 'POST', body: JSON.stringify({ challengeToken: token }),
  });
}

/** Keep receiving responses after dismissal so even a late-created grant can be revoked. */
export async function verifyStepUp(
  credentials: { password: string; code: string; method: StepUpMethod | ''; operation: string },
  signal: AbortSignal,
  showPush: (digits: string) => void,
): Promise<string> {
  let token = '';
  let delivered = false;
  const check = () => { if (signal.aborted) throw new Error('cancelled'); };
  try {
    let reply = await apiJson('/api/auth/step-up', parseStepUpReply, {
      method: 'POST', body: JSON.stringify(credentials),
    });
    if (reply.kind === 'pending') throw new Error('Unexpected pending response');
    token = reply.kind === 'grant' ? reply.stepUpToken : reply.challengeToken;
    check();
    if (reply.kind === 'challenge') {
      const challenge = reply;
      const assertion = challenge.method === 'webauthn'
        ? await getPasskeyAssertion(challenge.passkey, signal) : undefined;
      if (challenge.method === 'push') showPush(challenge.matchDigits);
      do {
        check();
        if (Date.now() >= Date.parse(challenge.expiresAt)) throw new Error('Verification expired; try again');
        reply = await apiJson('/api/auth/step-up/finish', parseStepUpReply, {
          method: 'POST', body: JSON.stringify({ challengeToken: token, assertion }),
        });
        check();
        if (reply.kind === 'pending') await new Promise(resolve => setTimeout(resolve, 1000));
      } while (reply.kind === 'pending');
    }
    check();
    if (reply.kind !== 'grant') throw new Error('Verification did not produce a grant');
    delivered = true;
    return reply.stepUpToken;
  } finally {
    if (token && !delivered) await cancelStepUp(token).catch(() => {});
  }
}
