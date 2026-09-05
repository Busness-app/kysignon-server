import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchCSRF } from './api';
import { parseStepUpMethods, parseStepUpReply, verifyStepUp } from './stepUp';

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}
function response(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
}
const credentials = { password: 'test password', code: '', method: 'push' as const, operation: 'POST /api/admin/users' };
const challenge = {
  kind: 'challenge', method: 'push', challengeToken: 'opaque',
  expiresAt: new Date(Date.now() + 300_000).toISOString(), matchDigits: '42',
};
async function prepareFetch(reply: Promise<Response>) {
  const fetch = vi.fn()
    .mockResolvedValueOnce(response({ csrfToken: 'csrf' }))
    .mockImplementationOnce(() => reply)
    .mockResolvedValue(response({ success: true }));
  vi.stubGlobal('fetch', fetch);
  await fetchCSRF(true);
  return fetch;
}
describe('step-up cancellation', () => {
  it.each(['grant', 'challenge'])('revokes a late %s without delivering it', async kind => {
    const late = deferred<Response>();
    const fetch = await prepareFetch(late.promise);
    const controller = new AbortController();
    const result = verifyStepUp(credentials, controller.signal, vi.fn());
    const rejected = expect(result).rejects.toThrow('cancelled');
    controller.abort();
    late.resolve(response(kind === 'grant'
      ? { kind, stepUpToken: 'opaque', expiresAt: challenge.expiresAt } : challenge));
    await rejected;
    expect(fetch.mock.calls.at(-1)?.[0]).toBe('/api/auth/step-up/cancel');
    expect(JSON.parse(fetch.mock.calls.at(-1)?.[1].body)).toEqual({ challengeToken: 'opaque' });
  });
  it('revokes a completion that races dismissal', async () => {
    const finish = deferred<Response>();
    const fetch = await prepareFetch(Promise.resolve(response(challenge)));
    fetch.mockImplementationOnce(() => finish.promise);
    const controller = new AbortController();
    const showPush = vi.fn();
    const result = verifyStepUp(credentials, controller.signal, showPush);
    const rejected = expect(result).rejects.toThrow('cancelled');
    await vi.waitFor(() => expect(showPush).toHaveBeenCalledWith('42'));
    controller.abort();
    finish.resolve(response({ kind: 'grant', stepUpToken: 'opaque', expiresAt: challenge.expiresAt }));
    await rejected;
    expect(fetch.mock.calls.at(-1)?.[0]).toBe('/api/auth/step-up/cancel');
  });
  it('delivers a live approved push once', async () => {
    const fetch = await prepareFetch(Promise.resolve(response(challenge)));
    fetch.mockResolvedValueOnce(response({ kind: 'grant', stepUpToken: 'opaque', expiresAt: challenge.expiresAt }));
    await expect(verifyStepUp(credentials, new AbortController().signal, vi.fn())).resolves.toBe('opaque');
    expect(fetch.mock.calls.map(call => call[0])).toEqual([
      '/api/auth/csrf', '/api/auth/step-up', '/api/auth/step-up/finish',
    ]);
  });
});
describe('step-up response boundary', () => {
  it('rejects unknown methods and incomplete challenges', () => {
    expect(() => parseStepUpMethods({ methods: ['password'] })).toThrow();
    expect(() => parseStepUpReply({ ...challenge, expiresAt: 'yesterday' })).toThrow();
    expect(() => parseStepUpReply({ ...challenge, matchDigits: 42 })).toThrow();
    expect(() => parseStepUpReply({ ...challenge, method: 'webauthn' })).toThrow();
    expect(parseStepUpMethods({ methods: ['totp', 'push', 'webauthn', 'recovery'] })).toHaveLength(4);
  });
});
