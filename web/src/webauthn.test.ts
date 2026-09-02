import { describe, expect, it } from 'vitest';
import { fromBase64Url, toBase64Url } from './webauthn';

describe('base64url codecs', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(Array.from(fromBase64Url(toBase64Url(bytes.buffer)))).toEqual(Array.from(bytes));
  });

  it('emits no padding and no standard-alphabet characters', () => {
    // The server compares the challenge as an exact string. Padding or +/ would not match.
    const bytes = new Uint8Array([251, 255, 190, 254]);
    const encoded = toBase64Url(bytes.buffer);
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });

  it('decodes a string the server would have produced', () => {
    expect(new TextDecoder().decode(fromBase64Url('Q0hBTExFTkdF'))).toBe('CHALLENGE');
  });
});
