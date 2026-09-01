import { describe, expect, it } from 'vitest';
import { faviconUrl } from './favicon';

describe('faviconUrl', () => {
  it('uses the application origin rather than its launch path', () => {
    expect(faviconUrl('https://portainer.example.test/app/#/home')).toBe(
      'https://portainer.example.test/favicon.ico',
    );
  });

  it('refuses a malformed application URL', () => {
    expect(faviconUrl('not a URL')).toBeUndefined();
  });
});
