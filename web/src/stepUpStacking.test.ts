import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The step-up prompt is opened from inside a feature modal that stays mounted — Register
 * Client asks for a grant without closing its own form. Both use `.modal-backdrop`, which
 * covers the viewport opaquely, so if the prompt does not outrank the modal it is buried:
 * invisible, unclickable, and the grant promise never settles. The action silently does
 * nothing.
 */
const css = readFileSync(new URL('./index.css', import.meta.url), 'utf8');
const stepUp = readFileSync(new URL('./components/StepUpPrompt.tsx', import.meta.url), 'utf8');

function zIndexOf(selector: string): number {
  const rule = new RegExp(`\\${selector}\\s*\\{([^}]*)\\}`).exec(css);
  expect(rule, `${selector} has no rule in index.css`).not.toBeNull();
  const z = /z-index:\s*(\d+)/.exec(rule![1]);
  expect(z, `${selector} declares no z-index`).not.toBeNull();
  return Number(z![1]);
}

describe('step-up prompt stacking', () => {
  it('carries the raised backdrop class', () => {
    expect(stepUp).toContain('className="modal-backdrop step-up-backdrop"');
  });

  it('outranks the modals it is opened from', () => {
    expect(zIndexOf('.step-up-backdrop')).toBeGreaterThan(zIndexOf('.modal-backdrop'));
  });
});
