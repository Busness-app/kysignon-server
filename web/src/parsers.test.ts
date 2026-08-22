import { describe, expect, it } from 'vitest';
import {
  parseAuditPage,
  parseAuthStep,
  parseMe,
  parseOAuthClients,
  parsePairedSystems,
  parseUsers,
} from './parsers';

const user = {
  id: 'u1',
  username: 'ada',
  displayName: 'Ada',
  email: 'ada@x.test',
  role: 'admin',
  status: 'active',
};

describe('parseUser', () => {
  it('reads a well-formed user', () => {
    const parsed = parseMe(user);
    expect(parsed.role).toBe('admin');
    expect(parsed.status).toBe('active');
  });

  it('accepts the wrapped shape /api/auth/me may return', () => {
    expect(parseMe({ user }).username).toBe('ada');
  });

  // A security state the UI does not understand must not be rendered as a safe one. If the
  // API grows `locked` or `pending`, showing that account as active is worse than failing.
  it.each(['locked', 'pending', '', undefined, null, 'ADMIN'])(
    'refuses the unknown status %p rather than defaulting to active',
    (status) => {
      expect(() => parseMe({ ...user, status })).toThrow(/status/);
    },
  );

  it.each(['superuser', 'root', '', undefined, null])(
    'refuses the unknown role %p rather than defaulting to user',
    (role) => {
      expect(() => parseMe({ ...user, role })).toThrow(/role/);
    },
  );

  // The specific bug this guards: an error body reaching a parser that shrugs and invents
  // a valid account.
  it('refuses an error body where a user was expected', () => {
    expect(() => parseMe({ error: 'unauthorized' })).toThrow();
  });

  it('rejects a users list containing one malformed entry', () => {
    expect(() => parseUsers({ users: [user, { ...user, role: 'wizard' }] })).toThrow(/role/);
  });

  it('treats an omitted users array as empty rather than failing', () => {
    expect(parseUsers({})).toEqual([]);
  });
});

describe('parseOAuthClients', () => {
  const client = {
    id: 'c1',
    clientName: 'App',
    clientType: 'confidential',
    redirectUrisJson: '[]',
    allowedScopesJson: '[]',
  };

  it('reads a well-formed client', () => {
    expect(parseOAuthClients({ clients: [client] })[0].clientType).toBe('confidential');
  });

  // Defaulting an unknown type to `public` silently downgrades how the UI describes the
  // client's authentication.
  it.each(['native', '', undefined])('refuses the unknown client type %p', (clientType) => {
    expect(() => parseOAuthClients({ clients: [{ ...client, clientType }] })).toThrow(
      /clientType/,
    );
  });
});

describe('parsePairedSystems', () => {
  const system = { id: 's1', name: 'S', callbackUrl: 'https://x.test', status: 'failing' };

  it('reads every known status', () => {
    for (const status of ['active', 'failing', 'disabled']) {
      expect(parsePairedSystems({ systems: [{ ...system, status }] })[0].status).toBe(status);
    }
  });

  it('refuses an unknown system status rather than reporting it active', () => {
    expect(() => parsePairedSystems({ systems: [{ ...system, status: 'paused' }] })).toThrow(
      /status/,
    );
  });
});

describe('parseAuditPage', () => {
  const event = {
    id: 'e1',
    action: 'admin.user_deleted',
    outcome: 'denied',
    ipAddress: '1.2.3.4',
    userAgent: 'test',
    createdAt: 'now',
  };

  it('preserves a denied outcome', () => {
    expect(parseAuditPage({ auditEvents: [event], total: 1 }).events[0].outcome).toBe('denied');
  });

  // Rendering an unrecognised outcome as "success" turns the audit view into a source of
  // false assurance, which is the one thing it may never be.
  it('refuses an unknown outcome rather than showing it as success', () => {
    expect(() => parseAuditPage({ auditEvents: [{ ...event, outcome: 'partial' }] })).toThrow(
      /outcome/,
    );
  });

  it('falls back to the event count when total is missing', () => {
    expect(parseAuditPage({ auditEvents: [event] }).total).toBe(1);
  });
});

describe('parseAuthStep', () => {
  it('reads an MFA challenge', () => {
    const step = parseAuthStep({
      success: false,
      mfaRequired: true,
      mfaMethods: ['totp', 'push'],
      mfaToken: 't',
      challengeId: 'c',
      matchDigits: '42',
      decoyDigits: ['11', '99'],
    });
    expect(step).toMatchObject({
      success: false,
      mfaRequired: true,
      mfaMethods: ['totp', 'push'],
      matchDigits: '42',
    });
    expect(step.user).toBeUndefined();
  });

  it('parses the user on a completed login', () => {
    expect(parseAuthStep({ success: true, user }).user?.role).toBe('admin');
  });

  // A login response carrying a user the parser cannot validate must fail the login, not
  // sign the operator in as an invented account.
  it('fails a login whose user carries an unknown role', () => {
    expect(() => parseAuthStep({ success: true, user: { ...user, role: 'wizard' } })).toThrow(
      /role/,
    );
  });
});
