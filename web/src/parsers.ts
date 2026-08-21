/**
 * Parsers for every API response the UI consumes.
 *
 * These exist because an identity UI's failure paths have to be deterministic. A response
 * that changed shape, or an error body arriving where a success body was expected, must fail
 * here with a legible message rather than reaching a component that dereferences a field the
 * server never sent.
 */
import { isRecord } from './api';
import type {
  Application,
  AuditEvent,
  BackupDrillResult,
  BackupStatus,
  NativeDevice,
  OAuthClient,
  PairedSystem,
  RecoveryKit,
  User,
} from './types';

function fail(what: string): never {
  throw new Error(`expected ${what}`);
}

function obj(value: unknown, what: string): Record<string, unknown> {
  return isRecord(value) ? value : fail(what);
}

function str(source: Record<string, unknown>, key: string): string {
  const v = source[key];
  return typeof v === 'string' ? v : fail(`string field "${key}"`);
}

function optStr(source: Record<string, unknown>, key: string): string | undefined {
  const v = source[key];
  return typeof v === 'string' ? v : undefined;
}

function num(source: Record<string, unknown>, key: string): number {
  const v = source[key];
  return typeof v === 'number' ? v : fail(`number field "${key}"`);
}

function bool(source: Record<string, unknown>, key: string): boolean {
  return source[key] === true;
}

function arr(value: unknown, what: string): unknown[] {
  return Array.isArray(value) ? value : fail(what);
}

function strArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string');
}

/** Reads an array that the server may omit entirely when empty. */
function list<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (value === null || value === undefined) return [];
  return arr(value, 'an array').map(parse);
}

export function parseUser(value: unknown): User {
  const o = obj(value, 'a user object');
  const role = o.role === 'admin' ? 'admin' : 'user';
  return {
    id: str(o, 'id'),
    username: str(o, 'username'),
    displayName: optStr(o, 'displayName') ?? str(o, 'username'),
    email: optStr(o, 'email') ?? '',
    role,
    status: o.status === 'disabled' ? 'disabled' : 'active',
    mfaMethods: strArray(o.mfaMethods),
    createdAt: optStr(o, 'createdAt'),
  };
}

export function parseUsers(value: unknown): User[] {
  const o = obj(value, 'a users response');
  return list(o.users, parseUser);
}

/** /api/auth/me returns the user either bare or wrapped. */
export function parseMe(value: unknown): User {
  const o = obj(value, 'an auth response');
  return parseUser(isRecord(o.user) ? o.user : o);
}

export function parseDevice(value: unknown): NativeDevice {
  const o = obj(value, 'a device object');
  return {
    id: str(o, 'id'),
    userId: optStr(o, 'userId') ?? '',
    deviceName: optStr(o, 'deviceName') ?? 'Unnamed device',
    deviceIdentifier: optStr(o, 'deviceIdentifier') ?? '',
    platform: optStr(o, 'platform'),
    pushToken: optStr(o, 'pushToken'),
    isMfaApprover: bool(o, 'isMfaApprover'),
    lastSeenAt: optStr(o, 'lastSeenAt'),
    createdAt: optStr(o, 'createdAt') ?? '',
  };
}

export function parseDevices(value: unknown): NativeDevice[] {
  const o = obj(value, 'a devices response');
  return list(o.devices, parseDevice);
}

export interface PairingToken {
  pairingToken: string;
  pinCode: string;
  qrPayload: string;
  expiresAt: number;
}

export function parsePairingToken(value: unknown): PairingToken {
  const o = obj(value, 'a pairing token response');
  return {
    pairingToken: str(o, 'pairingToken'),
    pinCode: optStr(o, 'pinCode') ?? '',
    qrPayload: optStr(o, 'qrPayload') ?? '',
    expiresAt: typeof o.expiresAt === 'number' ? o.expiresAt : 0,
  };
}

export interface TOTPSetup {
  secret: string;
  uri: string;
}

export function parseTOTPSetup(value: unknown): TOTPSetup {
  const o = obj(value, 'a TOTP setup response');
  return { secret: str(o, 'secret'), uri: str(o, 'uri') };
}

export function parseRecoveryCodes(value: unknown): string[] {
  const o = obj(value, 'a recovery codes response');
  const codes = strArray(o.recoveryCodes);
  return codes.length > 0 ? codes : fail('a non-empty recoveryCodes array');
}

export interface StepUpGrant {
  stepUpToken: string;
  expiresAt: string;
}

export function parseStepUpGrant(value: unknown): StepUpGrant {
  const o = obj(value, 'a step-up response');
  return { stepUpToken: str(o, 'stepUpToken'), expiresAt: optStr(o, 'expiresAt') ?? '' };
}

export function parseApplications(value: unknown): Application[] {
  const o = obj(value, 'an applications response');
  return list(o.applications, (item) => {
    const a = obj(item, 'an application object');
    return {
      id: str(a, 'id'),
      name: str(a, 'name'),
      url: optStr(a, 'url') ?? '',
      iconName: optStr(a, 'iconName') ?? '',
      description: optStr(a, 'description'),
      sortOrder: typeof a.sortOrder === 'number' ? a.sortOrder : undefined,
      enabled: a.enabled !== false,
    };
  });
}

export function parsePairedSystems(value: unknown): PairedSystem[] {
  const o = obj(value, 'a systems response');
  return list(o.systems, (item) => {
    const s = obj(item, 'a paired system object');
    const status = s.status === 'failing' || s.status === 'disabled' ? s.status : 'active';
    return {
      id: str(s, 'id'),
      name: str(s, 'name'),
      systemType: optStr(s, 'systemType') ?? 'custom',
      description: optStr(s, 'description'),
      iconUrl: optStr(s, 'iconUrl'),
      callbackUrl: optStr(s, 'callbackUrl') ?? '',
      status,
      lastSyncedAt: optStr(s, 'lastSyncedAt'),
      createdAt: optStr(s, 'createdAt') ?? '',
    };
  });
}

export interface CreatedSystem {
  system: PairedSystem;
  bearerToken: string;
}

export function parseCreatedSystem(value: unknown): CreatedSystem {
  const o = obj(value, 'a created system response');
  return {
    system: parsePairedSystems({ systems: [o.system] })[0],
    bearerToken: optStr(o, 'bearerToken') ?? '',
  };
}

export function parseOAuthClients(value: unknown): OAuthClient[] {
  const o = obj(value, 'a clients response');
  return list(o.clients, (item) => {
    const c = obj(item, 'a client object');
    return {
      id: str(c, 'id'),
      clientName: optStr(c, 'clientName') ?? str(c, 'id'),
      clientType: c.clientType === 'confidential' ? 'confidential' : 'public',
      redirectUrisJson: optStr(c, 'redirectUrisJson') ?? '[]',
      allowedScopesJson: optStr(c, 'allowedScopesJson') ?? '[]',
      launchUrl: optStr(c, 'launchUrl'),
      enabled: c.enabled !== false,
      createdAt: optStr(c, 'createdAt') ?? '',
    };
  });
}

export function parseCreatedClientSecret(value: unknown): string | undefined {
  const o = obj(value, 'a created client response');
  return optStr(o, 'clientSecret');
}

export interface AuditPage {
  events: AuditEvent[];
  total: number;
}

export function parseAuditPage(value: unknown): AuditPage {
  const o = obj(value, 'an audit response');
  const events = list(o.auditEvents, (item) => {
    const e = obj(item, 'an audit event');
    const outcome =
      e.outcome === 'failure' || e.outcome === 'denied' ? e.outcome : 'success';
    return {
      id: str(e, 'id'),
      actorId: optStr(e, 'actorId'),
      actorUsername: optStr(e, 'actorUsername'),
      action: str(e, 'action'),
      targetId: optStr(e, 'targetId'),
      targetType: optStr(e, 'targetType'),
      ipAddress: optStr(e, 'ipAddress') ?? '',
      userAgent: optStr(e, 'userAgent') ?? '',
      outcome,
      detailsJson: optStr(e, 'detailsJson'),
      createdAt: optStr(e, 'createdAt') ?? '',
    } satisfies AuditEvent;
  });
  return { events, total: typeof o.total === 'number' ? o.total : events.length };
}

export function parseBackupStatus(value: unknown): BackupStatus {
  const o = obj(value, 'a backup status response');
  return {
    paired: bool(o, 'paired'),
    recovery_url: optStr(o, 'recovery_url'),
    app_name: optStr(o, 'app_name') ?? 'KySignOn',
    app_version: optStr(o, 'app_version') ?? '',
  };
}

export function parseDrillResult(value: unknown): BackupDrillResult {
  const o = obj(value, 'a drill result');
  return {
    passed: bool(o, 'passed'),
    duration_ms: typeof o.duration_ms === 'number' ? o.duration_ms : 0,
    checks: list(o.checks, (item) => {
      const c = obj(item, 'a drill check');
      return {
        name: str(c, 'name'),
        passed: bool(c, 'passed'),
        message: optStr(c, 'message') ?? '',
      };
    }),
    error_message: optStr(o, 'error_message'),
  };
}

export function parseRecoveryKit(value: unknown): RecoveryKit {
  const o = obj(value, 'a recovery kit response');
  return {
    kitId: str(o, 'kit_id'),
    capsuleId: str(o, 'capsule_id'),
    payloadHash: optStr(o, 'payload_hash') ?? '',
    threshold: num(o, 'threshold'),
    totalShares: num(o, 'total_shares'),
    capsuleSize: num(o, 'capsule_size'),
    expiresAt: optStr(o, 'expires_at') ?? '',
    shards: list(o.shards, (item) => {
      const s = obj(item, 'a shard entry');
      return {
        index: num(s, 'index'),
        collected: bool(s, 'collected'),
        heldBySelf: bool(s, 'heldBySelf'),
      };
    }),
    maxPerCustodian: num(o, 'max_per_custodian'),
    soleCustodian: bool(o, 'sole_custodian'),
  };
}

export interface PushResult {
  capsuleId: string;
  sizeBytes: number;
}

export function parsePushResult(value: unknown): PushResult {
  const o = obj(value, 'a backup push response');
  return {
    capsuleId: optStr(o, 'capsule_id') ?? '',
    sizeBytes: typeof o.size_bytes === 'number' ? o.size_bytes : 0,
  };
}

/** Login and MFA responses share a status-plus-optional-user shape. */
/** Mirrors the server's LoginResponse, which every MFA step also answers with. */
export interface AuthStep {
  success: boolean;
  user?: User;
  mfaRequired: boolean;
  mfaMethods: string[];
  mfaToken?: string;
  challengeId?: string;
  matchDigits?: string;
  decoyDigits: string[];
}

export function parseAuthStep(value: unknown): AuthStep {
  const o = obj(value, 'an authentication response');
  return {
    success: bool(o, 'success'),
    user: isRecord(o.user) ? parseUser(o.user) : undefined,
    mfaRequired: o.mfaRequired === true,
    mfaMethods: strArray(o.mfaMethods),
    mfaToken: optStr(o, 'mfaToken'),
    challengeId: optStr(o, 'challengeId'),
    matchDigits: optStr(o, 'matchDigits'),
    decoyDigits: strArray(o.decoyDigits),
  };
}

/** The push-challenge poll answers with a bare status. */
export function parsePushStatus(value: unknown): string {
  const o = obj(value, 'a push poll response');
  return str(o, 'status');
}
