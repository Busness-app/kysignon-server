export interface User {
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: 'user' | 'admin';
  status?: 'active' | 'disabled';
  mfaMethods?: string[];
  createdAt?: string;
}

export interface PairedSystem {
  id: string;
  name: string;
  systemType: string;
  description?: string;
  iconUrl?: string;
  callbackUrl: string;
  status: 'active' | 'failing' | 'disabled';
  lastSyncedAt?: string;
  createdAt: string;
}

export interface NativeDevice {
  id: string;
  userId: string;
  deviceName: string;
  deviceIdentifier: string;
  platform?: string;
  pushToken?: string;
  isMfaApprover: boolean;
  lastSeenAt?: string;
  createdAt: string;
}

export interface Application {
  id: string;
  /** Where the card came from, which decides the endpoint that edits it. */
  source?: 'client' | 'custom';
  name: string;
  url: string;
  iconName: string;
  description?: string;
  sortOrder?: number;
  enabled: boolean;
}

export interface OAuthClient {
  id: string;
  clientName: string;
  clientType: 'public' | 'confidential';
  redirectUris: string[];
  allowedScopes: string[];
  launchUrl?: string;
  enabled: boolean;
  createdAt: string;
}

export interface AuditEvent {
  id: string;
  actorId?: string;
  actorUsername?: string;
  action: string;
  targetId?: string;
  targetType?: string;
  ipAddress: string;
  userAgent: string;
  outcome: 'success' | 'failure' | 'denied';
  detailsJson?: string;
  createdAt: string;
}

export interface BackupDrillCheck {
  name: string;
  passed: boolean;
  message: string;
}

export interface BackupDrillResult {
  passed: boolean;
  duration_ms: number;
  checks: BackupDrillCheck[];
  error_message?: string;
}

export interface BackupStatus {
  paired: boolean;
  recovery_url?: string;
  app_name: string;
  app_version: string;
}


export interface RecoveryShard {
  index: number;
  collected: boolean;
  /** True when this administrator is the one already holding the shard. */
  heldBySelf: boolean;
}

/**
 * A pending recovery kit. The capsule and each shard are collected separately, so this
 * carries only metadata — never key material.
 */
export interface RecoveryKit {
  kitId: string;
  capsuleId: string;
  payloadHash: string;
  threshold: number;
  totalShares: number;
  capsuleSize: number;
  expiresAt: string;
  shards: RecoveryShard[];
  /** The most shards one administrator may hold without being able to rebuild the key. */
  maxPerCustodian: number;
  /** True when this deployment has a single administrator, so custody cannot be split. */
  soleCustodian: boolean;
}
