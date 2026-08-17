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
  redirectUrisJson: string;
  allowedScopesJson: string;
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
