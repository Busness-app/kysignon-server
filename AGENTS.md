# KySignOn Server

KySignOn Server is the single-organization SSO provider and central identity authority for the KySecurity Suite of software (KyPost, KyBookmarks, KyNotes, KyPasswords).

## Core Capabilities & Responsibilities

1. **Central User Directory & Replication**: KySignOn is the source of truth for accounts. When an admin creates, updates, or disables an account, it automatically replicates to paired KySecurity products via SCIM 2.0 signed sync events.
2. **UI-Based System Pairing**: Admin generates an ephemeral (90s) pairing key to connect downstream KySecurity product servers and establish mutual HMAC credentials.
3. **OpenID Connect & OAuth 2.0**: Standard authorization-code flow with PKCE, RS256 ID tokens, and JWKS discovery.
4. **Native Device Pairing & Push MFA**: Natively hosts device pairing (`/api/notifications/native/register`) using 90s PIN/QR codes, push challenge dispatch through FCM/APNs relay Workers with 2-digit number matching, and TOTP/recovery code support.
5. **Dashboard & Application Launcher**: KySecurity Patina themed interface (dark `#0d0f14`, cyan `#4deeea`, Space Grotesk, IBM Plex Mono) using `css/styles.css` and local fonts.

## Security Invariants

- Public deployments require an HTTPS issuer and secure session cookies; loopback HTTP is development-only.
- Account creation and updates write their replication outbox events in the same database transaction. The final active administrator cannot be deleted, disabled, or demoted.
- Sensitive API and OAuth responses are `no-store`; registered redirect and launcher URLs must be HTTPS, except loopback HTTP for development.
- Legacy device-pairing tables containing plaintext PINs are rebuilt on startup; their 90-second tokens are intentionally invalidated.
- MFA reset invalidates pending native-device pairing tokens; native registration consumes a live token in the same transaction that creates the approver and push method.
- Native push relay URLs must be HTTPS; relay API keys are runtime secrets loaded from env or generated under the data directory, never committed.
- Sessions have both a configurable absolute lifetime (24h default) and inactivity lifetime (30m default); both are enforced in the store lookup.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Child DOX Index
