# KySignOn Server

KySignOn Server is the single-organization SSO provider and central identity authority for the KySecurity Suite of software (KyPost, KyBookmarks, KyNotes, KyPasswords).

## Core Capabilities & Responsibilities

1. **Central User Directory & Replication**: KySignOn is the source of truth for accounts. When an admin creates, updates, or disables an account, it automatically replicates to paired KySecurity products via SCIM 2.0 signed sync events.
2. **Direct SCIM 2.0 Service Connection**: Admin configures downstream KySecurity and 3rd-party product servers directly with their SCIM Base URL and Bearer token for automated RESTful CRUD replication.
3. **OpenID Connect & OAuth 2.0**: Standard authorization-code flow with PKCE, RS256 ID tokens, and JWKS discovery.
4. **Native Device Pairing & Push MFA**: Natively hosts device pairing (`/api/notifications/native/register`) using 90s PIN/QR codes, push challenge dispatch through FCM/APNs relay Workers with 2-digit number matching, and TOTP/recovery code support.
5. **Dashboard & Application Launcher**: KySecurity Patina themed interface (dark `#0d0f14`, cyan `#4deeea`, Space Grotesk, IBM Plex Mono) using `css/styles.css` and local fonts.
   The client table exposes each app's copyable OIDC connection details from the configured issuer, including its client ID, human-readable `username` claim, and compatible credential style; it never displays stored secret hashes or claims a browser-compatible logout endpoint exists.
   Administrators can add non-KySecurity launcher applications and select a built-in icon or an HTTPS site favicon; favicon loading stays in the browser rather than creating a server-side fetch path.
6. **Disaster Recovery & KyBackup (Feature 0)**: Encrypted capsule container creation (`.kycap`), Shamir Secret Sharing $(k=2, n=3)$ custodian key distribution, automated sandboxed live restore drills, offline HTML emergency recovery kit generation, and remote KyRecovery pairing.

## Security Invariants

- Public deployments require an HTTPS issuer and secure session cookies; loopback HTTP is development-only.
- Account creation and updates write their replication outbox events in the same database transaction. The final active administrator cannot be deleted, disabled, or demoted.
- Sensitive API and OAuth responses are `no-store`; registered redirect and launcher URLs must be HTTPS, except loopback HTTP for development.
- Legacy device-pairing tables containing plaintext PINs are rebuilt on startup; their 90-second tokens are intentionally invalidated.
- MFA reset invalidates pending native-device pairing tokens; native registration consumes a live token in the same transaction that creates the approver and push method.
- Native push relay URLs must be HTTPS; relay API keys are runtime secrets loaded from env or generated under the data directory, never committed.
- FCM token refreshes are authenticated by the enrolled device P-256 key, bound to the configured issuer and a fresh monotonic timestamp, and atomically persisted with their audit event; push tokens are never credentials.
- The step-up prompt outranks the modals it is opened from (`.step-up-backdrop`); a grant request painted under its caller silently cancels the action it was meant to protect.
- A client secret is shown once and rotated in place from the clients table; rotation revokes that client's outstanding tokens, so delete-and-recreate is never the recovery path for a lost secret.
- Sessions have both a configurable absolute lifetime (24h default) and inactivity lifetime (30m default); both are enforced in the store lookup.

## WebAuthn

`internal/webauthn` is pure verification: no database, no HTTP, no CBOR. It reads the SPKI
public key and raw authenticator data the browser exports, because attestation is not
verified and re-deriving those from the attestation object would buy nothing.

KySignOn records whether a passkey is backup-eligible but never rejects one for it. The rule
that a KySignOn login credential must live in KyAuth's device-local `totp_vault.kdbx` rather
than the KyPasswords-synced `passwords_vault.kdbx` is enforced in KyAuth, where the vault is
chosen.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

## Verification

- CI runs Go formatting, build, vet, vulnerability scanning, and race-enabled tests.
- CI builds, audits, and tests the web app, and rejects stale committed `web/dist` assets.
- CI audits and typechecks both push Workers and runs their shared and provider behavior tests.
- CI builds the production image, probes `/readyz`, and verifies public HTTP issuers fail closed.

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

- [internal/backup/AGENTS.md](file:///home/yoshi/busness.app/kysignon-server/internal/backup/AGENTS.md): Feature 0 disaster recovery, container encapsulation (.kycap), Shamir Secret Sharing, automated restore drills, and KyRecovery integration.
