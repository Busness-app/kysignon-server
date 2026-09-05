# KySignOn Server

KySignOn Server is the single-organization SSO provider and central identity authority for the KySecurity Suite of software (KyPost, KyBookmarks, KyNotes, KyPasswords).

## Core Capabilities & Responsibilities

1. **Central User Directory & Replication**: KySignOn is the source of truth for accounts. When an admin creates, updates, or disables an account, it automatically replicates to paired KySecurity products via bare SCIM 2.0 user bodies signed with `ky-primitives/syncauth`; event type and event ID are part of the signature, and the sync secret is never sent in `Authorization`.
2. **Direct SCIM 2.0 Service Connection**: Admin configures downstream KySecurity and 3rd-party product servers directly with their SCIM Base URL and Bearer token for automated RESTful CRUD replication.
3. **OpenID Connect & OAuth 2.0**: Standard authorization-code flow with PKCE, RS256 ID tokens, and JWKS discovery.
4. **Native Device Pairing & Push MFA**: Natively hosts device pairing (`/api/notifications/native/register`) using 90s PIN/QR codes, push challenge dispatch through FCM/APNs relay Workers with 2-digit number matching, and TOTP/recovery code support.
5. **Dashboard & Application Launcher**: Suite sidebar layout in Space Grotesk and IBM Plex Mono, themed with the fifteen KyPost palettes (`web/src/theme.ts`, Patina Ky default, chosen under Appearance and kept in this browser). Accent is a fill colour only; as text it fails contrast on the light palettes. `css/styles.css` serves the fonts and the pre-bundle fallback page.
   The client table exposes each app's copyable OIDC connection details from the configured issuer, including its client ID, human-readable `username` claim, and compatible credential style; it never displays stored secret hashes or claims a browser-compatible logout endpoint exists.
   Administrators can add non-KySecurity launcher applications and select a built-in icon or an HTTPS site favicon; favicon loading stays in the browser rather than creating a server-side fetch path.
6. **Disaster Recovery & KyBackup (Feature 0)**: `kycap/3` capsules sealed to the suite recovery public key (received at KyRecovery pairing or pinned by hand from the ceremony page), scheduled and on-demand delivery to a local backup directory and to KyRecovery, a schedule set in the admin UI, automated sandboxed live restore drills, and a `restore` command that takes custodian shares from the KyRecovery ceremony (operator runbook: `docs/RESTORE.md`). The wire contract is `kyrecovery-server/zero_code_pairing_handoff_spec.md`.

## Security Invariants

- `app_registry` gives each OAuth client, launcher card, and paired system a stable application identity. Startup backfills separate records without guessing links; insert/delete triggers keep references complete across all creation/deletion paths. Admin linking/unlinking requires step-up, matching revisions, non-overlapping connection types, and an atomic audit with readable connection names. Linking preserves connection IDs and credentials, and requires equal access settings with no assignments on either record; unlinking copies access settings and grants. Existing apps migrate to explicit all-active-user access, while new apps default to assigned-only. Direct and group grants combine by union; global admins do not bypass assignments. The same SQL access rules drive admin previews, launcher filtering and OAuth issuance. Access loss deletes pending and spent authorization codes and revokes affected tokens in the mutation transaction; token registration checks the originating code, active session and current access atomically. A re-grant never revives a deleted code or revoked token. Provisioning scope remains unchanged until PR08.

- Directory groups have stable IDs and unique names; names reject invisible format/control characters, private-use characters, and non-ASCII whitespace. Membership/deletion audit records capture readable target identifiers in the mutation transaction; explicit membership never grants global administrator status. Admin group/member lists are searched and paginated. Every group or membership mutation requires operation-bound step-up and commits with its audit record; individual membership writes are idempotent and preserve concurrent edits. Foreign-key cascades remove memberships when a user or group is deleted. Membership removal and group deletion atomically revoke app access only when no alternative grant remains. SCIM group provisioning remains a separate roadmap step.

- Public deployments require an HTTPS issuer and secure session cookies; loopback HTTP is development-only.
- Account creation and updates write their replication outbox events in the same database transaction. The final active administrator cannot be deleted, disabled, or demoted.
- Sensitive API and OAuth responses are `no-store`; registered redirect and launcher URLs must be HTTPS, except loopback HTTP for development.
- Legacy device-pairing tables containing plaintext PINs are rebuilt on startup; their 90-second tokens are intentionally invalidated.
- MFA reset invalidates pending native-device pairing tokens; native registration consumes a live token in the same transaction that creates the approver and push method.
- Native push relay URLs must be HTTPS; relay API keys are runtime secrets loaded from env or generated under the data directory, never committed.
- FCM token refreshes are authenticated by the enrolled device P-256 key, bound to the configured issuer and a fresh monotonic timestamp, and atomically persisted with their audit event; push tokens are never credentials.
- Step-up requires password plus an enrolled TOTP, push, or passkey when any factor is enrolled. Grants and pending challenges bind to user, session, and exact method/path (enrollment preparation maps to its final mutation). Recovery grants only directly authorize replacement TOTP/passkey enrollment; TOTP enrollment still rotates recovery codes and a recovered factor can authorize later operations. Challenge issuance and completion each commit with their audit event; lockout and missing-factor denials are audited. Cancellation burns pending challenges and raced grants. Step-up does not rewrite login authentication evidence.
- The step-up prompt uses a native modal dialog for keyboard focus and outranks the modals it is opened from (`.step-up-backdrop`); a grant request painted under its caller silently cancels the action it was meant to protect.
- A client secret is shown once and rotated in place from the clients table; rotation revokes that client's outstanding tokens, so delete-and-recreate is never the recovery path for a lost secret.
- Sessions have both a configurable absolute lifetime (24h default) and inactivity lifetime (30m default); both are enforced in the store lookup.
- Login sessions record actual password and second-factor verification times. Authorization codes snapshot that evidence; ID-token `auth_time` is the password proof time, never code creation. Legacy sessions omit unknown authentication claims. Recovery is identified separately from ordinary MFA; claim values are documented in README.md.
- New authorization codes and access-token records bind to their originating session. Token registration requires that session and an active user in the same SQL statement; removing the session blocks code exchange and online use of its tokens. Upgrade invalidates legacy pending codes and MFA flows, preserving existing sessions and already-issued tokens without inventing evidence.

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

- [internal/backup/AGENTS.md](file:///home/yoshi/busness.app/kysignon-server/internal/backup/AGENTS.md): adapter over ky-primitives/recoveryclient: what KySignOn seals, its drill checks, store/key/config glue.
