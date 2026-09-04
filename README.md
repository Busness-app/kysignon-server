# KySignOn Server

KySignOn Server is the single-organization Single Sign-On (SSO) identity provider and central user directory for the **KySecurity Suite** (KyPost, KyPasswords, KyBookmarks, KyNotes).

Built in Go with a focus on simplicity, minimal external dependencies, and native platform standards, KySignOn serves as the authoritative source of truth for accounts, OpenID Connect authentication, and mutual system replication.

---

## Core Capabilities

1. **Authoritative User Directory & Real-Time Sync**: Create, manage, and deactivate accounts from a unified portal. Changes automatically propagate to paired KySecurity downstream products via HMAC-SHA256 signed sync webhooks.
2. **OpenID Connect & OAuth 2.0 Provider**: RFC-compliant authorization code flow with PKCE (`S256`), dynamic JWKS key discovery (`/.well-known/jwks.json`), and RS256 token signing.
3. **Multi-Factor Authentication (MFA)**:
   - **TOTP Authenticator Apps**: Standard RFC 6238 time-based one-time passwords with encrypted secrets at rest (AES-256-GCM).
   - **Push Authentication with Number Matching**: 2-digit verification challenges with decoy numbers for mobile pairing.
   - **Passkeys (WebAuthn)**: ES256 platform and roaming authenticators as a second factor, verified with the standard library alone. Works with KyAuth's Android credential provider, and with iCloud Keychain, Windows Hello and hardware keys.
   - **Emergency Recovery Codes**: Cryptographically hashed single-use recovery codes.
4. **90-Second Ephemeral Pairing**: Frictionless UI-based pairing with QR codes and short PINs for native mobile devices and downstream server applications.
5. **KySecurity Suite Application Launcher**: Single-pane dashboard themed in KySecurity Patina (dark `#0d0f14`, cyan `#4deeea`, Space Grotesk, IBM Plex Mono) embedding the full React frontend into the standalone binary.

---

## Architecture & Standard Library Philosophy

Following the **Ponytail** engineering philosophy (*use the smallest correct change, prefer native platform APIs, minimize external bloat*), **over 95% of the Go backend is built exclusively using the Go Standard Library (`stdlib`)**.

```
                           ┌───────────────────────────────┐
                           │      React Web Frontend       │
                           │  (Embedded via Go embed/fs)   │
                           └───────────────┬───────────────┘
                                           │
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             KySignOn Server (Go)                                 │
├──────────────────┬───────────────────┬─────────────────────┬─────────────────────┤
│   HTTP Routing   │   OIDC / OAuth    │     MFA & TOTP      │    Sync Engine      │
│  (net/http 1.22) │ (crypto/rsa, jwks)│ (crypto/hmac, sha1) │ (net/http, sha256)  │
├──────────────────┴───────────────────┴─────────────────────┴─────────────────────┤
│                          SQLite Database Engine                                  │
│             (database/sql abstraction + modernc.org/sqlite)                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Standard Library Implementations

| Subsystem | Standard Library Components Used | Avoided External Dependencies |
| :--- | :--- | :--- |
| **HTTP Routing & API** | `net/http` (Go 1.22+ pattern routing), `context`, `net` | *No Gin, Fiber, Chi, or Gorilla Mux* |
| **OIDC, OAuth 2.0 & JWT** | `crypto/rsa`, `crypto/sha256`, `encoding/base64`, `encoding/json` | *No `golang-jwt`, `go-jose`, or `ory`* |
| **TOTP / 2FA Engine** | `crypto/hmac`, `crypto/sha1`, `encoding/base32`, `encoding/binary` | *No third-party TOTP libraries* |
| **At-Rest Encryption** | `crypto/aes` + `crypto/cipher` (AES-256-GCM) | *No third-party encryption packages* |
| **Sync Webhooks** | `net/http` client + `crypto/hmac` + `crypto/sha256` | *No webhook frameworks* |
| **Embedded Frontend** | `embed` + `io/fs` (React SPA served from binary memory) | *No packr or go-bindata* |
| **Database Access** | `database/sql` | *No GORM, Ent, or ORM frameworks* |

### Direct Dependencies

KySignOn relies on only **3 direct external packages**:
- **`modernc.org/sqlite`**: Pure-Go SQLite engine allowing zero-CGO static compilation (`CGO_ENABLED=0`) on Alpine Linux.
- **`golang.org/x/crypto`**: Official Go extended crypto library for secure `bcrypt` password hashing.
- **`github.com/google/uuid`**: RFC 4122 UUID generator.

---

## Quickstart with Docker Compose

### 1. Configure Environment
Clone the repository and copy the sample configuration:
```bash
cp .env.example .env
```

Review and adjust variables in `.env`:
```ini
# Interface binding (127.0.0.1 for local/proxy only, or 0.0.0.0 if not using proxy)
KYSIGNON_BIND=127.0.0.1

# Static container IP on shared kypost-net network
KYSIGNON_IP=10.89.0.2

# Public URL used in issued tokens (use your public HTTPS domain in production)
KYSIGNON_ISSUER_URL=https://auth.yourdomain.com

# Optional: Pre-seed administrator credentials
BOOTSTRAP_ADMIN_USER=admin
BOOTSTRAP_ADMIN_PASS=YourSecurePassword123!

# Optional: Cloudflare Worker native-push relays
PUSH_RELAY_URL=https://kysecurity-mobile-push-fcm.<account>.workers.dev
APNS_RELAY_URL=https://kysecurity-mobile-push-apns.<account>.workers.dev
```

### 2. Start the Server
```bash
docker compose up -d --build
```

### 3. Retrieve Credentials & Log In
If you did not define `BOOTSTRAP_ADMIN_PASS` in `.env`, KySignOn generates a one-time bootstrap password on first start:

```bash
docker compose exec kysignon cat /data/first-run-password.txt
```

Open your browser and navigate to:
```text
http://<YOUR_SERVER_IP>:5867
```
Sign in with `admin` and the retrieved password.

---

## Health & Status Verification

You can verify the status of the server at any time:

* **Liveness** (is the process running):
  ```bash
  curl http://localhost:5867/healthz
  # Response: {"status":"alive"}
  ```
* **Readiness** (can this instance actually authenticate someone). Point your load balancer
  at this one. It runs a bounded database read and confirms the signing and encryption keys
  are loaded, and returns `503` when they are not. `/healthz` deliberately proves none of
  that; a process that can encode JSON while its database is gone is still down.
  ```bash
  curl http://localhost:5867/readyz
  # Response: {"status":"ready","checks":{"audit":"ok","database":"ok",...}}
  ```
* **OpenID Connect Discovery**:
  ```bash
  curl http://localhost:5867/.well-known/openid-configuration
  ```
* **Docker Container Health**:
  ```bash
  docker compose ps
  # Look for "Up (healthy)"
  ```

---

## Command Line Utilities

Create the first admin account directly within the running container:
```bash
docker compose exec kysignon /usr/local/bin/kysignon bootstrap-admin --username admin --password "NewPassword123!"
```

`bootstrap-admin` only creates a missing account. It will not overwrite the password of an
account that already exists — change those from the admin UI, so the action is audited.

---

## Integration Requirements

These rules are enforced strictly. Each is a constraint on how a client integrates.

**Redirect URIs must match exactly.** There are no host aliases, port families, trailing
slash tolerance, or per-client fallbacks. A client that needs three callback ports
registers three URIs. This is the single control deciding who receives an authorization
code; anything looser makes registration advisory.

**PKCE (`S256`) is mandatory for public clients**, and `plain` is rejected everywhere. A
public client presents no secret, so the verifier is the only thing binding a code to the
party that requested it.

**Clients are confidential by default.** Registration issues a client secret unless
`"clientType":"public"` is passed explicitly. Every suite service (KyPost, KyDNS,
KyPasswords, KyNotes, KyBookmarks) is a server-side application that can hold one, so it
should be confidential; `public` exists for SPAs and native apps that genuinely cannot.
A confidential client with an empty `client_secret_hash` is rejected rather than
authenticated by existing.

**Rotate or correct a client in place** with `PUT /api/admin/clients/{id}` —
`{"clientType":"confidential"}` promotes a public client and returns a fresh secret,
`{"rotateSecret":true}` rotates an existing one. The secret appears in that response only.
This exists so a misregistration is recoverable; delete-and-recreate would break the
integration it is meant to secure, which guarantees nobody ever does it.

**Access tokens live 15 minutes** and carry a `jti` recorded server-side.
`POST /oauth/revoke` (RFC 7009, client authentication required) invalidates one;
disabling a user, resetting their MFA, changing their password, or revoking their sessions
invalidates all of theirs. Services that validate tokens offline against JWKS cannot see a
revocation until expiry — call `/oauth/userinfo` where revocation must take effect at once.

**System pairing requires the PIN** shown next to the token, and callback URLs must be
`https` and resolve off-network unless `KYSIGNON_ALLOW_PRIVATE_CALLBACKS=true` (the
compose file sets this, since services on `kypost-net` address each other privately).
Sync events are queued per paired system; a system only receives what was queued for it.

**Device pairing requires a P-256 public key.** A device without one can never approve a
push, and pairing it previously enrolled push MFA that no response could satisfy.

**`TRUSTED_PROXY_CIDRS` defaults to empty.** Forwarding headers are ignored unless the
immediate peer is a CIDR you named. Set it to your proxy's address and nothing wider: every
host inside a listed range can choose its own rate-limit bucket and its own entry in your
audit log.

**`KYSIGNON_FORWARDED_HEADER` names the one header that is believed, defaulting to
`X-Forwarded-For`.** Behind Cloudflare, set it to `CF-Connecting-IP`. Exactly one header is
honoured per deployment because trying several in turn means whichever one your edge does
*not* overwrite is the one an attacker gets to choose. The value must parse as an IP
address, and the chain is walked from the right past hops inside `TRUSTED_PROXY_CIDRS`, so a
client-supplied entry prepended to the list is never attributed.

**Backups are sealed to the suite recovery key and this server never holds what opens
them.** The key arrives by pairing with KyRecovery, or is pasted from the ceremony page on
the Disaster recovery screen for a server with no KyRecovery. Every capsule is sealed to it
and goes to each configured destination: KyRecovery when paired, and `KYSIGNON_BACKUP_DIR`
when set. Files there are named `<KYSIGNON_APP_NAME>-<capsule-id>.kycap`; the newest
`KYSIGNON_BACKUP_KEEP` (default 7) with that prefix are kept and anything else in the
directory is never listed or deleted. The schedule is set on
the same screen; `KYSIGNON_BACKUP_DEPOSIT_INTERVAL` (default 24h, 15m floor, `0` disables)
is only the default until an admin picks one. Custodian cards come from the KyRecovery
ceremony, and a restore is `kysignon restore -capsule <file.kycap> -to <dir>` with k shares
typed on stdin. A server with no key pinned can run drills but cannot make a capsule.

**KyRecovery must be reached over HTTPS, and by default at a public address.** TLS is not
for the capsule, which is sealed anyway; it protects the recovery public key that arrives at
pairing (trust on first use), the deposit token, and the receipts. For a KyRecovery on your
own network behind a TLS proxy, set `KYSIGNON_BACKUP_ALLOW_PRIVATE_RECOVERY=true`; HTTPS is
still required, the choice is recorded on every pairing, and loopback stays refused. Either
way, pin the key by hand from the ceremony page before pairing, or compare the key ID the
screen shows with the fingerprint in the KyRecovery dashboard; a swapped key then fails
loudly. In Docker, set `KYSIGNON_DNS` to your LAN's resolver so a name that exists only
there resolves inside the container.

**Passkeys are bound to the issuer's origin.** The relying party ID is the hostname of
`KYSIGNON_ISSUER_URL` and the accepted origin is its scheme, host and port. Changing the
issuer URL invalidates every enrolled passkey, because the browser will not offer a
credential registered under a different RP ID. Browsers permit WebAuthn over plain HTTP only
on `localhost`, so a deployment reached by IP or by a name without TLS cannot enrol one.

**Enrolling or removing a passkey spends a step-up grant**, like every other change to an
account's factors. Resetting a user's MFA deletes their passkeys along with their TOTP
secret and recovery codes. Step-up itself only demands a second factor when TOTP is
enrolled, so for an account whose only second factor is a passkey, a step-up grant
currently costs the password alone — enrol a passkey alongside TOTP or a push device
rather than as an account's sole factor.

**Destructive admin operations require step-up re-authentication.** Creating or editing an
account, resetting someone's MFA, deleting a user, registering or deleting an OAuth client,
connecting or removing a paired system, and exporting, pairing, pinning a key, running or
rescheduling a backup each
spend a single-use grant that costs your password and an enrolled factor. A stolen session
cookie cannot produce one. Read-only views and the emergency "revoke sessions" button stay
on the session alone, so locking an account down during an incident is not slowed by a
second prompt.

**`KYSIGNON_SECRET_KEY` and `KYSIGNON_ENCRYPTION_KEY` must be exactly 64 hex characters.**
A malformed value is a startup error, never a silently weakened key. Generate with
`openssl rand -hex 32`. Left unset, they are generated into the data directory and reused.

---

## License & Security

Refer to [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
