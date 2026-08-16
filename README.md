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

* **HTTP Health Check**:
  ```bash
  curl http://localhost:5867/healthz
  # Response: {"status":"healthy"}
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

## Operator Notes: Enforcement That May Affect Existing Integrations

These rules are enforced strictly. Each one closes a path that previously granted access.

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

**Existing clients registered before this change are public and have no secret.** The
server logs a NOTICE for each at startup. Promote one in place, without breaking it, via:

```bash
curl -X PUT https://auth.example.com/api/admin/clients/kypost \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
  --cookie "kysignon_session=$SESSION; kysignon_csrf=$CSRF" \
  -d '{"clientType":"confidential"}'
```

The response carries `clientSecret` once. Configure it in that service before its next
sign-in, since the client is confidential from that moment and unauthenticated exchanges
stop working. `{"rotateSecret":true}` rotates an existing one the same way.

**Scopes are intersected with the client's `allowedScopes`.** Asking for more than a client
is registered for narrows to the permitted set, or fails if nothing overlaps.

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

**`TRUSTED_PROXY_CIDRS` defaults to empty.** Forwarding headers, including
`CF-Connecting-IP`, are ignored unless the immediate peer is a CIDR you named. Set it to
your proxy's address and nothing wider: every host inside a listed range can choose its own
rate-limit bucket and its own entry in your audit log.

**`KYSIGNON_SECRET_KEY` and `KYSIGNON_ENCRYPTION_KEY` must be exactly 64 hex characters.**
A malformed value is a startup error, never a silently weakened key. Generate with
`openssl rand -hex 32`. Left unset, they are generated into the data directory and reused.

---

## License & Security

Refer to [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
