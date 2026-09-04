# Restoring KySignOn from a capsule

This is the procedure for bringing a KySignOn back from a `.kycap` backup after the original
is gone. It needs three things, held by three different parties by design:

| Thing | Who has it |
|---|---|
| The capsule (`.kycap`) | KyRecovery, or the local backup directory, or a downloaded copy |
| k custodian cards | The custodians from the suite ceremony (k is usually 2 of 3) |
| A machine to restore on | You |

Nobody can do this alone. KyRecovery cannot open a capsule. One custodian cannot. The server
that made the backup never could. That is the point, and it is also why you should run this
procedure once as a drill before you ever need it.

## What a capsule holds

Everything a fresh KySignOn needs to be the old one:

| Path in the capsule | What it is |
|---|---|
| `data/kysignon.db` | The whole directory: users, sessions, OAuth clients, MFA state, audit log, settings |
| `data/jwt_rs256.key` | The RSA signing key. Without it every issued token and every OIDC client breaks |
| `data/encryption.key` | 32 bytes. Every TOTP secret and paired-system token in the database is encrypted under it |
| `data/secret.key` | 32 bytes. Signs sessions and CSRF tokens |
| `data/recovery.pub` | The suite recovery public key, so the restored server comes back pinned (present when the backup was paired) |
| `config/kysignon.json` | Issuer URL, port, TTLs, app name. For your reference when re-deploying; nothing reads it |

The restored directory is the live directory in the clear. Treat it like the running server's
`/data`.

## Before you start

- **Pick the capsule.** In the KyRecovery dashboard, open Capsules, find the newest one for
  service `KySignOn` that is not flagged corrupt, and note its `capsule_id`, `created_at` and
  `digest`. You will compare these after the restore. Download it with an operator session
  (`GET /api/capsules/{id}/download`). From a local backup directory, the file is
  `<APP_NAME>-<capsule-id>.kycap`; the newest is the one to use unless you have a reason.
- **Gather k custodians.** Each card carries one share, a single line beginning `ky2-`. They
  type or paste it themselves; do not collect the shares in a file, a chat, or an email. Two
  shares in one place is the suite key in one place.
- **Prepare an empty directory** on a machine you trust, ideally the one that will run the
  restored server. The restore refuses a directory that is not empty.

## Step 1: open the capsule

With the binary (from a release, or `go build ./cmd/kysignon`):

```bash
kysignon restore -capsule cap-KySignOn-XXXXXXXX.kycap -to ./restored
```

With Docker Compose, from the repository directory, mount the capsule and an empty target
directory into a one-off container. The image's entrypoint is the binary, so the subcommand
goes straight after the service name; `--no-deps` keeps the real server down:

```bash
mkdir restored
docker compose run --rm --no-deps \
  -v "$PWD/cap-KySignOn-XXXXXXXX.kycap:/in.kycap:ro" \
  -v "$PWD/restored:/restored" \
  kysignon-server restore -capsule /in.kycap -to /restored
```

The command prompts:

```
Paste the custodian shares, one per line, then press Ctrl-D:
```

Each custodian enters their share on its own line. After the k-th, press Ctrl-D. Shares are
read from stdin only, never from the command line, because argv is world-readable and lands
in shell history.

If the shares are already in a file because this is a drill with test cards:

```bash
kysignon restore -capsule cap-KySignOn-XXXXXXXX.kycap -to ./restored < shares.txt
```

On success it prints the authenticated manifest:

```
Restored 5 files from capsule cap-KySignOn-1788564568139109864
  service:      KySignOn (v1.0.0)
  created:      2026-09-04T23:29:28Z
  recovery key: 886ff52c...
  payload hash: 8a053985...
```

**Check it against KyRecovery's record.** The capsule ID and `created` must match the
deposit record you noted. `capsule.Open` has already proved the bytes are intact and were
sealed to the suite key; matching the ID and time against the blind store's record is what
proves this is the capsule you meant, not an older one someone substituted.

Failures you may see, and what they mean:

| Message | Meaning |
|---|---|
| `capsule is for service "KySignOn", this instance is "X"` | You passed `-service` or set `KYSIGNON_APP_NAME` to something else. Only override `-service` if the backup was made under a different app name |
| `shamir: fewer shares than the threshold requires` | Fewer than k valid lines were read. Check for a missed line or a truncated paste |
| `restore target directory is not empty` | Use an empty directory. The restore never overwrites |
| a decrypt or integrity error | Wrong shares (from a different ceremony), a share mistyped, or a damaged file. Re-download and retry with the custodians |

## Step 2: check what came out

```bash
find restored -type f -printf '%m %p\n'
```

Expect five or six files, all mode `600`, under `restored/data` and `restored/config`.
`cat restored/config/kysignon.json` shows the issuer URL and port the old server ran with.

## Step 3: put it in service

The server reads keys from `/data` files unless the same keys are given by environment.
Choose one form and be consistent.

**Docker Compose (the normal deployment).** Stop any running KySignOn first. Copy the
restored `data/` contents into the data volume, then start:

```bash
docker compose down
docker compose run --rm --no-deps --user root --entrypoint sh \
  -v "$PWD/restored/data:/from:ro" kysignon-server \
  -c 'cp -a /from/. /data/ && chown -R kysignon:kysignon /data && chmod 600 /data/*'
docker compose up -d
```

The one-off container mounts the same `kysignon_data` volume the service uses, so the copy
lands where the server will read it, owned by the image's `kysignon` user. Keep `KYSIGNON_ISSUER_URL` identical to the old
deployment, from `config/kysignon.json`: the RSA key, every OIDC client and every passkey
are bound to it. If the old deployment supplied `KYSIGNON_SECRET_KEY` or
`KYSIGNON_ENCRYPTION_KEY` by environment, keep supplying them; the restored files are the
same keys, and the environment wins when both are present. To turn a restored key file into
its environment form: `xxd -p -c 64 restored/data/encryption.key`.

**Bare binary.** Point `KYSIGNON_DATA_DIR` at `restored/data`, set `KYSIGNON_ISSUER_URL` as
before, and start.

## Step 4: prove it

1. Open the issuer URL and sign in with an existing admin account and its second factor.
   TOTP working proves `encryption.key` is right. A passkey working proves the issuer URL is
   right.
2. Open Disaster recovery. If the backup was paired, the recovery key shows as pinned with
   the same key ID as before. The pairing token is in the database, so the restored server can
   deposit again without re-pairing; click Back up now to prove it. If the screen says the
   key is missing, `data/recovery.pub` did not come across; re-pair, which is refused unless
   KyRecovery hands back the same key.
3. Have one downstream application sign in through KySignOn. That proves the RSA key.
4. Check the audit log: the last events before the restore are there, followed by your
   sign-in.

## Afterwards

- Delete the `restored/` directory once the server runs from its own copy. It is the live
  directory in the clear.
- The custodians' cards are unchanged; a restore does not consume them. If a card was
  exposed during the restore (read aloud, photographed, pasted anywhere shared), that is a
  key compromise for the whole suite, not for one server: run a new ceremony.
- Make a backup from the restored server so the newest capsule reflects the recovery.

## Drill it

Run Steps 1 and 2 against the latest capsule on a scratch machine once a quarter, with the
real custodians and their real cards, and then delete the output. The in-app drill proves the
capsule format restores; only this proves the cards do.
