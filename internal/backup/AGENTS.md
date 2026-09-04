# Backup

## Purpose
Implements "Feature 0" disaster recovery: `kycap/3` container encapsulation (`.kycap`) from `github.com/Busness-app/ky-primitives/capsule`, sealed to the suite recovery public key received at KyRecovery pairing, deposit of the sealed container to KyRecovery, and automated sandboxed restore drills.

## Ownership
Owns backup payload collection (database snapshot, RSA signing key, encryption and secret keys, config manifest), the KyRecovery client (claim and deposit), loading and pinning the suite recovery public key (`recovery.pub`, key ID pinned in `system_settings`), the pairing record (`kyrecovery_url`, sealed `kyrecovery_token_enc`), the last deposit receipt (`kyrecovery_last_deposit`), and sandboxed restore drill verification against a throwaway key. It holds no private key and no shares; custodian cards come from the KyRecovery ceremony.

## Local Contracts
- `ClaimPairing` sends `service_name` explicitly and it must be the value `Seal` is given (`cfg.AppName`): KyRecovery pins the claimed name and refuses every deposit whose manifest names another.
- `StoreRecoveryKey` is write-once per key; `StorePairing` runs after it and seals the token under `crypto.DeriveKey(EncryptionKey, "kysignon:setting:kyrecovery_token")`. `LoadPairing` reports `ErrNotPaired` unless key, URL and token are all present.
- `CollectSealable` snapshots the database through the live handle (`SnapshotTo`, `VACUUM INTO`); a missing database, signing key or deployment key is fatal, never skipped. Its output leaves the process only inside a sealed capsule.
- `Deposit` sends the container as `application/octet-stream` with the bearer token, accepts 200 or 201, and refuses a receipt whose digest, size or capsule ID do not describe the bytes sent. Wire and store errors wrap `ErrRemote`; a deposit that landed but whose receipt write failed wraps `ErrReceiptUnrecorded` and still returns the receipt. Deposits are single-flight per process.
- `Outcome` turns any `DepositBackup` result into the audit action, outcome and details, bounded by `AuditSafe`; every caller (route, scheduler, CLI) records through it.
- Text from outside the process (remote error bodies, operator-typed URLs) goes through `AuditSafe` before it reaches an error string or an audit record: printable only, 200 characters.
- Restore drills seal to a throwaway key generated and discarded within the same call, extract into an ephemeral `0700` directory wiped on return, and report only checks they actually execute: file presence, SQLite integrity, required tables, an active admin, secret decryption, token signing.
- KyRecovery connections require HTTPS and reject private, loopback, link-local, reserved, and unsafe redirect destinations.
- `TestNothingInTheServerDecrypts` pins that no non-test file calls `recoverykey.Combine`, `recoverykey.FromSeed` or `capsule.Open` except the `restore` command.

## Verification
- `go test -v ./internal/backup/...`

## Child DOX Index
None.
