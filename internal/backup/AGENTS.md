# Backup

## Purpose
Implements "Feature 0" disaster recovery, container encapsulation (`.kycap`), Shamir Secret Sharing $(k, n)$ threshold key distribution, automated sandboxed restore drills, and KyRecovery pairing integration for KySignOn Server.

## Ownership
Owns encrypted backup capsule creation/extraction, ephemeral key splitting/reconstruction, sandboxed restore drill verification, and printable offline Disaster Recovery Kit generation.

## Local Contracts
- Sandboxed restore drills must execute inside ephemeral temporary directories with POSIX `0700` permissions and be wiped upon completion.
- Capsule payloads must be encrypted with AES-256-GCM and verified with SHA-256 integrity checksums.
- Key shards must strictly adhere to Shamir polynomial interpolation over $GF(2^8)$.

## Verification
- `go test -v ./internal/backup/...`

## Child DOX Index
None.
