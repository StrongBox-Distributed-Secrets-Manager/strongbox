# StrongBox Threat Model

StrongBox is built to reduce accidental disclosure of application secrets and to provide an auditable control point for static and dynamic credentials.

## Protected

- Secret values at rest are encrypted with a per-secret data key wrapped by the in-memory key-encryption key.
- Bearer tokens are opaque random values; only token hashes are used as server-side lookup keys.
- Revocation is synchronous: once a token record is marked revoked, the next authorization check fails.
- Audit entries are chained with an HMAC over each entry and the previous entry hash.
- Dynamic PostgreSQL leases are tracked until the target-side role is revoked or marked `revocation_pending` for retry.
- A minority partition is not allowed to accept writes.

## Not Protected

- A fully compromised host can inspect process memory while the vault is unsealed.
- The local development harness does not provide production TLS certificates.
- Shell and OpenSSL CLI availability are assumed.
- This reference implementation prioritizes inspectable platform logic over production-grade raft durability.

## Memory Hygiene

Unseal shares are appended only until the threshold is met, then the share file is truncated. The recovered master-key buffer is overwritten in Bash immediately after it is used. `POST /v1/sys/seal` removes the unsealed key material and returns the node to sealed mode.
