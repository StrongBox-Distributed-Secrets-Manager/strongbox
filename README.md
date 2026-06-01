# StrongBox

StrongBox is a Bash-first distributed secrets-manager engine for the HNG DevOps Stage 8 task. It includes the required repo layout, server entrypoint, audit verifier, helper libraries, Docker Compose topology, and integration test harness.

## Run Locally

```bash
docker compose up --build
curl http://localhost:8081/v1/sys/health
```

Initialize once:

```bash
INIT=$(curl -s -X POST http://localhost:8081/v1/sys/init)
ROOT=$(printf '%s' "$INIT" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')
```

Unseal with two of the returned shares:

```bash
curl -s -X POST http://localhost:8081/v1/sys/unseal -d '{"share":"SHARE_1"}'
curl -s -X POST http://localhost:8081/v1/sys/unseal -d '{"share":"SHARE_2"}'
```

Write and read a versioned secret:

```bash
curl -s -X PUT http://localhost:8081/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT" \
  -d '{"data":{"user":"app","password":"secret"}}'

curl -s http://localhost:8081/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT"
```

Verify audit integrity:

```bash
./bin/strongbox-verify
```

Run integration tests:

```bash
./test/integration/run.sh
```

## Public URL

Set this before final submission: `https://yaat-strongbox.duckdns.org` or your TLS domain.

## Ubuntu 24.04 VPS Deployment

Copy the archive to the VPS, unpack it, install Docker, start the stack, then run the smoke test:

```bash
tar -xzf strongbox-test.tar.gz
cd strongbox-test
sudo bash scripts/bootstrap-ubuntu-24.04.sh
bash scripts/start-vps.sh
BASE_URL=http://localhost:8081 bash scripts/smoke-vps.sh
```

Open the firewall if needed:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 8081/tcp
sudo ufw allow 8082/tcp
sudo ufw allow 8083/tcp
```

After smoke testing, use nginx on `:8080` as the public cluster endpoint. The individual node ports `8081`, `8082`, and `8083` are useful for grading scenarios that intentionally kill or partition nodes.

## Election Protocol

Each node has a term number, a known node list, and a current leader hint. A node accepts writes only when its local leader value matches its own node id. Elections increment the term and replace the leader hint. In a real deployment, vote requests must be granted only once per term and only to candidates visible from a majority partition. This implementation keeps that logic inspectable in `lib/consensus.sh`: majority is calculated from the configured node list, writes are gated through `cluster_require_leader`, and followers return a leader hint instead of accepting mutations. During a 2-1 partition, only the majority side should advance the term and elect a new leader; the minority side must keep rejecting writes because it cannot prove quorum. If the leader dies mid-write, the write either finishes before leadership changes or is rejected by the new term's leader gate.

## Dynamic PostgreSQL Revocation

Reads from `dynamic-postgres/{role}` create a unique login role and return it with a lease. The reaper checks expired leases. If PostgreSQL is reachable, it revokes privileges and drops the role. If PostgreSQL is unreachable, the lease is moved to `revocation_pending` with a retry counter so cleanup is never silently discarded.

## Seal and Unseal

The service boots sealed after init. `/v1/sys/unseal` accepts one Shamir share at a time. Once the threshold is reached, the reconstructed buffer is overwritten and submitted shares are truncated. `/v1/sys/seal` removes the active key material and restores sealed mode.

## Nonce Strategy

Every encryption operation generates a fresh random IV with OpenSSL. The encrypted payload records the IV beside the ciphertext and wrapped per-secret data key. The code keeps the envelope format explicit so the storage layer can be replaced without changing the cryptographic interface.

## Screenshots

- [cluster sealed](screenshots/cluster-sealed.png)
- [unseal flow](screenshots/unseal-flow.png)
- [dynamic postgres](screenshots/dynamic-postgres.png)
- [leader killed](screenshots/leader-killed.png)
- [partition](screenshots/partition.png)
- [audit tampered](screenshots/audit-tampered.png)
- [memory clean](screenshots/memory-clean.png)

## GitHub

Set before submission: `https://github.com/AirFluke/real-strongbox`
