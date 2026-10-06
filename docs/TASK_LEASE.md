# Compose S0 task lease (`dubsar.task-lease.v1`)

Contract Plane amendment for the Compose S0 chain
`Core -> Task Manager -> OpenSandbox-derived lifecycle / gVisor`. This document describes what the repository proves; the Task
Manager itself and the sandbox lifecycle are implemented and proven in
`dubsar-task-runtime`.

## Why a derived contract

`execution-lease` binds a worker to one workflow step and one connector action
(`run_id`, `step_id`, `workflow`, `approval_id`, `expected_action`). A Compose
S0 Task has no workflow, no connector and no approval record: it is one closed,
`effect: none` sandbox run decided by Core policy. Reusing `execution-lease`
would have forced fake workflow bindings; widening it would have changed a
frozen v1 contract for its existing consumers. `task-lease` therefore reuses
the lease **envelope** and replaces the workflow bindings with a closed `task`
authorization slice.

Shared envelope, identical patterns and semantics:

```text
lease_id, authority = DUBSAR_CORE, issued_at, not_before, expires_at,
nonce, replay_protection { replay_key, single_use = true }
```

Task-specific bindings:

| Field | Binds |
| --- | --- |
| `audience` | constant `dubsar-task-manager` |
| `task_id`, `action_id` | the Task id and the governed action id used on Task receipts |
| `tenant_id`, `mission_id` | the Core tenancy and mission scope |
| `task_manager` | the exact Task Manager `workload_id` / `instance_id` allowed to consume the lease |
| `task` | the authorization slice and digests (below) |
| `evidence_correlation_id` | the Evidence Plane correlation key shared by Core decision, Task Manager admission and sandbox receipts |

## The lease authorizes, it does not parameterize

The requester never supplies an image, command, mount or capability. Core
hashes a **closed profile** (`fixtures/v1/task-lease/closed-profile.json` for
the S0 fixture) under `dubsar.task-profile.v1` and a **runtime lock** under
`dubsar.runtime-lock.v1`. The lease carries those digests plus the
authorization bounds. The Task Manager recomputes `closed_profile()` from its
local lock, maps it to the same JSON, and rejects any digest mismatch.

`hashTaskProfile` / `hashRuntimeLock` / `bindTaskAuthorization` in
`src/contracts.mjs` are the canonical functions. The closed profile includes
the executable fields the lease itself refuses (`image`, `entrypoint`,
`commands`, `allowed_outputs`, `input_root`, `output_root`, `runtime_lock`).

Authorization slice and the S0 fixture values
(`fixtures/v1/task-lease/valid.json`, profile `dubsar.fixture.patch.v0`):

| Field | Constraint | Fixture |
| --- | --- | --- |
| `profile_id` | versioned dotted id | `dubsar.fixture.patch.v0` |
| `effect` | constant `none` | `none` |
| `input_digest` | `sha256:` digest of the S0 fixture project | fixture input |
| `runtime_lock_digest` | `hashRuntimeLock(lock)` | digest of the closed-profile lock |
| `profile_digest` | `hashTaskProfile(closedProfile)` | digest of the closed profile |
| `limits.cpu_millicores` / `memory_bytes` / `pids` | bounded integers | 500 / 128 MiB / 256 |
| `limits.disk_bytes` | must cover the sum of mounts | 26 MiB |
| `limits.ttl_seconds` | 1..300 and within the lease window | 60 |
| `limits.command_timeout_ms` | within the ttl | 20000 |
| `limits.output_bytes` | bounded | 1 MiB |
| `identity.uid` / `gid` | >= 1000 (root refused) | 65532 |
| `filesystem.rootfs_read_only` | constant `true` | `true` |
| `filesystem.mounts[]` | closed allowlist of tmpfs roots: `/run`, `/tmp`, `/workspace` only; already-canonical POSIX paths; `nodev`+`nosuid` required; any other path, including `/lib64` and descendants of system roots, is refused | `/run`, `/tmp`, `/workspace` |
| `capabilities.drop` | constant `["ALL"]` | `["ALL"]` |
| `capabilities.add` | subset of `CHOWN, KILL, SETGID, SETUID` | those four |
| `network.policy` | `egress_none` | `egress_none` |
| `allowed_operations` | sorted unique subset of `collect, create, execute, inspect, terminate` | all five |

Semantic invariants beyond the schema are enforced by `validateTaskLease` in
`src/contracts.mjs`: chronology, validity `<= 300 s`, sandbox ttl inside the
lease window, command timeout inside the ttl, mounted bytes inside
`disk_bytes`, canonical ordering, required `nodev`/`nosuid`, POSIX-canonical
mount paths (`path.posix.normalize(p) === p`, no `\0`, `\\`, `.`, `..` or
empty segments), uniqueness after that canonical form, and an exact
allowlist of `/run`, `/tmp` and `/workspace`. Paths such as `/lib64` (a
common symlink into `/usr/lib64`), `/etc/ssh`, `/run/user` and `/runtime`
are refused. `hashTaskProfile` applies the same mount and output-path rules:
output names are `/workspace/out/` plus a filename that starts with an
alphanumeric character, so `/workspace/out/..` is refused.

## Local closed profile (Task Manager)

`admit` and `consumeTaskLease` never trust a caller-supplied `expected.task`.
They require the Task Manager's local closed profile, call
`bindTaskAuthorization(closedProfile)` and compare that authorization slice
(including `profile_digest` and `runtime_lock_digest`) to the lease. A missing
profile fails closed (`TASK_LEASE_CLOSED_PROFILE_REQUIRED`). A well-formed
profile that does not rehash to the leased slice is `TASK_LEASE_PROFILE_MISMATCH`.

The JSON object in `fixtures/v1/task-lease/closed-profile.json` is the canonical
form. The Python S0 `closed_profile()` in `dubsar-task-runtime` is a different
shape (`cpu=500m`, `memory=128Mi`, `network_mode`, `egress:none`, …). P3 must
project that dataclass onto this JSON before hashing or admitting; this
repository does not perform that projection.

| Python `closed_profile()` field | Canonical JSON field |
| --- | --- |
| `cpu=500m` | `limits.cpu_millicores` = `500` |
| `memory=128Mi` | `limits.memory_bytes` = `134217728` |
| `pids=256` | `limits.pids` |
| `ttl_seconds=60` | `limits.ttl_seconds` |
| `command_timeout_ms=20000` | `limits.command_timeout_ms` |
| UID/GID `65532` | `identity.uid` / `identity.gid` |
| `egress:none` | `network.policy` = `egress_none` |
| image / entrypoint / commands | closed-profile only; never copied into the lease |

## Consumption

```js
import { consumeTaskLease, taskLeaseAllows } from '../src/contracts.mjs'
import { InMemoryTaskLeaseReplayStore } from '../src/task-manager/in-memory-task-lease-replay-store.mjs'

await consumeTaskLease(lease, {
  task_id, action_id, tenant_id, mission_id,
  task_manager: { workload_id, instance_id },
  closedProfile,
}, replayStore, now)
taskLeaseAllows(lease, 'create')
```

`replayStore` must implement `consumeOnce(identity, expiresAt)` and return
`true` exactly once. The function may be synchronous or async;
`consumeTaskLease` and `admit` `await` the result. A resolved value other than
`true` is a replay. The in-memory adapter is process-local and is not a
durable store. Admission fails closed if the store is missing. Production
Task Managers inject a shared, atomic adapter (P3).

`consumeTaskLease` checks the temporal window, every identity binding, the
locally rehashed authorization slice and then consumes the `replay_key:nonce`
identity. `expected.task`, if present, is ignored.

## Signed envelope

`src/core/signed-task-lease-format.mjs` fixes the compact serialization
described in [CANONICALIZATION](CANONICALIZATION.md):

```text
header  = {alg: "EdDSA", kid: "core-key_...", typ: "DUBSAR-TASK-LEASE+JSON", v: 1}
payload = {exp, iat, issuer: "dubsar-governance-core", lease, lease_digest,
           nbf, policy_digest, schema: "dubsar.signed-task-lease.v1"}
```

- `lease` is the complete `dubsar.task-lease.v1` document;
- `lease_digest` is `hashContract('task-lease', lease)` under the domain
  `dubsar.contract.task-lease.v1`;
- `policy_digest` is the digest of the Core policy decision that admitted the
  profile, so receipts can correlate lease and decision;
- `iat`/`nbf`/`exp` must equal the lease timestamps to the second; `nbf - iat
  <= 5 s`; `exp - nbf <= 300 s`;
- the signature segment must be the canonical base64url encoding of the
  64-byte Ed25519 signature.

`Ed25519TaskLeaseAuthority` (`src/core/`) is the reference Core issuer. It
requires `closedProfile`, hashes it, refuses a caller `task` that does not
match the authorization slice, validates the lease before signing, refuses
validity outside `1..300 s` and refuses identifier reuse within its lifetime.

`Ed25519TaskLeaseVerifier` (`src/task-manager/`) is the reference Task Manager
verifier. `verifySigned` checks, independently of the signature and in this
order: format, header, `kid` shape, closed payload key set, temporal envelope,
issuer, embedded contract validity, audience, timestamp agreement, digest
binding, key resolution (unknown / revoked / crypto window at **`iat` only**;
revocation is still evaluated at verification time), then the Ed25519
signature. `admit` requires a local `closedProfile` and a replay store, ignores
`expected.task`, calls `consumeTaskLease` and maps outcomes to
`TASK_LEASE_CLOSED_PROFILE_REQUIRED`, `TASK_LEASE_CLOSED_PROFILE_INVALID`,
`TASK_LEASE_REPLAY_DETECTED`, `TASK_LEASE_REPLAY_STORE_REQUIRED`,
`TASK_LEASE_PROFILE_MISMATCH`, `TASK_LEASE_BINDING_MISMATCH`,
`TASK_LEASE_NOT_YET_VALID` or `TASK_LEASE_EXPIRED`. `assertOperationAllowed`
rejects any operation absent from `allowed_operations` with
`TASK_LEASE_OPERATION_FORBIDDEN`.

## Conformance vector

`fixtures/v1/task-lease/signed-vector.json` publishes the valid fixture signed
by a throwaway Core key. Only the **public** JWK is committed. Any verifier
implementation (the Python Task Manager in `dubsar-task-runtime`, the
Scribe-Builder issuer's self-check) must:

1. accept `signed_task_lease` at `verify_at` with `kid` and `public_key_jwk`,
   recover a lease byte-identical to `fixtures/v1/task-lease/valid.json` and
   recompute `lease_digest`;
2. reject the same envelope at `expired_at` as expired;
3. reject a second `admit` of the same lease as a replay. `admit` must be
   given the local closed profile; copying `task` out of the verified lease
   is not admission.

## Authority and state transitions

`TASK_MANAGER` is named in `state-transition.actor.authority` so Task receipts
can identify their actor. It is **not** a Broker peer. The existing
external-action matrix still admits only `BROKER` on `AUTHORIZED` /
`IN_FLIGHT`. `TASK_MANAGER` is never authoritative from `RECEIVED`,
`AUTHORIZED`, `IN_FLIGHT` or `INDETERMINATE` on that machine. Compose S0 Task
lifecycle states (`CREATING`, `RUNNING`, `COLLECTING`, `TERMINATING`,
`CLEANED`) belong to `dubsar-task-runtime` (P3), not to this Broker contract.
The Broker's PostgreSQL store is unchanged and still admits only `BROKER`.

## Out of scope in this repository

No Task Manager process, no sandbox lifecycle, no Docker or gVisor, no key
distribution, no transport, no durable replay database. `admitted_revision`
values held outside this repository are not modified by this amendment.
