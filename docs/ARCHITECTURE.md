# Contract Plane authority and trust boundaries

## Canonical ownership

| Authority | Owns | Must not own |
| --- | --- | --- |
| Governance Core | policy evaluation, approvals, capability decisions and revocation | workflow runtime state or provider secrets |
| Automation Engine | workflow graph/version and technical run/step state | policy decisions or provider secrets |
| Worker | execution of the exact leased technical step | external provider secrets, approval or publication authority |
| Broker | bounded action admission and durable action outcome state | graph truth, approval truth or reusable bearer authority |
| Task Manager | verification of one task lease and the lifecycle of the exact leased Task inside an isolated sandbox | policy decisions, lease issuance, profile widening or the sandbox lifecycle server's privileges |
| Evidence Plane | attestations and receipt chain | policy or execution decisions |
| Hermes | structured proposals for human/Core review | publication, execution, approval or secret materialization |

## Contract chain

1. `workflow-ir` gives a deterministic, digestible graph with exact connector
   versions and opaque connection references.
2. `approval-record` binds a Core decision to one exact workflow digest and a
   bounded scope. Any graph change produces a different digest and invalidates
   that approval.
3. `execution-lease` binds one worker, run, step and expected action for a short
   interval, with nonce-based replay protection.
4. `action-proposal` describes a typed external action without resolving a
   secret.
5. `capability-claims` describes the claims the Lot 2C Ed25519 envelope binds.
   The claims contract remains independent of that envelope format.
6. `action-receipt` records the Broker outcome, the Core decision and consumed
   single-use capability without retaining a token or secret.
7. `state-transition` applies the closed Broker external-action state
   machine. Undeclared transitions are rejected; `INDETERMINATE` is never
   automatically retried. `BROKER` owns `AUTHORIZED -> IN_FLIGHT -> terminal`.
   `TASK_MANAGER` is named in the actor enum for Task receipts but has no
   authority on this matrix; only `CORE` authorizes from `RECEIVED` and only
   the Evidence Plane or a human reconciles from `INDETERMINATE`.
8. `task-lease` binds one Task Manager instance, one task, one tenant/mission
   and one exact closed S0 profile by `profile_digest` and
   `runtime_lock_digest`, plus authorization bounds (resource limits, non-root
   identity, read-only rootfs, tmpfs mounts, allowlisted capabilities, no egress,
   admitted lifecycle operations) for a short interval with store-backed
   single-use replay protection. The lease authorizes; it never
   parameterizes. See [TASK_LEASE](TASK_LEASE.md).

The durable Broker store (`migrations/`) still admits only `BROKER` on the
lifecycle transitions it persists: the Task Manager records its own transitions
in its own evidence store, never in the Broker's tables.

## Explicit non-goals through Lot 2C and Compose S0 P1

- no real connector or network call;
- no production Broker transport, Gateway, vault, mTLS or durable key service;
- no Automation MCP surface;
- no publication or deployment;
- no change to the qualified Automation Engine image;
- no generated Pydantic or TypeScript bindings before a consumer proves the
  need and conformance tests cover generator drift.

## Pilot boundary

Lot 2B preserves an in-memory conformance fake. Lot 2C adds a separate Core
signer and a PostgreSQL-backed Broker adapter without changing the canonical v1
contracts or the authority allocation above. The only executor still returns a
deterministic `effect: none` result. No Automation Engine integration begins in
this repository.

Compose S0 P1 adds the eighth contract, a reference Core task-lease signer
(`src/core/`) and a reference Task Manager verifier (`src/task-manager/`). It
does not implement the Task Manager, the sandbox lifecycle, gVisor, Docker or
any transport; those belong to `dubsar-task-runtime` and are proven there.
