# Lot 2B in-memory Action Broker

## Boundary

The Lot 2B Broker is a single-process conformance pilot. It consumes only v1
Workflow IR, Approval Record, Action Proposal and Capability Claims values. It
has no network transport, database, provider adapter, secret lookup or runtime
integration. The only admitted action is the deterministic fixture-derived
`dubsar.ticketing@1.2.3/create_ticket` preview; it reports `effect: none`.

The constructor requires injectable boundaries:

- `clock.now()` supplies the authorization and receipt time;
- `capabilityVerifier.verify(...)` supplies the authority verification seam;
- `workloadIdentityProvider.current()` supplies the authenticated caller;
- `executor.assertSupported(...)` and `executor.execute(...)` supply the one
  bounded pilot operation;
- `brokerIdentity` identifies the receipt producer.

The included `ContractOnlyCapabilityVerifier` is deliberately
non-cryptographic. It proves schema and approval binding for this fake only. It
is not a JWT, signature, PKI, mTLS or issuer-authenticity implementation, and
the Broker refuses to run when no verifier is injected.

## In-memory safety properties

Before execution, the Broker validates every input contract and requires:

- exact workflow ID and canonical workflow digest;
- exact approval ID, current approval validity and approved node scope;
- exact run, step, proposal, action, connection, destination and policy bounds;
- exact payload digest and payload size bound;
- exact workload and instance identity;
- current, non-revoked Capability Claims;
- a previously established Evidence digest;
- a never-consumed capability `jti`;
- a non-conflicting idempotency key.

State changes pass through the canonical closed transition matrix. A coherent
repeat with a fresh capability returns the original completed receipt without
calling the executor again. Reuse of the original `jti` is rejected. Reuse of
an idempotency key for different action content is rejected. Any uncertain
executor outcome becomes `INDETERMINATE` with `retryable: false`; a coherent
repeat returns that receipt and never starts another execution.

These are process-memory properties, not durable or distributed guarantees.
They do not establish exactly-once delivery. A process restart loses replay,
state and idempotency memory.

## Receipt and Evidence seam

The Broker emits a contract-valid Action Receipt whose evidence digest binds
the full receipt and the mandatory previous event digest. No independent
Evidence Plane is implemented. The deterministic receipt and a source-bound
proof manifest are checked with:

```text
npm run verify:broker
```

## Explicit non-goals

Lot 2B does not implement real authorization tokens, PKI, mTLS, a Secret
Manager, an external provider, an Evidence service, Automation Engine, MCP
Automation, persistence, a queue, networking, deployment or Lot 2C.
