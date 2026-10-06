# Lot 2C Core authority and durable Action Broker

## Scope and separation

Lot 2C replaces two Lot 2B simulations without adding a provider effect:

- `Ed25519CapabilityAuthority` is the minimal Core-side signer. Its private
  `KeyObject` is held in a private class field and is never exported by the
  adapter. Test keys are generated ephemerally in memory.
- `Ed25519CapabilityVerifier` is the Broker-side verifier. It receives only an
  admitted Ed25519 public-key ring.
- `PostgresActionStore` owns replay, idempotency, state transitions and receipt
  persistence. `PostgresActionBroker` owns validation and orchestration.
- `DeterministicPilotExecutor` remains the only action implementation and has
  no external effect or network transport.

No mTLS is claimed. An injected authenticated workload-identity provider is
still mandatory, and its result must exactly equal the proposal and capability
workload. The Worker cannot self-assert the identity used for authorization.

## Signed capability protocol

The wire value is a three-segment compact serialization:

```text
base64url(canonical protected header)
.
base64url(canonical signed payload)
.
base64url(Ed25519 signature)
```

The protected header is closed to exactly `alg`, `kid`, `typ` and `v`.
`alg=EdDSA`, `typ=DUBSAR-CAPABILITY+JSON` and `v=1` are constants; there is no
algorithm negotiation or fallback. The signed payload is closed to `schema`,
`iat`, `nbf`, `exp`, the existing v1 Capability Claims, the complete
authenticated workload identity, and domain-separated canonical digests of the
Action Proposal and Approval Record. Numeric temporal claims must exactly equal
the ISO timestamps inside the Capability Claims. The validity interval is
positive and at most 120 seconds.

The Core derives claims from a contract-valid Action Proposal, Workflow IR,
Approval Record and authenticated workload identity. It hashes the complete
contract objects with the existing DUBSAR canonicalization and the
`action-proposal` and `approval-record` domains; no manual field subset is a
second canonical representation. The payload additionally binds the exact
`workload_id`/`instance_id` pair. The Broker recomputes both object digests and
compares the authenticated identity to both the proposal and signed identity
after signature verification.

The public-key ring admits Ed25519 keys by exact `kid`, optional validity window
and revocation state. Multiple admitted keys model overlap during rotation. An
unknown, inactive or revoked key fails closed. This is rotation conformance,
not a production key-distribution or revocation service.

## PostgreSQL model

Migration `001_durable_action_broker.sql` creates one isolated
`dubsar_broker` schema:

| Object | Durable invariant |
| --- | --- |
| `broker_consumed_jtis` | primary-key uniqueness consumes one `jti` atomically |
| `broker_idempotency` | one key, one fingerprint and one action/receipt binding |
| `broker_approval_usage` | one canonical approval digest, immutable limit and transactionally consumed action count |
| `broker_actions` | exact proposal binding, closed state and optimistic version |
| `broker_action_transitions` | ordered transition log with closed transition and authority checks |
| `broker_receipts` | one receipt per action with evidence-digest binding |
| `schema_migrations` | serialized, checksummed and idempotent migration history |

Admission is exposed to the runtime role only through a fixed
`SECURITY DEFINER` function. In one explicit `READ COMMITTED` transaction it
serializes the mutable idempotency and approval keys with advisory locks, then
row-locks existing records. It consumes the `jti`, resolves coherent
repetition before accounting, checks and consumes `max_actions`, creates the
action and records `RECEIVED -> AUTHORIZED -> IN_FLIGHT` before the executor is
called. PostgreSQL uniqueness, row locks and advisory transaction locks prevent
concurrent actions from exceeding the signed limit or causing two executions.
Collisions and rejected admissions roll back without consuming the limit.
The idempotency fingerprint binds both complete canonical proposal and approval
digests, so a reissued or conflicting Approval Record cannot reuse a completed
operation's receipt or accounting identity.

## PostgreSQL authority boundary

Migrations run as a distinct owner role. Application tests and the Broker use
the non-owner `dubsar_broker_runtime` role. That role receives schema usage,
column-scoped read access and execution of only the admitted claim/finalization
functions. It receives no direct `INSERT`, `UPDATE` or `DELETE` privilege and
cannot invoke the internal transition function. The bounded CI provisioning
creates it `NOINHERIT`, without memberships, and proves that it owns no
protected object, cannot create in the Broker schema and cannot `SET ROLE` to
the migration owner. Every `SECURITY DEFINER`
function fixes `search_path` to `pg_catalog, dubsar_broker`, PUBLIC execution is
revoked, and the migration contains no dynamic SQL.

This boundary is intentionally not claimed against the database owner or a
PostgreSQL superuser. Provisioning and protecting those administrative
principals remains an infrastructure authority responsibility outside Lot 2C.

Finalization is a separate transaction because an external effect can never be
made atomic with PostgreSQL. In this pilot the executor has no effect, but the
failure model is kept honest: a process cut after the `IN_FLIGHT` commit leaves
durable uncertainty. Explicit restart recovery records `INDETERMINATE` and a
non-retryable Action Receipt. It never calls the executor again. Lot 2C does
not claim exactly-once behavior.

## Evidence seam and non-goals

Receipts remain contract-valid and bind the supplied previous Evidence digest.
No independent Evidence Plane is implemented. The repository also does not
add an Automation Engine adapter, provider connector, secret lookup, Gateway,
MCP Automation, network listener, deployment or Scaleway resource.

PostgreSQL integration, concurrency, restart and drift proofs run only in the
bounded GitHub Actions service documented in `docs/CI.md`. Docker Desktop and
WSL are not required locally.
