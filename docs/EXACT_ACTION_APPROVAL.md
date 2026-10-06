# Exact action approval v2

An approved workflow does not itself prove that a person approved the final
recipient, body or attachment. This opt-in Core/Broker path binds the exact
material content and its presentation to a server-owned mission and an
authoritative human decision before durable action admission.

## Versions and identity

The closed schemas live in `schemas/v2/`, their index in
`contracts/v2/contract-set.json`, and positive/negative fixtures in `fixtures/v2/`.
ActionProposal, WorkflowIR, WorkflowApproval and embedded capability claims
retain their v1 schemas and hash domains. No v1 schema or hash vector changes.

MissionBinding v2 binds tenant, project, run, step, proposal and complete workload
identity. The mission and legacy references retain explicit namespaces and the
original identifiers: `scribe-backend:mis_...` is not rewritten to
`task-runtime:mission_...`. The binding comes from the injected server authority.
It is not inferred from a prefix, a user-provided tenant or a client APPROVE object.

PreparedAction v2 binds that identity, both complete v1 proposal/approval hashes,
an immutable payload artifact, a complete display manifest, the expected effect,
adapter digest and resolved material configuration (including its digest), and
validity dates. ExactDecision v2 binds the prepared/display/binding digests, an
authenticated subject acting in an eligible function, the workflow policy,
APPROVE/REFUSE and its own validity interval. Revocation remains current state
owned by the decision service, outside the immutable decision document.

The signed compact envelope uses the existing canonical JSON/base64url and
Ed25519 implementation, with protected header `v: 2` and payload schema
`dubsar.signed-capability.v2`. Its signed `exact_action` proof binds the complete
mission identity and decision/preparation/display digests. There is no nested
usable v1 token. Stripping the proof changes the signed bytes. A verifier
configured for version 1 rejects version 2, and vice versa. The embedded v1
claims are data within this v2 envelope, not a separately signed authorization.

`hashExact(kind, value)` uses `dubsar.exact-action.<kind>.v2`; payload/display use
the existing `hashPayload` domain. Receipt evidence uses
`dubsar.evidence.action-receipt.v2`. Fixed vectors are stored in `contracts/v2/`.

## Server integration contract

1. Resolve the authenticated tenant/project/mission on the server. Construct the
   binding and complete canonical proposal with all material values resolved.
2. `prepareExactAction(...)` produces the prepared record and display manifest.
   Persist the payload and display in immutable artifact storage. Preparation
   is ordinary data and never grants execution authority.
3. Present the complete manifest through the Human Gate. The decision service
   records the authenticated subject, eligible active function, evaluated policy
   and the digest actually presented. Persist the immutable decision and a
   separate revocation record.
4. Inject `ExactActionGate({ records, artifacts })` into Core and Broker. Core
   calls `issueExact({ proposal, workflow, approval, workloadIdentity,
   decisionRef })`. A Core configured with this gate refuses `issue(...)`.
5. Configure `Ed25519CapabilityVerifier({ keyRing, version: 2 })` and an executor
   with `exactMaterial`, then submit the ordinary Broker request containing
   `signedCapability`. Broker resolves the signed decision reference again,
   verifies current authority and immutable artifacts, checks executor material,
   and admits the action through the existing durable store.

The server must choose the exact endpoint from its own policy. Never let a client
select a legacy endpoint to bypass exact approval. A Broker with an exact gate
rejects a verification lacking an exact proof, even if its verifier is accidentally
configured for v1; a Broker without that gate rejects an exact proof.

### Required ports (not implemented product services)

`records.withCurrent(decisionRef, callback)` must resolve only records authorized
for the authenticated server context, and invoke/await the callback exactly once
with `{ binding, prepared, decision, revoked, principal }`. Principal supplies
`subject`, `active_function`, `eligible` and `presented_digest` from trusted
authentication, policy and presentation records. It must not copy those values
from request JSON. Changing the active function or policy requires reevaluation.

This port must serialize revocation and eligibility changes with the whole awaited
callback, including the Broker PostgreSQL transaction. A process-local mutex is
insufficient across Core/Broker replicas. The product adapter must provide a
shared transactional lock or an equivalent authoritative admission protocol.
The [PostgreSQL records adapter](EXACT_ACTION_RECORDS.md) now supplies durable
records and SQL locking for this port; its failure boundaries and qualification
are documented separately. Authentication and presentation services remain
integration work. A truthy boolean
or a fabricated adapter is not proof of authentication; injected server code is
part of the trust boundary, as are the existing key ring and workload provider.

The PostgreSQL records port additionally passes a one-use transaction handle as
the callback's second argument. The gate forwards it as the action callback's
second argument; Broker requires `claimInTransaction` whenever it is present.
The claim and current authority check then commit on the same connection.
Missing store support fails before claim. The owner of the records transaction
alone commits/rolls back; finalization runs through the usual Broker connection
afterward. Legacy test ports without a handle retain their existing interface;
they do not prove durable atomic authority. This handle is trusted in-process
state and is never serialized into a request, proof, capability or receipt.

`artifacts.read(ref)` returns immutable canonical JSON by reference. The gate
checks both the stored digest and exact equality with the inline proposal or
complete generated display manifest. Digest-only proposals are not admitted by
this bounded implementation. Missing artifacts fail closed. The future Portal
must actually render the complete approved manifest; hashing alone cannot prove
that the human saw it.

`executor.exactMaterial` contains `adapter_digest`, `configuration_digest` and
the full resolved `configuration`. The Broker captures it at construction,
compares it with approved material, and passes it with the cloned proposal and
proof to `execute(...)`, recursively frozen. The adapter must exclusively use
these snapshots and the pinned implementation. It must not reread mutable
configuration, resolve implicit recipients or fetch mutable attachment content.
An actual provider adapter and digest-to-code attestation remain integration
work; this library cannot force arbitrary injected code to obey its contract.

All material message fields must already be explicit in the proposal: from/to,
cc/bcc, subject, text/HTML, attachments and defaults. The test uses email-like
content through an instrumented generic executor; it is not an email connector.
Provider credentials remain outside these objects and must not be stored in
payloads, configuration, fixtures or receipts.

## Admission, replay and evidence

The gate checks the current clock after asynchronous artifact reads. The signed
expiry is bounded by the prepared action, exact decision and workflow approval.
Broker rechecks validity immediately before claim; the PostgreSQL adapter also
invokes an admission check after SQL lock waits and before commit. Failure rolls
back JTI consumption, approval usage and pending action. Admission is the
authorization boundary: later revocation/expiry does not undo an already admitted
external action. Cancellation of admitted work requires a separate protocol.

The v2 idempotency fingerprint includes the full exact proof, so an already
consumed action cannot silently move to a new mission or human decision.
Every capability JTI is single use. A completed-operation lookup through submit
requires a fresh capability with the same proof; it returns the original receipt
and does not resend. Revoked/expired work should be inspected through read-only
receipt/state retrieval instead of requesting a new capability.

The exact proof is persisted in `pending_context` and in the closed v2 receipt.
Existing JSONB storage and SQL constraints support these additive documents;
no migration or v1 manifest rewrite is required. Recovery only finalizes
INDETERMINATE and never invokes the executor. A crash after provider acceptance
but before durable finalization therefore does not authorize a blind resend.

A v2 receipt retains the action/run/step, provider result digest/status and evidence
chain, and adds the exact proof. `business_outcome: UNOBSERVED` is mandatory.
SUCCEEDED means a valid instrumented/provider acceptance response (2xx), not a
confirmed business outcome or delivery. Non-2xx, thrown/invalid responses and
interrupted finalization remain conservative INDETERMINATE outcomes. This is
not a claim of exactly-once external execution.

## Validation and limits

Run `node --test tests/exact-action.test.mjs`, `npm test`, `npm run check`,
`npm run verify:hashes`, and `npm run verify:broker`.

The 38 exact tests cover A01–A09 at the component boundary: immutable material,
server identity mutations, absent/forged client approval, refusal/revocation,
expiry including asynchronous reads, incompatible versions, signature stripping,
concurrent submissions, recovery before/after the instrumented call, mission
rebinding, frozen inputs, stored vectors and SQL-adapter rollback. The existing
67 tests remain included in the 105-test suite.

The independent review of the initial candidate found two receipt-validation
gaps. The validator now recomputes the embedded binding digest and requires
a 2xx provider status for a successful v2 receipt. Regression tests rehash the
outer receipt after changing the mission or status, so they exercise semantic
validation rather than merely detecting a stale outer hash. These checks do
not authenticate a receipt by themselves; an unkeyed digest is not authority.

Concurrency/restart tests use a serialized in-memory store double; the SQL-adapter
rollback test uses a recording database client. Neither proves a running
PostgreSQL transaction or a distributed authority lock. The existing PostgreSQL
integration suite includes three new exact-mode PostgreSQL scenarios (independent
Broker gates, recovery after finalization failure, and transactional expiry
rollback); it has not been run locally for this lot. The existing PR conformance
workflow runs that suite without any workflow change. No Backend, Portal, identity
provider, Human Gate service, ArtifactStore or real provider is connected here.
The draft requires review and later integration qualification. No production
E2E, merge, deployment, provider delivery or completed MVP is claimed.
# ArtifactStore integration

The optional [ArtifactStore reader](ARTIFACT_STORE.md) supplies verified canonical
JSON from encrypted immutable objects. Configure its explicit server-owned
exact-context mapping; existing business hashes and Gate checks remain required.
