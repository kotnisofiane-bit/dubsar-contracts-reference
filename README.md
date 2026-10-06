# DUBSAR Contracts — reference

DUBSAR Contracts provides deterministic boundaries for governed agentic work.
This repository holds the public contracts and reference implementations of
DUBSAR.

> The software carries reality.
> The model carries judgment.
> Humans retain authority over consequential effects.

DUBSAR Contracts is the reference set of versioned contracts, validators and
small reference implementations that sit **between** AI agents and anything
consequential they might touch. It defines what an agent may see, what it may
propose, how a human decision is bound to exact content, and how an admitted
action is executed at most once and recorded.

This is a contracts-and-conformance repository. It is not a product, a hosted
service, an agent framework or a model.

## Why canonical state and authority live outside agents

An agent's context window is not a source of truth, and a model's output is
not an authorization. DUBSAR therefore keeps three things out of the agent:

- **canonical state** — observations, corrections and derived views are
  persisted and qualified by deterministic code (Operational Context);
- **authority** — capabilities, approvals and leases are issued by an authority
  component and verified by a Broker, never minted by the model;
- **evidence** — receipts and transitions are produced by the Broker from what
  actually happened, not from what the model claims.

The model is consulted for judgment through a closed interface whose outputs
carry `authority: none` and `executable: false`.

## What is implemented

| Area | Content |
| --- | --- |
| Contracts and hashing | JSON Schemas (`schemas/`), contract sets and the closed execution state machine (`contracts/`), deterministic canonical JSON and domain-separated SHA-256 hashing (`src/canonical-json.mjs`, `src/contracts.mjs`), fixtures and hash vectors |
| Operational Context | Observation journal, explicit corrections/retractions, tenant/environment-scoped views, bounded state projection, a lab-only stdio bridge (`src/operational-context/`, migrations `008`, `009`) |
| Judgment | Closed input/output/trajectory contracts and validators for `consult`, `conclude`, `clarify`, `revise`, `stop` (`src/judgment/`, `schemas/judgment/`) |
| Task Lease / S1 | Ed25519-signed task leases and the Task Runtime S1 Gateway probe contract (`src/task-manager/`, `src/task-runtime-s1/`) |
| Broker | In-memory pilot and PostgreSQL-backed Broker: signed capabilities, replay/idempotency, exact-action approval binding, receipts, fail-closed recovery (`src/broker/`, `src/exact-action/`, migrations `001`–`007`) |
| AgentContext / Automation | Read-only AgentContext and automation request/admission/result contracts (`src/agent-context/`, `src/automation-integration/`) |

### Operational Context

Observations are append-only. A correction or retraction is a separate
observation (`observe` cannot carry `correction_of`/`retraction_of`); chained
corrections resolve to the live leaf, and retracting a superseded base does not
erase valid descendants. Views are scoped by tenant and environment. When
supporting observations are unknown, revoked or truncated by the support window,
the view fails closed (`pending_recalculation`, `SUPPORT_WINDOW_TRUNCATED`)
instead of fabricating a current value.

### Judgment

Judgment contracts describe what a model receives and what it may answer.
There is no model, inference runtime, dataset or training material here; all
fixtures are synthetic vectors validated locally.

### Task Lease and admission

A task lease is a signed, bounded grant derived from an admitted action.
The S1 contract defines a local conformance probe only; it is explicitly
`CONTRACT_ONLY_NOT_RUNTIME_QUALIFIED`.

### Broker

The Broker admits an action only with a valid signed capability bound to the
exact approved content, consumes it once, persists transitions and receipts,
and reports uncertain provider outcomes as `INDETERMINATE` instead of retrying
blindly. The synthetic exact-action fixtures SX09–SX17 exercise material
binding, post-approval edits, recipient/attachment/header changes, refusal and
revocation, expiry after a lock wait, concurrent gates, idempotence and a lost
provider response recovered without a second dispatch.

## What the tests prove — and what they do not

The suites prove, against the code in this repository: schema closure and hash
vectors; state-machine and authority invariants; exact-content binding of
approvals; single consumption under concurrency on a disposable PostgreSQL 16;
fail-closed behaviour of Operational Context views; role separation in the SQL
migrations.

They do **not** prove: production security (mTLS, key management, vaults),
any real connector or provider delivery, exactly-once external effects,
availability or performance, model quality, or the behaviour of any runtime
that consumes these contracts. Executors, identities and providers in tests are
instrumented fixtures.

## Relationship to other DUBSAR components

DUBSAR Personal and the DUBSAR Control Plane are separate components that are
intended to consume these contracts. Neither is included here, and this
repository makes no statement about their availability.

## Running the suites

Requirements: Node.js `24.19.0`, and for PostgreSQL suites a **disposable**
PostgreSQL 16 database reachable through `DUBSAR_TEST_POSTGRES_URL`. The tests
create and drop roles and schemas; never point them at a database you care about.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run test:contracts && npm run check && npm run verify:hashes && npm run verify:broker
npm run check:judgment && npm run test:judgment
npm run check:operational-context && npm run test:operational-context
npm run test:s1
npm run test:broker
export DUBSAR_TEST_POSTGRES_URL=postgresql://user@127.0.0.1:5432/disposable_db
npm run test:postgres                         # Broker, one fresh cluster
npm run test:document-access:postgres
npm run test:session-lifecycle:postgres
npm run test:operational-context:postgres
```

The Broker PostgreSQL suite requires a cluster without pre-existing DUBSAR
roles. CI runs each job in a fresh container.

## Repository documents

- [PUBLIC_BOUNDARY.md](PUBLIC_BOUNDARY.md) — what is and is not published
- [PROVENANCE.md](PROVENANCE.md) and `public-source-manifest.json` — file-level provenance
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md)
- [LICENSE](LICENSE), [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
