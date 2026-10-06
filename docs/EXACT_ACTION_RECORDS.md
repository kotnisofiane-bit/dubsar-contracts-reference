# PostgreSQL exact decision records

`PostgresExactActionRecords` implements the `records.withCurrent` port consumed
by `ExactActionGate`. Decisions survive process restarts and current revocation
and approver eligibility are read under PostgreSQL row locks. The adapter is a
trusted internal service API, not an authentication endpoint.

## Data and authority boundary

Construct each instance with a server-resolved `context` containing `tenant_ref`,
`project_ref`, and the complete `mission: { namespace, id }`. The constructor
snapshots that context; requests cannot select another tenant or mission through
the API. Context isolation is enforced by query predicates, not database RLS.
The service role can access all contexts: authenticating/routing callers remains
the responsibility of the trusted service injecting this port.

Three tables in `dubsar_exact_records` separate:

- current subject, active function and eligibility (`authorities`);
- immutable binding, prepared action, exact decision and presentation digest
  (`decisions`);
- monotone current revocation (`revocations`).

The decision service calls `setPrincipal` with an evaluated identity and function,
then `publish({ binding, prepared, decision, presentedDigest })` with the digest
actually shown through the Human Gate. These inputs must come from authenticated
server records, never directly from request JSON. `publish` checks schemas and
binding/preparation/display digests. It does not prove a human viewed a screen,
nor reevaluate the policy itself. A policy/function change requires fresh service
evaluation; a new approval must receive a new immutable decision reference.

Re-publishing identical documents is idempotent, including after revocation.
Different documents under the same context/reference fail with
`EXACT_RECORDS_IMMUTABLE_CONFLICT`. `revoke(ref)` only sets revocation to true.
SQL permissions and triggers reject document updates/deletions and reverting a
revocation. An owner remains trusted and can administer/drop database objects.

Payload and display bytes are not stored here. PreparedAction retains its existing
references; `artifacts.read` is injected separately, following ADR-MVP-021 for
the eventual ArtifactStore. No competing ArtifactRef or Gmail connector is added.

## Transactions and connection budgets

`withCurrent` reads the immutable subject, takes a SHARE row lock on its authority,
then a SHARE lock on the decision's revocation state. It reads the current values
at READ COMMITTED and invokes/awaits the callback exactly once while holding both
locks. Its callback also receives a one-use, callback-scoped transaction handle.
`ExactActionGate` forwards that handle to the Broker, which requires
`store.claimInTransaction(input, handle)` and refuses a store that ignores it.
`PostgresActionStore` runs claim SQL on the authority connection without another
BEGIN, checkout or COMMIT. Revocation takes the authority lock then updates revocation; eligibility
changes update the authority row. PostgreSQL therefore serializes those changes
against ordinary admission callbacks across instances, without a process mutex.

Use a dedicated authority pool, distinct from the `PostgresActionStore` pool.
Each pending admission needs one authority connection. Finalization and recovery
use the Broker pool after admission has committed; the claim does not acquire
a connection from it. Do not pass a checked-out client as a pool or perform
authority writes recursively inside a callback: those patterns can deadlock.
The callback must be bounded by the calling service and
must finish its admission work before resolving. Do not start detached work.

`waitMs` defaults to 3000 (1–60000 allowed). It bounds checkout, SQL statements and
SQL lock waits. A late checkout is released without use. PostgreSQL statement and
lock timeouts are transaction-local. Idle-in-transaction timeout is disabled in
this transaction so the database does not silently release locks during awaited
artifact reads. No JavaScript timeout races the callback and then releases locks
while admission is still running. Pool/query errors are sanitized; callback
errors propagate. Rollback runs on failures and broken connections are discarded.

The authority read and Broker claim now share one PostgreSQL transaction.
Connection loss before commit rolls back both the authority transaction and
the claim. A committed revocation is therefore checked before a new admission,
or waits until that admission commits. Execution starts only after the gate
returns following commit. If the COMMIT response itself is lost, its outcome is
uncertain: never interpret a connection error as permission to resend. Read
Broker state and use the existing conservative INDETERMINATE recovery.

This replaces the first candidate's two-transaction design, which independent
review showed could consume a JTI after loss of the authority lock. The
narrow gate/Broker/store scope extension closes that failure window. Tests cover loss during artifact reads with a subsequent
committed revocation, loss after claim SQL before commit, and expiry after SQL.

## Owner migration and runtime provisioning

Provision a dedicated non-owner role before running the existing migration runner:

```sql
CREATE ROLE dubsar_exact_records_runtime
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
```

Configure its connection authentication outside this repository. Apply
`applyBrokerMigrations(ownerPool)` with the database owner: the existing runner
automatically discovers/checksums `002_exact_action_records.sql`, serializes
migrations, and installs it transactionally. The migration is additive; existing
Broker tables and contract/hash files are untouched. The owner and authority
runtime roles must remain distinct. The runtime role receives schema usage,
SELECT/INSERT on the three tables and UPDATE only on current eligibility/function
and revocation. It also receives USAGE on the Broker schema and EXECUTE on the
existing security-definer claim function, so admission can run on the same
connection. It has no direct Broker-table mutation, finalization function,
schema creation, migration, DELETE or TRUNCATE rights.
These write privileges are service authority, not privileges for an end user.

## Qualification

Run `node --test tests/*.test.mjs` for component checks, plus `check`,
`verify:hashes` and `verify:broker` through the existing package scripts.
`npm run test:postgres` requires the existing disposable PostgreSQL CI database;
it verifies migrations, a fresh Node process reading persisted records,
Core/Broker integration, wrong contexts, refusal/revocation/ineligibility,
concurrent revocation and function changes, failure cleanup and runtime rights.
Concurrency tests observe actual PostgreSQL lock waiters before releasing a
deterministic callback barrier. Their completion does not prove product E2E.

The executor, immutable artifact reads, signing identity and human identity
inputs remain test fixtures. No Portal, Python Core, authentication provider,
ArtifactStore, Gmail/Drive connection, delivery or business outcome is qualified.
