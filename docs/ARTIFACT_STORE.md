# Immutable ArtifactStore

This additive library implements the first publish/read/reconcile segment of
ADR-MVP-021. It stores encrypted bytes in an administered local filesystem and
publication metadata in PostgreSQL. It is not a deployed storage service.

## Contract and integration

`schemas/artifacts/v1/artifact-ref.schema.json` defines the closed ArtifactRef.
Its SHA-256 digest covers the exact plaintext bytes; it is distinct from the
existing domain-separated business `hashPayload`. Objects are buffered and
limited to 1 MiB. Larger documents require a separately qualified streaming path.
The reference carries provenance, classification, expiry, retention policy,
lifecycle and evidence fields. These fields do not implement export or deletion.

Construct `PostgresArtifactMetadata` and `LocalEncryptedBlobs` with the same
server-owned context: tenant, corpus, mission and explicit `exact_context`
mapping to the exact-action namespace. At least corpus or mission is required.
Construct `ArtifactStore` with these ports plus trusted policy, clock, key
reference and Evidence service. The key provider returns a 32-byte AES key.
No key material belongs in an ArtifactRef or metadata record.

`publish({ idempotencyKey, bytes, metadata })` accepts a Buffer and the seven
metadata fields used in the tests. Reusing a scoped idempotency key returns the
same identity only for the same request. `read(artifact_id)` returns verified
bytes and its reference. `ExactArtifactReader` requires canonical JSON and
explicit identity mapping; the existing Gate still verifies business hashes.

## Publication and recovery

Reservation commits STAGING before file installation. AES-256-GCM authenticates
the scope, identity, location, size and digest as associated data. Installation
uses exclusive staging files and directory rename without replacing an existing
nonempty object. The PostgreSQL row lock serializes publishers and readers.
Only verified bytes plus a validated Evidence response permit PUBLISHED.
Evidence must deduplicate the deterministic artifact publication event identifier
and return the same evidence reference on retry. A lost COMMIT response is an
uncertain outcome; reconcile or retry the same idempotency key.

`reconcile(id)` makes missing objects, temporary filesystem access failures and
temporary key outages INDETERMINATE. Integrity failures become QUARANTINED;
quarantine cannot be implicitly released. Restored valid bytes can recover an
indeterminate object while preserving its first publication date and evidence
reference. Policy and expiry are checked before reads and publication. Failed
reads expose no partial content; an explicit reconcile records their state.

`inspectOrphans(limit)` reports at most the requested bounded inventory of
unreferenced installed objects in the current scope. It is not a complete scan,
garbage collector or deletion job. Abandoned staging directories require an
operational recovery procedure; this API does not enumerate or remove them.

## Trust and durability boundary

The root must already exist and be administered by the service operator. Clients
must not write the root or its ancestors. Path traversal, observed symlinks and
object substitution are rejected. Node does not provide a portable race-free
`openat2` boundary against a hostile administrator changing paths concurrently.
PostgreSQL runtime credentials are service credentials, not tenant credentials;
tenant authorization is supplied by the trusted context and policy port.

Linux synchronizes file contents and directory entries, including newly created
partition links, before publishing. Windows directory synchronization is not
claimed: tests there prove process-level reopen behavior, not power-loss
durability. Neither platform test simulates a physical power cut.

Migration 003 is additive. An administrator provisions `dubsar_artifact_runtime`
before migration. That role can select/insert metadata and update publication
fields, but cannot delete, migrate or rewrite existing immutable identity.
SQL triggers preserve the original publication even across INDETERMINATE.

## Qualification and remaining MVP work

`tests/artifact-store.test.mjs` uses real encrypted files with transactional
metadata doubles. The existing PostgreSQL CI additionally tests real SQL,
fresh-process reread, concurrent publication, split-storage failures, role
restrictions and the exact-decision-records Core/Broker path. The executor, policy, keys and
Evidence remain instrumented fixtures. Corrupt content must cause zero Broker
admission consumption and zero executor calls.

Production authentication, operational encrypted volume, managed keys and key
rotation, Evidence availability, backups/restoration, retention enforcement,
exports and deletion remain required integration/lifecycle work before the full
MVP. This segment neither merges another service nor deploys anything.
