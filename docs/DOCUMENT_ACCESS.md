# Documentary access v1 (DA1)

This private authority grants read scope only. It never creates an approval,
execution capability, lease or external effect. The existing approver registry
and all existing effect contracts are unchanged.

Compose `DocumentAuthority` with a PostgreSQL reader pool, a fixed server
`{tenant_ref, context_ref}`, clock, Ed25519 human-proof public key/issuer and
`verifySession(claims, {signal, context})`. Audience is exclusively
`dubsar:document-access`. The injected session source must verify a fresh current
session and honor cancellation; absent or false source denies, timeout fails
closed. A signature by itself never provisions a session or grants access.
The real Portal B1 source is not delivered or qualified by DA1.

`authorize({proof, context, request_ref, requested_resources})` accepts only the
configured context and 1–100 explicit document references, at most 64 KiB. Every
requested resource must be granted to the current principal/function. Unknown,
disabled or unauthorized resources produce one generic deny, never a partial
list. No wildcard is supported. Results bind versions, session, principal,
request, epoch and a maximum 60-second validity window, capped by proof/session.

`revalidate({proof, decision_id, scope_digest})` reads the immutable persisted
decision and current policy again. A digest is an integrity commitment, not an
offline credential. Do not restore a cached allow on outage. Retrieval must call
authorize before selection and revalidate immediately before restitution.
Neither this module nor DA1 performs retrieval or exposes an HTTP endpoint.

Migration 007 uses the existing additive migration runner. It creates two
NOLOGIN roles: `dubsar_document_reader` and `dubsar_document_admin`. The reader
may select policy, lock its epoch through an immutable false marker, and insert
decisions, but cannot change rights or persisted decisions. The admin has only
the closed `dubsar_document_access.mutate(tenant,context,kind,json)` policy port.
Kinds: context, membership, session, corpus, resource, grant. It locks the epoch
before touching rows and increments it in the same transaction. Direct policy
DML is reserved to the trusted migration owner, never a runtime credential.
Sessions cannot be rebound or resurrected. Administration belongs to a separate
trusted server composition; IPC exposes only authorize/revalidate.

Readers hold the context epoch SHARE lock across the final checks and decision
write, making lower policy rows stable without competing per-row write locks.
Requested resources are sorted canonically. All admin operations lock epoch
first, including creation. SQL statements, lock waits, pool acquisition and the
injected source have finite timeouts; rollback never retries. A revocation
committed before revalidation must prevent allow. Revocation committed after
the final transaction cannot recall already returned bytes. No transaction
spans future retrieval/extraction work.

Private IPC `dubsar.document-access-ipc/1` uses one bounded, correlated frame and
one fresh process per request, with an absolute trusted composition module.
There is no administrative operation, shell, HTTP route or automatic activation.

Qualification: local unit tests; real PostgreSQL policy/revocation/concurrency
tests; paired Python→Node→PostgreSQL with synthetic identity and source; existing
exact action and B1 regressions. A fresh authority/process must reread persisted
decisions. No real Google account, content, secret, send or deployment is proved.
