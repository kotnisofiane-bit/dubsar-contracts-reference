# Ordered My Work snapshots — OC-MYWORK-CURRENT-01

Opt-in contracts: observation/2, mapping/2, view-request/2, view/2,
state-binding/1 and state-projection/1. Their closed schemas are registered beside
the existing v1 schemas. Existing observation documents are never rewritten.

An observation/2 must match the active admitted binding, producer, source instance,
epoch, mapping and rule before ingestion. Delivery replay retains its original
receipt. Sequence orders snapshots; timestamps only determine freshness and clock
consistency. Conflicting sequence content blocks eligibility even after a higher
sequence arrives. No last-arrival or lexical-reference winner exists.

The view/2 keeps the generic v1 qualification and adds `state_projection` beside it.
The projection includes candidate, history, explicit policy versions, age, freshness,
eligibility, limits and the permanent last-verified-snapshot reserve. A bounded page
that cannot establish completeness returns no candidate. Source and receipt dates
are preserved separately. The selected source date determines age; TTL is inclusive.

Migration 009 is additive and runs after 008. Its immutable policy events record
administrative identity and time. Admission uses `admitStatePolicy(trust,
{binding,mapping,rule})`; revocation uses `revokeStatePolicy(trust,binding)`.
Neither method is exposed by the two-operation bridge. A binding transition names
`supersedes` explicitly (`{absence:"initial"}` for bootstrap, otherwise ref/version).
Concurrent transitions use a transaction lock and compare their predecessor.
An older binding's revocation cannot select it again. Historical views use policies
known and effective at the requested instant. Administrative backdating is refused.

The explicit legacy frontier names existing v1 observations in the exact scope.
Unknown legacy supports after cutover block eligibility. No synthetic sequences,
dates, automatic epoch reset, background refresh or heartbeat are introduced.

Validation: pure unit tests plus disposable PostgreSQL tests. A production install
must pin this repository's reviewed commit/tree, migrate with the authorized owner
workflow, and keep the producer OFF until all consumers understand v2.
