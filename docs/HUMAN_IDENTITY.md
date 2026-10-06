# Human identity adapter

This opt-in adapter associates an authenticated human session with immutable
presentations and exact decisions. It does not implement Portal login or OIDC.
The proof adapter verifies Ed25519 signatures over canonical JSON, issuer,
audience, subject, session, human kind and a maximum five-minute validity.
Production authentication must be supplied by the subsequent Portal adapter;
the qualification emitter and its ephemeral key are test-only.

Provision membership mappings through the administrative owner port, from exact
issuer/subject to principal/context/function. No browser, device credential or
license grants membership. Runtime SQL cannot administer mappings or revoke
sessions. No credential/token is persisted. Session revocation is monotone.

Configure PostgresExactActionRecords with requireHuman and HumanRegistry; absent
decision/session links fail closed. Human checks use the same SQL transaction
as admission. Shared locks cover session, membership, exact principal and
revocation; writers must preserve this ordering. A committed local revocation
before admission prevents it; an earlier admission is not retroactively undone.
Remote IdP logout is not a local revocation until received and committed.

ApprovalService resolves action data from a trusted server port, checks immutable
artifacts, and atomically persists decision, session link and idempotent result.
Refusal stores a result without executable authority. Historic records mode is
preserved and must not be used as a fallback for human-required requests.

SQL role separation and positive/negative tests are in the existing PostgreSQL
suite. No production session, real provider action, deployment or operational
key lifecycle is proven by this library qualification.
