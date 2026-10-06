# Synthetic exact-action qualification fixtures (SX09–SX17)

`synthetic_public_fixture: true`. Every value, text and attachment here was
written from scratch for conformance testing. Nothing is copied or derived from
any private corpus.

SX09–SX17 cover exact material binding, post-approval edits, recipient/attachment/header
alterations, refusal and revocation, claim-lock wait across expiry, two
concurrent gates on one idempotent request, and a lost provider response that
recovers as `INDETERMINATE` without a second dispatch.

The `.invalid` addresses and the destination are not connected to any
provider. No approval marker here is authority; the trusted test record is
built by `tests/helpers/exact-action-fixture.mjs`.

SX09–SX14 run in `tests/synthetic-exact-action.test.mjs`. SX15–SX17 run in the
disposable PostgreSQL suite `tests/postgres/durable-broker.integration.test.mjs`.
