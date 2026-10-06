# Security policy

## Scope

This repository contains contracts, validators and bounded reference
implementations. It is not a deployed service. Reports are welcome for:

- validation or canonicalization bypasses (a value accepted that the contract
  forbids, or two distinct values sharing a digest);
- authority bypasses (an action admitted without a valid, exactly bound
  capability or approval, or admitted twice);
- fail-open behaviour in Operational Context views;
- privilege issues in the SQL migrations.

## Reporting

Please report privately through GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open a
public issue for an unpatched vulnerability.

## Test material

All keys, tokens, identifiers and URLs in `fixtures/` and `tests/` are
synthetic test values. PostgreSQL suites must only run against a disposable
database: they create and drop roles and schemas.
