# Contributing

Thank you for your interest. This repository is a public reference export of
contracts maintained in a canonical source; changes are reviewed there first.

- Open an issue describing the contract, validator or test you want to change
  and why. Contract changes require a versioned schema/contract identifier and
  updated hash vectors (`npm run verify:hashes`).
- Pull requests must keep every CI job green and must not weaken a fail-closed
  check, an authority boundary or a hash domain.
- Fixtures must be explicitly synthetic: no real people, accounts, sessions,
  hosts, tokens or customer data.
- By contributing you agree that your contribution is licensed under the
  Apache License 2.0 (section 5 of LICENSE).
