# Public boundary

This repository is an allowlisted subset of the private canonical DUBSAR
Contracts source. Anything not listed in `public-allowlist.json` is not public.
When a file's redistribution status was ambiguous, it was excluded.

## Published

- `contracts/`, `schemas/`, `migrations/` (all nine migrations);
- canonicalization and domain-separated hashing, validators and selected
  reference implementations under `src/`;
- Operational Context, Automation, AgentContext, Judgment, Task Lease / S1 and
  Broker contracts and code;
- synthetic fixtures and conformance/adversarial tests, including the
  from-scratch synthetic exact-action fixtures SX09–SX17
  (`fixtures/qualification/synthetic-exact-action/`);
- generic reproducibility tools (`tools/`), `CONTRACT_HASHES.json`,
  `BROKER_PROOF.json`;
- technical contract documents under `docs/`, with private tracker
  identifiers and internal chronology removed.

## Not published

- all of `judgment-data/` (corpus, captures, annotations, training tooling);
- a private qualification corpus and the test cases that depend on it; the
  same exact-action conditions are covered publicly by SX09–SX17;
- private CI (self-hosted runner selection, private baseline comparison) and
  the tests and helpers that assert or prepare it;
- internal reports, results, reviews, delivery manifests, execution contracts
  and tracker chronology;
- documents with SOPHIA or Platform material of ambiguous redistribution;
- the private Git history.

## Adaptation rule

Adaptations only remove private publication context (tracker ids, private
links, base pins, tests bound to excluded material). They do not change
validation, state machines, authority, hashing, security or runtime behaviour.
No file under `src/`, `schemas/`, `contracts/` or `migrations/` is adapted, and
no fixture data is adapted (one fixture README is reworded). Every adaptation is listed in `public-source-manifest.json`.
