# Judgment V1 — bounded examples

All JSON fixtures are local vectors, not new reads or inference. Their `matched`
labels are simulated trusted reader attestations. They create no human decision,
canonical Memory, OC publication or training sample.

The [historical input](../../fixtures/judgment/v1/historical-run-input.json)
uses the synthetic native E5 vector of
`fixtures/agent-context/v1/automation-results-vector.json` and its digest.
Its `reference.digest` is exactly
`95d61d03953af2d90c801f35c4f9896855ea6dc2758ad6562473fde18a8aaab7`,
with `digest_scheme=dubsar.automation.run-event.v1`; no `sha256:` is added.
The [interop vector](../../fixtures/judgment/v1/source-digest-interop.json) also
uses native AgentContext digest
`08c5a5b549da8f64bddc4e5af8c20379d8339cb9b328f93a2e8aeb13b29c3cd1`
without a prefix. Both are recomputed outputs of the pure source functions.
The [output](../../fixtures/judgment/v1/conclude-output.json) evaluates only the
software-provided `c_run` claim. Its exact payload is:

```json
{"status":"supported","claim_ids":["c_run"],"element_ids":["e_e5"],"limit_ids":["l_history","l_mission"]}
```

The renderer could later explain this as: "Le résultat technique est documenté.
Les critères de mission restent non évalués ; l'état externe courant n'est pas
établi." This is a rendering of the structured judgment and retained limits,
not a new authoritative fact emitted by the model.

Other exact payload examples:

```json
{"consult_id":"consult_proof","reason":"verify_reference","limit_ids":["l_history","l_mission","l_reference"]}
```

```json
{"missing_ids":["m_objective"],"limit_ids":["l_history","l_mission"]}
```

```json
{"previous_response_ref":"response_prior","change":"strengthened","status":"supported","claim_ids":["c_current"],"element_ids":["e_now"],"new_element_ids":["e_now"],"limit_ids":["l_history","l_stale"]}
```

```json
{"cause":"budget_exhausted","limit_ids":["l_history","l_mission","l_reference"]}
```

They must be wrapped by `output.schema.json` with the matching `move`, format and
fixed readonly/advisory semantics. No payload field accepts free effect arguments.

## Synthetic scenarios behind the vectors

All identifiers below are synthetic fixture values (`project-fixture`,
`mission-fixture`, `DUB-900`, `run_fixture_example`). No value is taken from a
live DUBSAR system.

The paired-origin fixture models one E5 event recording `succeeded` at
`2026-10-04T00:00:00.000Z` and a derived OC observation
`oco_00000000000000000000000000000001` recording
`automation.run.receipt_status=succeeded` with that same source time. These are
one upstream event, not two independent proofs. The fixture's OC digest is
illustrative, not a verified fingerprint.

A historical Memory relation retained only after contribution approval and a
distinct promotion approval may be assessed for relevance by a later judgment;
the judgment cannot reproduce those approvals, auto-ingest or promote another
record.

Context explicitly accepted for the fixture mission is reread and snapshot
matched. The model sees consideration context, never human identity or action
authority. These contracts do not add external domain concepts to its
AgentContext representation.

The fresh release SHA fixture uses the synthetic value
`1111111111111111111111111111111111111111` to demonstrate revision after a
new qualified read. Its freshness is fixture data, not a deployed release.

The [trajectory example](../../fixtures/judgment/v1/trajectory-valid.json)
has `model:fixture` and not-measured usage; no LLM call occurred. Its semantic
input has no session/runtime/request/turn IDs. Those appear only in this technical
record, along with exact sent bytes, raw response and validation.
