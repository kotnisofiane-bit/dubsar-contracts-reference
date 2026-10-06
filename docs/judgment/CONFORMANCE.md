# JUDGMENT-CONTRACT-01 — pure conformance

The portable [conformance vectors](../../fixtures/judgment/v1/conformance.json)
name an input fixture, an RFC 6902 add/replace patch subset, an output and exact
expected validation codes. The helper only applies local fixture patches.

| Case | Expected |
| --- | --- |
| E5 succeeded, mission criteria not evaluated | Supported run-documentation judgment; limits retained |
| Run succeeded treated as mission complete | Rejected |
| Stale observation considered with its limit | Undetermined accepted |
| Stale observation presented as current | Rejected |
| Reference without verified content | Undetermined accepted |
| Reference treated as verified content | Rejected |
| Contradictory source elements | Conflicted judgment, no truth selection |
| Pertinent available source not yet consulted | Exact catalog consultation accepted |
| Consultation outside catalog | Rejected |
| Unnecessary repeated consultation | Rejected |
| Clarification needed | Declared missing information IDs accepted |
| Blocking missing information ignored | Rejected |
| Exhausted budget | Stop accepted |
| Consultation with exhausted budget | Rejected |
| Conclusion with no supporting elements | Rejected |
| Revision after new qualified observation | Previous judgment + new read + changed status accepted |
| E5 and derived OC counted as independent proofs | Rejected |
| Same upstream provenance retained explicitly | Undetermined accepted |

Additional tests cover closed objects and refs, advisory text, forbidden authority,
free facts/arguments, cost/latency unknowns, origin aliases, omission counts,
whole-item bounds, hostile/control IDs, duplicate JSON keys, exact raw response
capture, denied/inaccessible consultations, no substitution, separated human
feedback, native AgentContext/E5 digests and immutable repeated validation.
The [source interop vectors](../../fixtures/judgment/v1/source-digest-interop.json)
call the acquired AgentContext/E5 hash functions directly and preserve their
bare-hex outputs byte-for-byte. Tests cover all five closed source scheme/format
pairs, incompatible/unknown schemes, prefix changes, half-null pairs, source-kind
mislabeling, unchanged acquired OC/Evidence codecs and source-pair changes in
captured traces. Judgment technical digests retain their prefixed representation.
They also cover terminal-without-E5, unchanged My Work freshness, suppression of
unqualified OC state values and the offline two-turn revision chain: original
response, unchanged claim meaning, source reads, scope and exact prior-turn digest.

Shared [digest vectors](../../fixtures/judgment/v1/digest-vectors.json) include
Unicode/escaped text and the maximum safe integer, a full input, closed output and
technical trace. They give canonical UTF-8 text, byte SHA-256 and domain-separated
SHA-256 separately. Golden values were computed independently of the validator;
they are usable by another language following the existing JS canonical codec.
No Python-specific digest variant is a new normative algorithm. Floats, -0,
non-JSON values and lossy UTF-8 are not valid identities.

Run only the relevant pure checks:

```sh
npm run test:judgment
npm run check:judgment
node --test --test-isolation=none \
  tests/agent-context.test.mjs tests/agent-context-v1b.test.mjs \
  tests/agent-context-automation-results.test.mjs
```

Static schemas/fixtures are read locally. No PostgreSQL, provider, MCP, Gateway,
Memory writer, effect gate, runtime, dataset or model is used. This qualification
does not prove the semantic quality of a model or the authenticity of an external
reader; those remain separate composition/evaluation obligations.

Qualification locale (Node 24.19.0) : **66 tests Judgment + 18 non-régressions
AgentContext = 84 PASS**, zéro fail/skip. `check:judgment` vérifie 18 vecteurs,
4 vecteurs de digest, 2 vecteurs interop source, une chaîne de 2 tours et 88 références fermées. Le contrôle
pur des 8 contrats canoniques existants reste PASS. Aucun banc/runtime installé
ou appel de modèle n'est revendiqué.

## Before any judgment dataset

Review this draft independently. Then specify data selection and anonymization,
expected judgments and human labeling, provenance-grouped train/evaluation splits,
handling of contradictions/stale/unread/omitted evidence, consult utility and
budget metrics. Judgment feedback is not an effect approval or proof of truth.

A subsequent trusted capture/export composition must preserve exact actual model
input and raw replies, validate prior-turn links and candidate revision history,
and store protected immutable technical artifacts through existing mechanisms.
No new canonical Memory or autonomous execution path is implied by this format.
