# DUBSAR Judgment Interface V1

Status: draft contract, pure local conformance. No inference runtime, model, MCP call, service,
storage, approval, business effect or deployment is implemented.

Le logiciel porte le réel. Le modèle porte le jugement. L'humain garde
l'autorité sur les effets importants.

## Dedicated additive contract space

| Document | Version | Consumer |
| --- | --- | --- |
| [input.schema.json](../../schemas/judgment/v1/input.schema.json) | `dubsar.judgment.input/1` | Semantic data actually supplied to a model |
| [output.schema.json](../../schemas/judgment/v1/output.schema.json) | `dubsar.judgment.output/1` | Untrusted model judgment |
| [trajectory.schema.json](../../schemas/judgment/v1/trajectory.schema.json) | `dubsar.judgment.trajectory/1` | Technical per-turn record, never supplied as semantic context |
| [common.schema.json](../../schemas/judgment/v1/common.schema.json) | Shared closed definitions | Schemas only |

Every object is closed. Every envelope fixes `authority=none`,
`content_trust=advisory_data`, `text_role=data`, `truth=not_selected`,
`executable=false`. A structurally accepted judgment is still advisory. Neither
its status nor its digest is a selected truth, permission, approval or instruction.

The optional textual `advisory` has only `content_trust=advisory_data`,
`ignored_by_authority=true` and bounded `text`. It MUST NOT participate in effect
admission, authorization, gate records or execution dispatch. It cannot supply
claims, endpoints, arguments or missing-information IDs to the structured path.

## Existing sources and limits, unchanged

Read before this contract:

- AgentContext V1, [V1-B ports](../agent-context/AGENT-CONTEXT-V1-B.md),
  the automation-results extension, and their
  current Mission View, OC selector, `accepted_context` and Automation schemas;
- [Memory Plane contract](../MEMORY_PLANE_V0.md) and the current Memory v2
  `SourceInput`, `RelationRecord`, provenance and acquired TM03–TM06 docs;
- the My Work automation bridge, E1/E5 schemas, the Automation to OC projection,
  exact OC observation/state projection and authorized Evidence readers;
- My Work's acquired accepted-context binding, source snapshot digest and
  readonly mission/results readers.

No AgentContext schema, capability, authority, Mission View or TM05 binding is
changed. `execution_refs.automation=null` stays unchanged. Automation remains
My Work provenance, not a fourth authority. TM06 can later be evaluated as a
partial-conservation scenario; TM03–TM06 domain concepts are not new AgentContext
fields or judgment movements.

Available/missing/unavailable/not_applicable and current/stale/unknown retain
their meanings. Source time is copied from the source or null, never inferred
from a publication/read/trace time. `historical` records are not current state.
My Work's unknown freshness is not silently upgraded. Only qualified OC state
can substantiate a `current_state` claim: current freshness, current temporal
scope, eligible value and matched content are required.

E5 `succeeded` is a recorded run result. Its `mission_criteria=not_evaluated`
and nested references' `reference_contents_read=false`,
`reference_availability=not_checked` survive this projection. Actually reading
the E5 does not read its nested receipt/artifact contents. A separately authorized
Evidence element is needed to describe such a read. V1 does not establish mission
criteria fulfillment, even if a run is succeeded or a provider returned HTTP 200.
An isolated recorded terminal run has `result=missing`, null event ID and an
explicit `RESULT_NOT_DOCUMENTED` limit; it cannot support documented-result claims.
Unqualified OC state has no candidate value; historical OC observations can retain
their value with historical/stale limits. My Work freshness remains unknown.

`content_verification=matched` means a trusted reader supplied verified source
content and a bounded data projection. The source digest identifies the source
record, not the selected prose. This pure contract checker cannot authenticate a
reader, verify remote contents or infer their semantic truth. These attestations
must come from the existing trusted readers, never the model.

## Input: server-owned semantic envelope

The server supplies exact `scope={project_id,mission_id,ticket_id}`, `question`,
`context`, software-owned `claims`, `missing_information`, `consult_catalog`,
`budget` and optional `previous_judgment`.

`context` includes the original AgentContext digest when available, exact
element references/digest schemes, declared origins, explicit limits, whole-item
omission counts and `snapshot_atomic=false`. Separate source reads are not a
transaction. Each element preserves source, kind, source date, availability,
verification, freshness, temporal scope, upstream origin IDs and limits.
Its bounded text is data; unverified/reference-only content is null.

Claims are IDs and statements supplied by software, with eligible element IDs,
required limit IDs and structural support requirements. Claim kinds are
`automation_result|mission_criteria|current_state|relevance|evidence_sufficiency|source_consistency`.
The model can assess a supplied claim but cannot mint another one. Verified
content is required for supported/not-supported conclusions. These checks prove
structural admissibility, not semantic correctness: judging the relevance or
meaning of the evidence is evaluated separately.

Origins are server-resolved exact upstream identities. E5 and its derived OC
observation share the same upstream origin. Different IDs for the same origin
reference are rejected. The validator counts conservative connected groups of
declared shared origins, not references, messages or paraphrases. Partial/unknown
provenance never adds an independent support. Hidden ancestry cannot be inferred
by this pure checker and remains the responsibility of the trusted composition.

`previous_judgment.response_ref` identifies the previous cognitive judgment
needed by `revise`. It is not a session/runtime ID or execution token. Session,
runtime, request and turn correlation belong only in the technical trajectory.

The dedicated input is bounded to 32 KiB UTF-8 and 9,000 Unicode characters of
canonical serialized JSON, a conservative ceiling including its catalog/claims.
It admits at most 20 Memory relations, 32 elements, 8 claims, 16 consult entries
and 32 limits. The existing Memory depth-1 policy remains a reader precondition.
This validator does not implement a shrinker: the future composer must omit whole
elements/claims/entries, record counts and retain exact scope/current OC state.
Overflow is refused, not silently shortened. UUIDs, digests and refs are not cut.

## Consult catalog: declarations, never credentials or runtime routing

`owner=server`, `effect=readonly`, with closed entries:

```text
consult_id, target_element_id,
read_kind=mission|memory_relation|memory_history|oc_observation|automation_e5|evidence_content,
purpose, state=available|already_consulted|unavailable,
expected_freshness=current|stale|unknown,
cost_microusd={value,method,basis}, latency_ms={value,method,basis}
```

Only a catalog ID is returned by the model. No endpoint, namespace, credential,
callback, file path, URL or free tool arguments occur in the catalog/output.
Exact reader selection, namespace, trust, rights and transport remain private
server configuration. A constant `owner=server` is not authentication: the future
consumer must use its original trusted catalog, not a catalog echoed by a model.

Cost is integer micro-USD, latency is integer milliseconds. `method` is
measured/estimated/unknown; unknown value/basis are explicit null/unknown. These
are information for judgment, not guaranteed billing or latency bounds. A finite
budget with unknown or excessive estimates refuses consultation. Actual usage
is separately measured in the trajectory. Unknown does not mean zero.

Repeated consultation without new source information is not a V1 refresh path.
An already-consulted entry, a fresh alias of the same target/read kind, or an
available entry whose target content is already matched is rejected. Future
legitimate new observations require a new trusted input/identity; model output
cannot rearm an old read or any mutator.

## Five closed output payloads

Every output has `format`, the five fixed semantics, `move`, its one payload and
optional `advisory`. Status is `supported|not_supported|undetermined|conflicted`;
these are judgment statuses, never domain lifecycle/state transitions.

| Move | Exact payload fields |
| --- | --- |
| `consult` | `consult_id`, `reason`, `limit_ids` |
| `conclude` | `status`, `claim_ids`, `element_ids`, `limit_ids` |
| `clarify` | `missing_ids`, `limit_ids` |
| `revise` | `previous_response_ref`, `change`, `status`, `claim_ids`, `element_ids`, `new_element_ids`, `limit_ids` |
| `stop` | `cause`, `limit_ids` |

Consult reasons: verify_reference, resolve_conflict, check_freshness,
fill_missing_source, assess_relevance. Clarify references declared missing
information (objective, criterion, source, user_selection, scope_ambiguity);
it neither requests nor records an effect approval.

Revise changes: strengthened, weakened, contradiction_identified,
conflict_resolved, withdrawn. The previous response and same claims must match;
status must change and the new element IDs must be newly used matched reads.
It changes only the judgment and never an admission, retry marker or execution.

Stop causes: insufficient_evidence, limit_reached, budget_exhausted,
source_absent, contradiction, clarification_required, no_useful_consultation.
Observable causes such as exhausted budget/absent source/blocking clarification
must agree with the input. Semantic insufficiency remains a judgment.

All mandatory limits and those of used elements/claims must be preserved by ID.
Unknown IDs, dropped limits, undeclared consults, missing evidence, stale/current
confusion and unjustified supported conclusions are refused. No output contains
a free authoritative statement or a business effect.

## Technical trajectory and exact bytes

One bounded record per turn carries trajectory/request/turn/session/runtime
identities, previous-turn digest, contract/prompt/model versions, exact
`input.sent_utf8`, raw reply, validation/rejection, requested/read consultations,
source origins/limits, measured usage and optional human judgment feedback.

The input sent to a future model must be the canonical JSON bytes specified by
`src/canonical-json.mjs`. It has no self-digest field. The trace carries:

1. `sent_digest=SHA256(exact UTF-8 bytes sent)`;
2. `canonical_digest=domainSeparatedHash(dubsar.judgment.input.v1,input)`;
3. `raw_digest=SHA256(exact raw reply UTF-8 bytes)`.

These are distinct identities. The existing domain-separated codec uses a NUL
separator. Native Automation hashes use their existing codec/domain and are not
recomputed as judgment hashes. AgentContext's own digest/exclusions and My Work
snapshot/Memory source digest conventions stay unchanged.

### Inherited digests: native values, closed source codecs

Judgment's `sent_digest`, `raw_digest`, `canonical_digest` and
`previous_turn_digest` remain `sha256:<64 lowercase hex>`, with the same byte and
domain-separated algorithms. A source digest is a different type: copy its value
byte-for-byte, without adding/removing a prefix or hashing it again.

The following pairs are the entire V1 reference registry. An arbitrary scheme,
wrong prefix, uppercase hex or a partially null pair is refused by the schemas.
Unknown/unprovided digests use **both** `digest=null` and `digest_scheme=null`.

| Source identity | Closed `digest_scheme` | Native `digest` format | Source codec |
| --- | --- | --- | --- |
| AgentContext `context_digest` | `sha256-canonical-json-agent-context-v1` | 64 lowercase hex, no prefix | `src/agent-context/index.mjs:agentContextDigest`, acquired exclusions unchanged |
| Automation E5 `event_digest` | `dubsar.automation.run-event.v1` | 64 lowercase hex, no prefix | `src/automation-integration/index.mjs:hashAutomationContract('event', event)`, acquired LF/domain codec unchanged |
| Memory v2 provenance `content_digest` | `memory-v2-content-digest` | 64 lowercase hex, no prefix | Memory Plane `digest.py:content_digest`, SHA-256 of the original source text UTF-8 |
| OC observation fingerprint | `dubsar.oc.observation.v1` | `sha256:` + 64 lowercase hex | `src/operational-context/contracts.mjs:observationFingerprint`, existing observation content basis/domain unchanged |
| Evidence/immutable artifact bytes | `sha256-bytes` | `sha256:` + 64 lowercase hex | `src/artifacts/contracts.mjs:bytesDigest`, exact stored bytes |

Where the source record exposes no separate scheme field (AgentContext, Memory
content digest, ArtifactRef), this closed name identifies the existing codec in
Judgment; it neither adds a field to that source nor defines a new hash variant.
`context.agent_context_digest` has its fixed native AgentContext type; it is not
a Judgment technical digest and has no model-selectable scheme.

Automation, Memory and OC-observation elements must use their respective native
scheme when a digest is present; another admitted codec cannot relabel them.
Repeated exact record references in elements/origins must carry the same pair.
The OC state-projection contract has no native digest field: the revision vectors
use a declared immutable snapshot artifact's byte digest, not an invented OC
state fingerprint. A Memory source-content digest is not a digest of the entire
RelationRecord or a My Work accepted-context snapshot. Those identities cannot
be substituted for each other. Source codecs not listed here need an explicit
reviewed extension; a generic scheme string is not an escape hatch.

The portable [source interop vectors](../../fixtures/judgment/v1/source-digest-interop.json)
were generated directly with the acquired `agentContextDigest` and
`hashAutomationContract('event', ...)`. Tests insert their unmodified return
values into valid Judgment inputs and compare UTF-8 bytes, then refuse changed
representations/incompatible schemes. The captured trajectory also rejects a
changed source scheme relative to the exact input. These pure checks establish
format and binding compatibility, not external authenticity or semantic truth.

Source corrections change the exact Judgment input bytes, so the corresponding
golden sent/canonical/trajectory values and chain links are recomputed. Their
technical schemes, algorithms and five movement payloads are unchanged.

The future adapter must record any transport/system prompt wrapping separately
by exact immutable prompt reference/digest; `sent_digest` does not pretend to hash
an entire provider HTTP request. Prompt/model IDs and measurement metadata are
technical trace fields, not semantic input.

Raw JSON parsing is strict: duplicate keys (including escaped duplicates), JSON5,
excessive depth and trailing content are rejected. A rejected response retains
its raw bytes/digest, null validated output and the deterministic rejection
codes. A validated output must match the raw parsed output and pass contextual
validation against the actual sent input. Actual consulted results must preserve
the exact target reference and digest or remain explicitly unverified/changed;
no substitute source is accepted.

Token methods: provider_usage/tokenizer/not_measured. Latency method:
monotonic_clock/not_measured. Cost method: provider_bill/token_price_estimate/
not_measured, with pricing reference for an estimate. Unknown measurements are
null, not fabricated zero. Human feedback is `kind=judgment_feedback` and
`effect_approval=false`, with an opaque reference and optional advisory note;
it is separate from Human Gates and cannot authorize an effect.

This lot defines records, not a writer or append service. A standalone record's
previous-turn digest is only a link. The pure offline chain validator checks
supplied prior turns, immutable scope, exact hashes, previous responses and
unchanged claim meaning across revisions. It never fetches or appends a record.
Durable append/capture behavior still requires the future trace composition.
Session references and raw content are private technical data. Dataset export
will need policy, redaction and accessible prompt/input artifacts. A reference
alone is insufficient to reproduce what the model actually saw. No hidden chain
of thought is requested or required.

## External references read, no dependency

At Qwen-Agent commit `31a4d36d123688581a9e9744427272b33ce940e0`:

- [Qwen-Agent message/function-call schema](https://github.com/QwenLM/Qwen-Agent/blob/31a4d36d123688581a9e9744427272b33ce940e0/qwen_agent/llm/schema.py)
  separates function name, argument JSON and returned messages. DUBSAR instead
  exposes only its closed catalog ID/payload; no agent loop/tool implementation,
  dependency or framework code is imported.
- [DeepPlanning](https://github.com/QwenLM/Qwen-Agent/blob/31a4d36d123688581a9e9744427272b33ce940e0/benchmark/deepplanning/README.md)
  and its [benchmark description](https://github.com/QwenLM/Qwen-Agent/blob/31a4d36d123688581a9e9744427272b33ce940e0/qwen-agent-docs/website/content/en/benchmarks/deepplanning/index.mdx)
  distinguish trajectories, proactive information acquisition, local constraints,
  global constraints and outcome scoring. They are future evaluation references,
  not a DUBSAR runtime, dataset, travel/shopping model or training dependency.

The interface, model candidate, curated dataset, training procedure and inference
runtime remain separate. Qwen3.5-2B can be considered later; no model is required
to validate this contract.

See [examples](EXAMPLES.md) and [pure conformance](CONFORMANCE.md).
