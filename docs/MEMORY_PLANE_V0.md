# DUBSAR Memory Plane v0 — Architecture Contract

Status: **candidate contract v0.1**. This document does not authorize runtime development, VPS installation, deployment, or model selection.

## 1. Purpose

Memory Plane provides DUBSAR with a shared contextual, relational, and temporal memory layer.

It may represent and retrieve entities, relations, decisions, intentions, preferences, hypotheses, facts, references to OC observations, references to My Work missions/evidence, provenance, temporal evolution, supersession, contradictions, and historical context.

Memory Plane is **not** a new operational authority. It does not replace Hermes, Operational Context (OC), My Work, Evidence, or the documentary Knowledge Plane.

## 2. Authority boundaries

### Hermes

Hermes remains responsible for general dialogue, reasoning, Bots/Profiles, sessions, tools/skills, and agentic orchestration.

Hermes may query Memory Plane. Hermes is not the internal storage or authority mechanism of Memory Plane.

### Operational Context

OC remains authoritative for qualified operational observations, operational provenance, freshness, admissibility, current operational state, and operational contradictions under OC contracts.

Memory Plane may retain an opaque reference to an OC observation. It MUST NOT declare that an OC observation is current, fresh, or admissible. Any decision depending on current operational state MUST re-read OC.

### My Work

My Work remains authoritative for missions, objectives, mission state, attempts, blockers, authorizations, results, and evidence.

Memory Plane may retain opaque references to My Work missions/evidence. It MUST NOT reproduce or override the My Work state machine. Any decision depending on current mission state MUST re-read My Work.

## 3. Memory status vocabulary

Memory Plane distinguishes at least:

- `fact`
- `observation`
- `decision`
- `intention`
- `hypothesis`
- `preference`
- `uncertain`

These values describe the semantic nature of a memory record. They do not confer operational authority.

In particular, `observation` in Memory Plane never means “qualified OC observation”.

## 4. Provenance

Every accepted Memory Plane record MUST have sufficient provenance.

Where applicable, provenance includes:

- source type;
- source identifier;
- ingestion timestamp;
- event/observation timestamp;
- original text or payload reference;
- producer;
- extraction method;
- model identifier/version when probabilistic inference was used;
- confidence when applicable.

Information without sufficient provenance MUST NOT become a canonical relation. It MAY remain a candidate or `uncertain`.

## 5. Temporal model

Memory Plane MUST preserve history rather than silently overwrite it.

A relation may expose:

- `valid_from`;
- `valid_to`;
- `supersedes`;
- `superseded_by`.

When a new compatible record replaces an older record:

1. the older record remains stored;
2. its validity may be closed;
3. the new record explicitly references the record it supersedes.

The system MUST support historical queries such as: “what was known or considered valid at time T?”

## 6. Contradictions

Incompatible information MUST NOT be arbitrarily merged.

Memory Plane MUST be able to preserve both claims, their provenance, and an explicit contradiction relation.

A contradiction does not authorize Memory Plane to decide which claim is true. Resolution belongs to a deterministic rule, the relevant source authority, or an explicit escalation path.

## 7. Supersession

Supersession is allowed only when the previous relation can be identified explicitly.

A probabilistic model MUST NOT invent a supersession target.

When a change is detected but the prior target cannot be identified with sufficient certainty, the result MUST be `uncertain` or escalated rather than rewriting history.

## 8. Anti-promotion invariant

The following automatic promotions are forbidden:

- `hypothesis -> fact`
- `hypothesis -> observation`
- `intention -> fact`
- `intention -> decision`
- `preference -> decision`
- `uncertain -> fact`
- `uncertain -> decision`

A specialized model or Hermes MAY propose an interpretation. Only a deterministic writer applying contract rules may accept a Memory Candidate.

Conversational content MUST NOT directly become a qualified OC observation.

## 9. Canonical ingestion pipeline

The canonical path is:

```
Source
  -> deterministic extraction when sufficient
  -> specialized capability when needed
  -> Memory Candidate
  -> schema validation
  -> invariant validation
  -> deterministic writer
  -> Memory Record
```

No model receives direct database write credentials.

No model receives direct write authority over OC or My Work.

## 10. Memory Candidate

Probabilistic output is a candidate, not canonical memory.

A candidate SHOULD contain:

- source reference;
- candidate entities;
- candidate relations;
- candidate status;
- confidence;
- extraction method;
- model/version when applicable.

## 11. Local intelligence policy

Memory Plane follows the capability hierarchy:

1. deterministic;
2. local-specialized;
3. local-light only when justified;
4. Hermes/general model only as explicit escalation.

The lowest layer that performs the function adequately SHOULD be preferred.

Candidate stable capability interfaces include:

- `StatusClassifier`;
- `EntityExtractor`;
- `RelationExtractor`;
- `Embedder`;
- `Reranker`.

Memory Plane v0 MUST NOT depend normatively on a specific model or runtime. GLiNER, sklearn, ONNX, Jev-like/Kev-like models, Ollama, or equivalent technologies are implementation candidates only.

## 12. Hermes escalation

Hermes MAY be used when general understanding is genuinely necessary, including ambiguous relations, unresolved supersession, significant disagreement between deterministic and probabilistic paths, or an `uncertain` result.

Hermes MUST return a structured proposal which passes through the same deterministic validation/writer path. Hermes cannot bypass the writer.

## 13. Storage target

The v0 target is PostgreSQL.

Logical structures include at least:

- `memory_sources`;
- `memory_entities`;
- `memory_relations`;
- `memory_contradictions`.

Embeddings are optional.

Memory Plane MAY share a PostgreSQL instance with other DUBSAR services, but MUST retain separate migrations, ownership, roles, and logical schema/database boundaries. Sharing an instance does not grant implicit access to OC or My Work tables.

## 14. Retrieval

Required for v0:

- structured filters;
- lexical/FTS retrieval;
- temporal filters;
- relation traversal;
- provenance retrieval;
- historical retrieval;
- deterministic result fusion when needed.

RRF MAY be used for deterministic fusion.

Optional capabilities:

- embeddings;
- pgvector;
- specialized reranking.

Vector search is not a v0 prerequisite.

## 15. Opaque OC / My Work references

Memory Plane MAY store opaque references such as:

- `oc_observation_ref`;
- `mywork_mission_ref`;
- `evidence_ref`.

Memory Plane may state that records are related. It MUST NOT infer current OC/My Work state from a cached relationship. Current state MUST be re-read from the relevant authority.

## 16. Idempotence

Ingestion MUST be replay-safe.

A source/event SHOULD have a stable identifier or digest when possible. Re-ingesting the same event MUST NOT create an equivalent duplicate relation.

Deduplication MUST NOT collapse distinct events merely because their text is identical.

## 17. Context View

Memory Plane MAY project a read model for Hermes combining relevant memory relations with references to current authoritative sources.

A Context View may include:

- relevant decisions and previous decisions;
- contradictions;
- relevant document references;
- OC references/current state obtained by re-read;
- My Work references/current state obtained by re-read;
- evidence references;
- provenance.

A Context View is a projection, never a new source of truth.

## 18. Knowledge Plane boundary

The documentary Knowledge Plane primarily answers: “what do the documents say?”

Memory Plane primarily answers: “what is related to what, how did it evolve, and why?”

OC answers: “what is currently observed and qualified?”

My Work answers: “what work is actually committed/underway/completed and with what evidence?”

These boundaries MUST remain explicit.

## 19. Security invariants

Memory Plane v0 forbids:

- model-held database write credentials;
- model writes to OC;
- model writes to My Work;
- model-issued mission authorization;
- model deletion of historical records;
- automatic semantic promotion;
- LLM as source of truth;
- Graphiti runtime as a prerequisite;
- Neo4j/FalkorDB as a prerequisite;
- Ollama as an architectural prerequisite;
- pgvector as an architectural prerequisite.

Model inputs MUST be bounded. Model outputs MUST be schema-validated. Model versions MUST be traceable. Optional intelligence capabilities MUST fail closed.

## 20. Personal vs B2B

The Memory Plane semantic contract MAY be shared across Personal and B2B.

Personal remains mono-user/self-hosted with simple bounded permissions and optional local-specialized capabilities.

B2B may add organization/tenant identity, IAM/RBAC, policies, isolation, enterprise audit/retention, data classification, model governance, and isolated environments.

Those enterprise concerns MUST NOT be imposed on Personal v0 unless separately required.

## 21. Non-goals for v0

Memory Plane v0 does not attempt to provide:

- perfect memory;
- universal understanding of arbitrary conversations;
- universal entity resolution;
- universal relation extraction;
- a full enterprise knowledge graph;
- autonomous graph reasoning;
- replacement of Hermes Memory;
- replacement of documentary RAG;
- replacement of OC;
- replacement of My Work.

## 22. Future development acceptance criteria

A conforming implementation MUST demonstrate at least:

1. idempotent ingestion;
2. provenance preservation;
3. preference != decision;
4. intention != fact;
5. hypothesis != qualified observation;
6. supersession without history deletion;
7. contradiction preservation;
8. historical query at time T;
9. opaque My Work reference;
10. opaque OC reference;
11. models cannot write directly;
12. operation without optional models;
13. fail-closed optional AI capability;
14. Context View traceable to sources;
15. authoritative re-read of OC/My Work before conclusions depending on their current state;
16. candidate lifecycle preserves non-canonical state until explicit promotion;
17. canonical mutation rejects a stale expected state/digest;
18. Context View is bounded and deterministic for the same canonical inputs;
19. content identity/freshness is not treated as semantic or operational truth;
20. concurrent candidate production cannot bypass serialized/transactional canonicalization.

## 23. Current qualification

The Graphiti exploration and Local Intelligence Lab establish, on synthetic fixtures:

- feasibility of the semantic/temporal invariants;
- feasibility of a deterministic-first core;
- conceptual feasibility of PostgreSQL as the target store;
- usefulness of temporal/provenance concepts inspired by Graphiti.

They do NOT yet establish:

- qualified PostgreSQL runtime for Memory Plane;
- qualified pgvector retrieval;
- reliable general NER/relation extraction;
- a selected local-specialized model;
- quality on real conversations;
- real Hermes integration;
- real OC/My Work integration;
- production readiness.

## 24. Human Gate

After review and explicit Human Gate, this contract may authorize preparation of a governed development mission for the **deterministic Memory Plane v0 core**.

It does NOT automatically authorize:

- merge;
- VPS installation;
- deployment;
- model selection;
- Hermes activation;
- OC/My Work migration;
- Portal modification;
- B2B runtime promotion.


## 25. Candidate lifecycle and explicit promotion

Memory Candidates are non-canonical by default.

The minimum lifecycle is:

```
candidate
  -> validated
  -> promotable
  -> canonical
```

Alternative terminal or holding states MAY include:

- `rejected`;
- `uncertain`.

Validation means only that the candidate satisfies the structural and invariant checks required for its stage. It does not confer authority.

A candidate MUST NOT influence canonical retrieval, current-state conclusions, readiness, mission authorization, OC qualification, or My Work state before explicit promotion.

Promotion MUST pass through the deterministic writer and MUST identify the candidate and the canonical state against which the promotion was evaluated.

This principle is inherited conceptually from the earlier DUBSAR Memory pending-candidate model; the filesystem implementation and its checkpoint format are not inherited.

## 26. Preview / expected state / apply

Canonical mutations that alter an existing semantic relation, close temporal validity, resolve a contradiction, or establish supersession MUST be protected against stale writes.

The implementation MUST provide an equivalent of:

```
preview
  -> expected canonical state/digest/version
  -> apply
```

The exact concurrency primitive is implementation-specific. PostgreSQL transactions, row versions, constraints, advisory locks, or equivalent mechanisms MAY be used.

If the canonical state relevant to the proposed mutation changed after preview, the apply MUST fail closed with a conflict/stale-state result. It MUST NOT silently recompute and overwrite a newer state.

A digest/version proves identity of the checked state only. It does not prove semantic truth, freshness, authorization, or external validity.

## 27. Bounded Context View

A Context View MUST be a bounded projection, not a dump of Memory Plane storage.

The implementation MUST define explicit bounds for at least:

- maximum number of returned records/relations;
- traversal depth;
- output size or equivalent context budget;
- deterministic ordering/tie-breaking;
- provenance attached to included records.

A Context View SHOULD prefer the minimum context needed for the requested scope.

For identical canonical inputs, query parameters, capability versions, and authoritative re-read results, deterministic parts of the projection SHOULD be reproducible.

Failure or degradation while building a Context View MUST NOT mutate or reclassify canonical memory.

Optional retrieval/reranking capabilities MAY affect ranking only within their declared contract and MUST expose their version/provenance when they do.

## 28. Identity, freshness, and truth are distinct

Memory Plane MUST distinguish at least these concepts:

- **identity**: whether referenced bytes/data match a recorded digest/version;
- **freshness**: whether a source or authoritative observation is still current enough for its intended use;
- **semantic validity**: whether a memory relation remains applicable in its temporal/semantic scope;
- **authority/truth claim**: whether the relevant authority supports the conclusion.

A matching digest MUST NOT be interpreted as proof that information is still current or true.

Where a reference freshness state is exposed, implementations SHOULD use explicit states such as:

- `same_content`;
- `current`;
- `stale`;
- `unknown`;

or an equivalent closed vocabulary whose semantics are documented.

Operational freshness remains an OC responsibility where OC is the authority.

## 29. Concurrency and canonical writer

Memory Plane MAY accept candidates from multiple producers concurrently.

Canonicalization MUST be serialized or transactionally protected so that concurrent promotions cannot create incompatible canonical states without an explicit contradiction/conflict representation.

A producer identity, process ID, branch name, hostname, model identity, or source label MUST NOT by itself confer write authority.

The implementation MUST re-read or transactionally validate the canonical state relevant to a promotion immediately before commit.

Concurrency conflicts MUST fail closed or produce an explicit conflict requiring resolution. They MUST NOT be hidden by last-write-wins behavior when temporal/supersession semantics would be changed.

This contract does not require the historical DUBSAR Memory single-workspace writer or filesystem lock design. It preserves the invariant while allowing PostgreSQL-native concurrency controls.
