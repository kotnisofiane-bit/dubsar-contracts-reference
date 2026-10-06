# AGENT-CONTEXT-V1-B — readonly My Work and trusted OC selection

V1-B adds source contracts for the read ports that will feed `dubsar.agent-context/1` in V1-C. It does not change the V1-A AgentContext semantics.

## Mission View

`dubsar.my-work-mission-view/1` is a bounded projection of one immutable `readTickets()` snapshot.

Selection is exact only:

1. `ticket.work_id === trusted mission_id`;
2. if no work-id match exists, `ticket.id === trusted mission_id`.

No newest-ticket, title, user-text, LLM, fuzzy or partial match exists. Multiple exact work-id matches are unavailable/ambiguous rather than guessed.

The trusted mission id is a host/server binding and is not a model-selectable MCP argument. Missing host binding produces `availability: missing`.

The view carries objective, criteria, blocker, repository refs and bounded Cursor/Codex execution refs. Full receipts are not copied. Automation is null in V1-B because the current Automation store has project/run bindings but no canonical ticket/mission binding.

## OC selection

`dubsar.my-work-oc-selection/1` names the server-owned selection chosen from an exact trusted mission/project mapping.

V1-B declares one production selection:

- project and mission: one trusted deployment mapping (fixtures use `project-fixture` / `mission-fixture`)
- selector: `mywork.release.current_sha`
- relation depth: 0

Any other mission/project binding is `not_applicable`. There is no universal current-sha fallback.

The privileged helper accepts only the opaque allowlisted `selection_id`; it resolves resource/property/depth itself. Callers cannot submit those fields.

`dubsar.my-work-oc-context-read/1` wraps the selection and the existing bounded OC receipt so absence is explicit without inventing OC data.

