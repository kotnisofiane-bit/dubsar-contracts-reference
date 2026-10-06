# Lot 2B contract binding correction

## Demonstrated gap

The Lot 2B Broker must verify an exact `workflow_id` and `approval_id` and must
prove complete consistency between the Action Proposal and Capability Claims.
The initial v1 proposal and claims carried only `workflow_digest`. That digest
can bind a supplied Workflow IR, including its identifier, but neither contract
carried the approval identifier. A Broker therefore could not prove that the
proposal, capability and Approval Record referred to the same Core decision.

## Bounded correction

Before any runtime integration, `workflow_id` and `approval_id` are made
required in both `action-proposal` and `capability-claims`. Capability
consumption compares both values exactly in addition to the existing digest,
run, step, action, payload, destination and workload bindings.

No authority allocation changes: the Automation Engine still owns proposals,
Governance Core still owns approvals and capability decisions, and the Broker
only consumes their bounded records. This is a pre-pilot correction to the
unpublished v1 Contract Set, not a compatibility claim for an existing runtime.

All Contract-First schemas, fixtures, semantic tests and hash evidence must be
regenerated and pass before the in-memory Broker is implemented.
