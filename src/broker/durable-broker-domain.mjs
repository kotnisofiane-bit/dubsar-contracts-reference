import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import {
  assertApprovalCurrent,
  assertContract,
  assertNoSecretMaterial,
  hashContract,
  receiptEvidenceDigest,
} from '../contracts.mjs'
import { BrokerRejection, reject } from './broker-error.mjs'

const DIGEST = /^sha256:[a-f0-9]{64}$/

export function validateDurableRequest(request, observedAt) {
  if (!isPlainObject(request)) reject('BROKER_REQUEST_INVALID')
  if (!DIGEST.test(request.previousEvidenceDigest ?? '')) reject('BROKER_PREVIOUS_EVIDENCE_REQUIRED')
  if (typeof request.signedCapability !== 'string') reject('BROKER_SIGNED_CAPABILITY_REQUIRED')
  const proposal = assertInputContract('action-proposal', request.proposal, 'BROKER_PROPOSAL_INVALID')
  const workflow = assertInputContract('workflow-ir', request.workflow, 'BROKER_WORKFLOW_INVALID')
  const approval = assertInputContract('approval-record', request.approval, 'BROKER_APPROVAL_INVALID')
  const workflowDigest = hashContract('workflow-ir', workflow)
  if (proposal.workflow_id !== workflow.workflow_id || proposal.workflow_digest !== workflowDigest) {
    reject('BROKER_WORKFLOW_MISMATCH')
  }
  if (proposal.approval_id !== approval.approval_id) reject('BROKER_APPROVAL_MISMATCH')
  try {
    assertApprovalCurrent(approval, workflow, observedAt)
  } catch (error) {
    if (/expired/.test(error.message)) reject('BROKER_APPROVAL_EXPIRED')
    reject('BROKER_APPROVAL_MISMATCH')
  }
  return { proposal, workflow, approval }
}

export function assertDurableActionScope(proposal, claims, workflow, approval) {
  if (Date.parse(claims.issued_at) < Date.parse(approval.issued_at)
    || Date.parse(claims.not_before) < Date.parse(approval.issued_at)
    || Date.parse(claims.expires_at) > Date.parse(approval.expires_at)) {
    reject('BROKER_CAPABILITY_APPROVAL_WINDOW_MISMATCH')
  }
  const matchingNodes = workflow.nodes.filter(node => node.kind === 'action'
    && canonicalJson({ kind: 'connector_action', connector: node.connector, operation: node.operation })
      === canonicalJson(proposal.action))
  if (matchingNodes.length !== 1) reject('BROKER_ACTION_SCOPE_MISMATCH')
  const node = matchingNodes[0]
  if (!approval.scope.node_ids.includes(node.node_id)
    || node.connection_ref !== proposal.connection_ref
    || !approval.scope.connection_refs.includes(proposal.connection_ref)
    || canonicalJson(node.policy_bounds) !== canonicalJson(claims.bounds)
    || approval.scope.destinations.length !== 1
    || canonicalJson(approval.scope.destinations[0]) !== canonicalJson(proposal.destination)) {
    reject('BROKER_ACTION_SCOPE_MISMATCH')
  }
  if (Object.hasOwn(proposal, 'payload')) {
    const payloadBytes = Buffer.byteLength(canonicalJson(proposal.payload), 'utf8')
    if (payloadBytes > claims.bounds.max_payload_bytes) reject('BROKER_PAYLOAD_BOUNDS_EXCEEDED')
  }
}

export function buildDurableReceipt({ proposal, claims, approval, brokerIdentity, previousEvidenceDigest, afterState, result, recordedAt }) {
  const suffix = proposal.proposal_id.slice('proposal_'.length)
  const receipt = {
    schema: 'dubsar.action-receipt.v1',
    contract_version: '1.0.0',
    receipt_id: `receipt_${suffix}`,
    proposal_id: proposal.proposal_id,
    run_id: proposal.run_id,
    step_id: proposal.step_id,
    workflow_digest: proposal.workflow_digest,
    action: structuredClone(proposal.action),
    broker_identity: structuredClone(brokerIdentity),
    core_decision: {
      decision_id: approval.policy_evaluation.decision_id,
      approval_id: approval.approval_id,
      policy_digest: approval.policy_evaluation.policy_digest,
    },
    capability_jti: claims.jti,
    before_state: 'IN_FLIGHT',
    after_state: afterState,
    result,
    recorded_at: recordedAt,
    evidence_chain: {
      event_id: `event_${suffix}`,
      previous_event_digest: previousEvidenceDigest,
      event_digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    },
  }
  receipt.evidence_chain.event_digest = receiptEvidenceDigest(receipt)
  assertContract('action-receipt', receipt)
  return receipt
}

export function successfulResult(execution) {
  return {
    kind: 'success',
    outcome_digest: domainSeparatedHash('dubsar.broker.pilot-outcome.v1', execution.output),
    provider_status: execution.provider_status,
  }
}

export function indeterminateResult() {
  return {
    kind: 'error',
    error: {
      code: 'PILOT_EXECUTION_INDETERMINATE',
      category: 'PROVIDER',
      retryable: false,
      detail_digest: domainSeparatedHash('dubsar.broker.error-detail.v1', {
        classification: 'executor_outcome_unknown',
      }),
    },
  }
}

export function validateExecutionResult(result) {
  if (!isPlainObject(result) || result.kind !== 'success'
    || !Number.isInteger(result.provider_status)
    || result.provider_status < 100 || result.provider_status > 599
    || !isPlainObject(result.output)) return null
  assertNoSecretMaterial(result.output)
  canonicalJson(result.output)
  return structuredClone(result)
}

export function idempotencyFingerprint(proposal, approval) {
  return domainSeparatedHash('dubsar.broker.idempotency.v1', {
    approval_digest: hashContract('approval-record', approval),
    proposal_digest: hashContract('action-proposal', proposal),
  })
}

export function actionDigest(proposal) {
  return domainSeparatedHash('dubsar.broker.action-identity.v1', proposal.action)
}

export function actionIdFor(proposalId) {
  if (typeof proposalId !== 'string' || !proposalId.startsWith('proposal_')) reject('BROKER_PROPOSAL_ID_INVALID')
  return `action_${proposalId.slice('proposal_'.length)}`
}

export function assertWorkloadIdentity(identity, code) {
  if (!isPlainObject(identity)
    || Object.keys(identity).sort().join(',') !== 'instance_id,workload_id'
    || !/^workload_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.workload_id)
    || !/^instance_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.instance_id)) {
    throw new BrokerRejection(code)
  }
}

export function mapBindingRejection(error) {
  const message = error instanceof Error ? error.message : ''
  if (/expired/.test(message)) return new BrokerRejection('BROKER_CAPABILITY_EXPIRED')
  if (/not yet valid/.test(message)) return new BrokerRejection('BROKER_CAPABILITY_NOT_YET_VALID')
  if (/workload/.test(message)) return new BrokerRejection('BROKER_WORKLOAD_MISMATCH')
  if (/workflow/.test(message)) return new BrokerRejection('BROKER_WORKFLOW_MISMATCH')
  if (/approval/.test(message)) return new BrokerRejection('BROKER_APPROVAL_MISMATCH')
  if (/run/.test(message)) return new BrokerRejection('BROKER_RUN_MISMATCH')
  if (/step/.test(message)) return new BrokerRejection('BROKER_STEP_MISMATCH')
  if (/action/.test(message)) return new BrokerRejection('BROKER_ACTION_MISMATCH')
  if (/payload digest/.test(message)) return new BrokerRejection('BROKER_PAYLOAD_MISMATCH')
  return new BrokerRejection('BROKER_CAPABILITY_INCOHERENT')
}

function assertInputContract(kind, value, code) {
  try {
    assertContract(kind, value)
    return structuredClone(value)
  } catch {
    throw new BrokerRejection(code)
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
}
