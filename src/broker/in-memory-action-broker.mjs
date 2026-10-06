import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import {
  assertApprovalCurrent,
  assertContract,
  assertNoSecretMaterial,
  consumeCapabilityClaims,
  hashContract,
  proposalPayloadDigest,
  receiptEvidenceDigest,
} from '../contracts.mjs'
import { BrokerRejection, reject } from './broker-error.mjs'
import { InMemoryActionStateStore } from './in-memory-action-state-store.mjs'

const DIGEST = /^sha256:[a-f0-9]{64}$/

export class InMemoryActionBroker {
  #clock
  #capabilityVerifier
  #workloadIdentityProvider
  #executor
  #brokerIdentity
  #stateStore
  #usedJtis = new Set()
  #idempotency = new Map()

  constructor({
    clock,
    capabilityVerifier,
    workloadIdentityProvider,
    executor,
    brokerIdentity,
    stateStore = new InMemoryActionStateStore(),
  } = {}) {
    if (typeof clock?.now !== 'function') reject('BROKER_CLOCK_REQUIRED')
    if (typeof workloadIdentityProvider?.current !== 'function') reject('BROKER_WORKLOAD_IDENTITY_REQUIRED')
    if (typeof executor?.assertSupported !== 'function' || typeof executor?.execute !== 'function') {
      reject('BROKER_EXECUTOR_REQUIRED')
    }
    assertWorkloadIdentity(brokerIdentity, 'BROKER_IDENTITY_INVALID')
    this.#clock = clock
    this.#capabilityVerifier = capabilityVerifier
    this.#workloadIdentityProvider = workloadIdentityProvider
    this.#executor = executor
    this.#brokerIdentity = structuredClone(brokerIdentity)
    this.#stateStore = stateStore
  }

  async submit(request) {
    if (!isPlainObject(request)) reject('BROKER_REQUEST_INVALID')
    if (typeof this.#capabilityVerifier?.verify !== 'function') {
      reject('BROKER_AUTHORITY_VERIFIER_REQUIRED')
    }
    if (!DIGEST.test(request.previousEvidenceDigest ?? '')) {
      reject('BROKER_PREVIOUS_EVIDENCE_REQUIRED')
    }

    const observedAt = this.#now()
    const proposal = assertInputContract('action-proposal', request.proposal, 'BROKER_PROPOSAL_INVALID')
    const workflow = assertInputContract('workflow-ir', request.workflow, 'BROKER_WORKFLOW_INVALID')
    const approval = assertInputContract('approval-record', request.approval, 'BROKER_APPROVAL_INVALID')
    this.#assertWorkflowAndApproval(proposal, workflow, approval, observedAt)

    let claims
    try {
      claims = await this.#capabilityVerifier.verify({
        claims: structuredClone(request.capabilityClaims),
        approval: structuredClone(approval),
        workflow: structuredClone(workflow),
        now: observedAt,
      })
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_AUTHORITY_VERIFICATION_FAILED')
    }
    claims = assertInputContract('capability-claims', claims, 'BROKER_CAPABILITY_INVALID')

    const callerIdentity = await this.#currentWorkloadIdentity()
    if (canonicalJson(callerIdentity) !== canonicalJson(proposal.workload_identity)) {
      reject('BROKER_WORKLOAD_MISMATCH')
    }
    this.#assertActionScope(proposal, claims, workflow, approval)

    const fingerprint = idempotencyFingerprint(proposal)
    const existing = this.#idempotency.get(proposal.idempotency_key)
    if (existing !== undefined && existing.fingerprint !== fingerprint) {
      reject('BROKER_IDEMPOTENCY_CONFLICT')
    }

    try {
      consumeCapabilityClaims(
        claims,
        proposal,
        callerIdentity.workload_id,
        this.#usedJtis,
        observedAt,
      )
    } catch (error) {
      throw mapCapabilityRejection(error)
    }

    if (existing !== undefined) {
      if (existing.status !== 'completed') reject('BROKER_OPERATION_IN_PROGRESS')
      return structuredClone(existing.receipt)
    }

    try {
      this.#executor.assertSupported(proposal)
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_ACTION_UNSUPPORTED')
    }
    const actionId = actionIdFor(proposal.proposal_id)
    if (this.#stateStore.get(actionId) !== null) reject('BROKER_ACTION_ALREADY_EXISTS')
    this.#idempotency.set(proposal.idempotency_key, {
      action_id: actionId,
      fingerprint,
      status: 'in_flight',
      receipt: null,
    })
    this.#stateStore.create(actionId, observedAt)
    this.#stateStore.transition(actionId, 'AUTHORIZED', {
      authority: 'CORE',
      identity_ref: 'core_governance_001',
      reason_code: 'CAPABILITY_VERIFIED',
      observed_at: observedAt,
    })
    this.#stateStore.transition(actionId, 'IN_FLIGHT', {
      authority: 'BROKER',
      identity_ref: this.#brokerIdentity.workload_id,
      reason_code: 'PILOT_EXECUTION_STARTED',
      observed_at: observedAt,
    })

    const execution = await this.#executeSafely(proposal, claims)
    const recordedAt = this.#now()
    const afterState = execution.kind === 'success' ? 'SUCCEEDED' : 'INDETERMINATE'
    const result = execution.kind === 'success'
      ? {
          kind: 'success',
          outcome_digest: domainSeparatedHash('dubsar.broker.pilot-outcome.v1', execution.output),
          provider_status: execution.provider_status,
        }
      : {
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
    const receipt = buildReceipt({
      proposal,
      claims,
      approval,
      brokerIdentity: this.#brokerIdentity,
      previousEvidenceDigest: request.previousEvidenceDigest,
      afterState,
      result,
      recordedAt,
    })
    this.#stateStore.transition(actionId, afterState, {
      authority: 'BROKER',
      identity_ref: this.#brokerIdentity.workload_id,
      reason_code: afterState === 'SUCCEEDED' ? 'PILOT_EXECUTION_SUCCEEDED' : 'EXECUTION_OUTCOME_UNKNOWN',
      observed_at: recordedAt,
    })
    this.#idempotency.set(proposal.idempotency_key, {
      action_id: actionId,
      fingerprint,
      status: 'completed',
      receipt: structuredClone(receipt),
    })
    return structuredClone(receipt)
  }

  getAction(proposalId) {
    return this.#stateStore.get(actionIdFor(proposalId))
  }

  snapshot() {
    return {
      actions: this.#stateStore.snapshot(),
      used_jtis: [...this.#usedJtis].sort(),
      idempotency: [...this.#idempotency.entries()]
        .map(([key, value]) => ({ key, action_id: value.action_id, status: value.status }))
        .sort((left, right) => left.key.localeCompare(right.key)),
    }
  }

  async #currentWorkloadIdentity() {
    let identity
    try {
      identity = await this.#workloadIdentityProvider.current()
      assertWorkloadIdentity(identity, 'BROKER_WORKLOAD_IDENTITY_INVALID')
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_WORKLOAD_IDENTITY_UNAVAILABLE')
    }
    return structuredClone(identity)
  }

  #assertWorkflowAndApproval(proposal, workflow, approval, now) {
    const workflowDigest = hashContract('workflow-ir', workflow)
    if (proposal.workflow_id !== workflow.workflow_id || proposal.workflow_digest !== workflowDigest) {
      reject('BROKER_WORKFLOW_MISMATCH')
    }
    if (proposal.approval_id !== approval.approval_id) reject('BROKER_APPROVAL_MISMATCH')
    try {
      assertApprovalCurrent(approval, workflow, now)
    } catch (error) {
      if (/expired/.test(error.message)) reject('BROKER_APPROVAL_EXPIRED')
      reject('BROKER_APPROVAL_MISMATCH')
    }
  }

  #assertActionScope(proposal, claims, workflow, approval) {
    if (Date.parse(claims.issued_at) < Date.parse(approval.issued_at)
      || Date.parse(claims.not_before) < Date.parse(approval.issued_at)
      || Date.parse(claims.expires_at) > Date.parse(approval.expires_at)) {
      reject('BROKER_CAPABILITY_APPROVAL_WINDOW_MISMATCH')
    }
    const matchingNodes = workflow.nodes.filter(node => node.kind === 'action'
      && canonicalJson({ kind: 'connector_action', connector: node.connector, operation: node.operation }) === canonicalJson(proposal.action))
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

  async #executeSafely(proposal, claims) {
    try {
      const result = await this.#executor.execute({
        proposal: structuredClone(proposal),
        capabilityClaims: structuredClone(claims),
      })
      if (!isPlainObject(result) || result.kind !== 'success'
        || !Number.isInteger(result.provider_status)
        || result.provider_status < 100 || result.provider_status > 599
        || !isPlainObject(result.output)) {
        return { kind: 'indeterminate' }
      }
      assertNoSecretMaterial(result.output)
      canonicalJson(result.output)
      return structuredClone(result)
    } catch {
      return { kind: 'indeterminate' }
    }
  }

  #now() {
    let value
    try {
      value = this.#clock.now()
    } catch {
      throw new BrokerRejection('BROKER_CLOCK_UNAVAILABLE')
    }
    const instant = value instanceof Date ? new Date(value.getTime()) : new Date(value)
    if (!Number.isFinite(instant.getTime())) reject('BROKER_CLOCK_INVALID')
    return instant.toISOString()
  }
}

function buildReceipt({ proposal, claims, approval, brokerIdentity, previousEvidenceDigest, afterState, result, recordedAt }) {
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

function assertInputContract(kind, value, code) {
  try {
    assertContract(kind, value)
    return structuredClone(value)
  } catch {
    throw new BrokerRejection(code)
  }
}

function mapCapabilityRejection(error) {
  const message = error instanceof Error ? error.message : ''
  if (/replay/.test(message)) return new BrokerRejection('BROKER_CAPABILITY_REPLAY')
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

function idempotencyFingerprint(proposal) {
  return domainSeparatedHash('dubsar.broker.idempotency.v1', {
    proposal_id: proposal.proposal_id,
    run_id: proposal.run_id,
    step_id: proposal.step_id,
    workflow_id: proposal.workflow_id,
    workflow_digest: proposal.workflow_digest,
    approval_id: proposal.approval_id,
    action: proposal.action,
    payload_digest: proposalPayloadDigest(proposal),
    connection_ref: proposal.connection_ref,
    destination: proposal.destination,
    workload_identity: proposal.workload_identity,
  })
}

function actionIdFor(proposalId) {
  if (typeof proposalId !== 'string' || !proposalId.startsWith('proposal_')) reject('BROKER_PROPOSAL_ID_INVALID')
  return `action_${proposalId.slice('proposal_'.length)}`
}

function assertWorkloadIdentity(identity, code) {
  if (!isPlainObject(identity)
    || Object.keys(identity).sort().join(',') !== 'instance_id,workload_id'
    || !/^workload_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.workload_id)
    || !/^instance_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.instance_id)) {
    throw new BrokerRejection(code)
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
}
