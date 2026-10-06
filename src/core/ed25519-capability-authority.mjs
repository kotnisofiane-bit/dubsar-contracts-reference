import { randomBytes, sign } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { assertExact } from '../exact-action/contracts.mjs'
import {
  assertApprovalCurrent,
  assertContract,
  hashContract,
  proposalPayloadDigest,
} from '../contracts.mjs'
import {
  CAPABILITY_ALGORITHM,
  CAPABILITY_AUDIENCE,
  CAPABILITY_ISSUER,
  CAPABILITY_SCHEMA,
  CAPABILITY_TYPE,
  encodeCapabilitySegment,
  isPlainObject,
} from './signed-capability-format.mjs'

const KEY_ID = /^core-key_[a-z0-9][a-z0-9_-]{7,63}$/
const JTI = /^jti_[A-Za-z0-9_-]{32,128}$/
const MAX_VALIDITY_SECONDS = 120

export class Ed25519CapabilityAuthority {
  #signingKey
  #kid
  #clock
  #jtiFactory
  #issuedJtis = new Set()
  #exactActionGate

  constructor({ signingKey, kid, clock, jtiFactory = defaultJti, exactActionGate } = {}) {
    if (signingKey?.type !== 'private' || signingKey?.asymmetricKeyType !== 'ed25519') {
      throw new TypeError('CORE_ED25519_PRIVATE_KEY_REQUIRED')
    }
    if (!KEY_ID.test(kid ?? '')) throw new TypeError('CORE_KEY_ID_INVALID')
    if (typeof clock?.now !== 'function') throw new TypeError('CORE_CLOCK_REQUIRED')
    if (typeof jtiFactory !== 'function') throw new TypeError('CORE_JTI_FACTORY_REQUIRED')
    this.#signingKey = signingKey
    this.#kid = kid
    this.#clock = clock
    this.#jtiFactory = jtiFactory
    if (exactActionGate !== undefined && typeof exactActionGate?.withAuthorization !== 'function') throw new TypeError('CORE_EXACT_GATE_REQUIRED')
    this.#exactActionGate = exactActionGate
  }

  issue(request = {}) {
    if (this.#exactActionGate !== undefined || Object.keys(request).some(key => !['proposal', 'workflow', 'approval', 'workloadIdentity', 'validitySeconds'].includes(key))) {
      throw new Error('CORE_EXACT_MODE_REQUIRED')
    }
    return this.#issue(request)
  }

  async issueExact(request = {}) {
    if (this.#exactActionGate === undefined) throw new Error('CORE_EXACT_GATE_REQUIRED')
    if (Object.keys(request).some(key => !['proposal', 'workflow', 'approval', 'workloadIdentity', 'validitySeconds', 'decisionRef'].includes(key))) throw new Error('CORE_EXACT_REQUEST_INVALID')
    const snapshot = structuredClone(request)
    return this.#exactActionGate.withAuthorization({ ...snapshot, clock: this.#clock }, proof => this.#issue(snapshot, proof))
  }

  #issue({ proposal, workflow, approval, workloadIdentity, validitySeconds = 60 } = {}, exactAction) {
    assertContract('action-proposal', proposal)
    assertContract('workflow-ir', workflow)
    assertContract('approval-record', approval)
    assertWorkloadIdentity(workloadIdentity)
    if (!Number.isInteger(validitySeconds) || validitySeconds < 1 || validitySeconds > MAX_VALIDITY_SECONDS) {
      throw new TypeError('CORE_CAPABILITY_VALIDITY_INVALID')
    }

    const issuedAt = normalizedInstant(this.#clock.now(), 'CORE_CLOCK_INVALID')
    assertApprovalCurrent(approval, workflow, issuedAt)
    assertProposalAuthorityBinding({ proposal, workflow, approval, workloadIdentity })

    const iat = Math.floor(Date.parse(issuedAt) / 1000)
    const approvalExpiry = Math.floor(Date.parse(approval.expires_at) / 1000)
    const nbf = iat
    const exp = Math.min(iat + validitySeconds, approvalExpiry, exactAction === undefined ? Infinity : Math.floor(Date.parse(exactAction.expires_at) / 1000))
    if (exp <= nbf) throw new TypeError('CORE_CAPABILITY_WINDOW_EMPTY')

    const jti = this.#jtiFactory()
    if (!JTI.test(jti ?? '')) throw new TypeError('CORE_JTI_INVALID')
    if (this.#issuedJtis.has(jti)) throw new Error('CORE_JTI_REUSE_REFUSED')
    this.#issuedJtis.add(jti)
    const claims = {
      schema: 'dubsar.capability-claims.v1',
      contract_version: '1.0.0',
      jti,
      issuer: CAPABILITY_ISSUER,
      audience: CAPABILITY_AUDIENCE,
      subject_workload_id: workloadIdentity.workload_id,
      run_id: proposal.run_id,
      step_id: proposal.step_id,
      workflow_id: proposal.workflow_id,
      workflow_digest: proposal.workflow_digest,
      approval_id: proposal.approval_id,
      proposal_id: proposal.proposal_id,
      action: structuredClone(proposal.action),
      connection_ref: proposal.connection_ref,
      payload_digest: proposalPayloadDigest(proposal),
      destinations: [structuredClone(proposal.destination)],
      bounds: structuredClone(findApprovedActionNode(workflow, proposal).policy_bounds),
      issued_at: new Date(iat * 1000).toISOString(),
      not_before: new Date(nbf * 1000).toISOString(),
      expires_at: new Date(exp * 1000).toISOString(),
      revoked_at: null,
    }
    assertContract('capability-claims', claims)

    const header = {
      alg: CAPABILITY_ALGORITHM,
      kid: this.#kid,
      typ: CAPABILITY_TYPE,
      v: exactAction === undefined ? 1 : 2,
    }
    const payload = {
      approval_digest: hashContract('approval-record', approval),
      claims,
      exp,
      iat,
      nbf,
      proposal_digest: hashContract('action-proposal', proposal),
      schema: exactAction === undefined ? CAPABILITY_SCHEMA : 'dubsar.signed-capability.v2',
      subject_workload: structuredClone(workloadIdentity),
    }
    if (exactAction !== undefined) payload.exact_action = structuredClone(assertExact('proof', exactAction))
    const protectedSegment = encodeCapabilitySegment(header)
    const payloadSegment = encodeCapabilitySegment(payload)
    const signingInput = Buffer.from(`${protectedSegment}.${payloadSegment}`, 'ascii')
    const signature = sign(null, signingInput, this.#signingKey)
    return `${protectedSegment}.${payloadSegment}.${signature.toString('base64url')}`
  }
}

function assertProposalAuthorityBinding({ proposal, workflow, approval, workloadIdentity }) {
  const workflowDigest = hashContract('workflow-ir', workflow)
  if (proposal.workflow_id !== workflow.workflow_id || proposal.workflow_digest !== workflowDigest) {
    throw new Error('CORE_WORKFLOW_MISMATCH')
  }
  if (proposal.approval_id !== approval.approval_id) throw new Error('CORE_APPROVAL_MISMATCH')
  if (canonicalJson(workloadIdentity) !== canonicalJson(proposal.workload_identity)) {
    throw new Error('CORE_WORKLOAD_MISMATCH')
  }
  const node = findApprovedActionNode(workflow, proposal)
  if (!approval.scope.node_ids.includes(node.node_id)
    || node.connection_ref !== proposal.connection_ref
    || !approval.scope.connection_refs.includes(proposal.connection_ref)
    || approval.scope.destinations.length !== 1
    || canonicalJson(approval.scope.destinations[0]) !== canonicalJson(proposal.destination)
    || canonicalJson(node.policy_bounds.allowed_destinations) !== canonicalJson([proposal.destination])) {
    throw new Error('CORE_SCOPE_MISMATCH')
  }
}

function findApprovedActionNode(workflow, proposal) {
  const matches = workflow.nodes.filter(node => node.kind === 'action'
    && canonicalJson({ kind: 'connector_action', connector: node.connector, operation: node.operation })
      === canonicalJson(proposal.action))
  if (matches.length !== 1) throw new Error('CORE_ACTION_SCOPE_MISMATCH')
  return matches[0]
}

function assertWorkloadIdentity(identity) {
  if (!isPlainObject(identity)
    || Object.keys(identity).sort().join(',') !== 'instance_id,workload_id'
    || !/^workload_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.workload_id)
    || !/^instance_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.instance_id)) {
    throw new TypeError('CORE_WORKLOAD_IDENTITY_INVALID')
  }
}

function normalizedInstant(value, code) {
  const instant = value instanceof Date ? value.getTime() : Date.parse(value)
  if (!Number.isFinite(instant)) throw new TypeError(code)
  return new Date(Math.floor(instant / 1000) * 1000).toISOString()
}

function defaultJti() {
  return `jti_${randomBytes(24).toString('base64url')}`
}
