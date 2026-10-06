import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import { sealExactReceipt } from '../exact-action/receipt.mjs'
import { freezeExact } from '../exact-action/contracts.mjs'
import { assertCapabilityClaimsBound, assertContract, hashContract } from '../contracts.mjs'
import { BrokerRejection, reject } from './broker-error.mjs'
import {
  actionDigest,
  actionIdFor,
  assertDurableActionScope,
  assertWorkloadIdentity,
  buildDurableReceipt,
  idempotencyFingerprint,
  indeterminateResult,
  mapBindingRejection,
  successfulResult,
  validateDurableRequest,
  validateExecutionResult,
} from './durable-broker-domain.mjs'

export class PostgresActionBroker {
  #clock
  #capabilityVerifier
  #workloadIdentityProvider
  #executor
  #brokerIdentity
  #store
  #lifecycle
  #exactActionGate
  #exactMaterial

  constructor({
    clock,
    capabilityVerifier,
    workloadIdentityProvider,
    executor,
    brokerIdentity,
    store,
    lifecycle = {},
    exactActionGate,
  } = {}) {
    if (typeof clock?.now !== 'function') reject('BROKER_CLOCK_REQUIRED')
    if (typeof capabilityVerifier?.verifySigned !== 'function') reject('BROKER_AUTHORITY_VERIFIER_REQUIRED')
    if (typeof workloadIdentityProvider?.current !== 'function') reject('BROKER_WORKLOAD_IDENTITY_REQUIRED')
    if (typeof executor?.assertSupported !== 'function' || typeof executor?.execute !== 'function') {
      reject('BROKER_EXECUTOR_REQUIRED')
    }
    if (typeof store?.claim !== 'function'
      || typeof store?.finalize !== 'function'
      || typeof store?.listInFlight !== 'function') {
      reject('BROKER_POSTGRES_STORE_REQUIRED')
    }
    if (lifecycle.afterClaim !== undefined && typeof lifecycle.afterClaim !== 'function') {
      reject('BROKER_LIFECYCLE_INVALID')
    }
    assertWorkloadIdentity(brokerIdentity, 'BROKER_IDENTITY_INVALID')
    this.#clock = clock
    this.#capabilityVerifier = capabilityVerifier
    this.#workloadIdentityProvider = workloadIdentityProvider
    this.#executor = executor
    this.#brokerIdentity = structuredClone(brokerIdentity)
    this.#store = store
    this.#lifecycle = lifecycle
    if (exactActionGate !== undefined) {
      if (typeof exactActionGate?.withAuthorization !== 'function' || executor.exactMaterial === undefined) reject('BROKER_EXACT_CONFIGURATION_REQUIRED')
      this.#exactMaterial = structuredClone(executor.exactMaterial)
    }
    this.#exactActionGate = exactActionGate
  }

  async submit(request) {
    request = structuredClone(request)
    const observedAt = this.#now()
    const { proposal, workflow, approval } = validateDurableRequest(request, observedAt)
    let verification
    try {
      verification = await this.#capabilityVerifier.verifySigned({
        signedCapability: request.signedCapability,
        now: observedAt,
      })
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_AUTHORITY_VERIFICATION_FAILED')
    }
    const claims = verification?.claims
    if ((verification?.exactAction !== undefined) !== (this.#exactActionGate !== undefined)) reject('BROKER_EXACT_MODE_REQUIRED')
    if (Object.keys(request).some(key => !['proposal', 'workflow', 'approval', 'signedCapability', 'previousEvidenceDigest'].includes(key))) reject('BROKER_REQUEST_INVALID')
    try {
      assertContract('capability-claims', claims)
    } catch {
      throw new BrokerRejection('BROKER_CAPABILITY_INVALID')
    }

    const callerIdentity = await this.#currentWorkloadIdentity()
    if (canonicalJson(callerIdentity) !== canonicalJson(proposal.workload_identity)
      || canonicalJson(callerIdentity) !== canonicalJson(verification.workloadIdentity)) {
      reject('BROKER_WORKLOAD_MISMATCH')
    }
    try {
      assertCapabilityClaimsBound(claims, proposal, callerIdentity.workload_id, observedAt)
    } catch (error) {
      throw mapBindingRejection(error)
    }
    const proposalDigest = hashContract('action-proposal', proposal)
    if (proposalDigest !== verification.proposalDigest) reject('BROKER_PROPOSAL_DIGEST_MISMATCH')
    const approvalDigest = hashContract('approval-record', approval)
    if (approvalDigest !== verification.approvalDigest) reject('BROKER_APPROVAL_DIGEST_MISMATCH')
    assertDurableActionScope(proposal, claims, workflow, approval)
    try {
      this.#executor.assertSupported(proposal)
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_ACTION_UNSUPPORTED')
    }

    const actionId = actionIdFor(proposal.proposal_id)
    const pendingContext = {
      approval,
      brokerIdentity: this.#brokerIdentity,
      capabilityClaims: claims,
      previousEvidenceDigest: request.previousEvidenceDigest,
      proposal,
      ...(verification.exactAction === undefined ? {} : { exactAction: verification.exactAction }),
    }
    const checkAdmission = () => {
      // Recheck after asynchronous port/identity reads, immediately before claim.
      const admissionTime = this.#now()
      validateDurableRequest(request, admissionTime)
      assertCapabilityClaimsBound(claims, proposal, callerIdentity.workload_id, admissionTime)
      return admissionTime
    }
    const admit = async (_proof, transaction) => {
      const admissionTime = verification.exactAction === undefined ? observedAt : checkAdmission()
      if (transaction !== undefined && typeof this.#store.claimInTransaction !== 'function') {
        reject('BROKER_ADMISSION_TRANSACTION_REQUIRED')
      }
      const input = {
        ...(verification.exactAction === undefined ? {} : { assertAdmissionCurrent: checkAdmission }),
        actionId,
        proposal,
        proposalDigest,
        claims,
        kid: verification.kid,
        fingerprint: verification.exactAction === undefined ? idempotencyFingerprint(proposal, approval)
          : domainSeparatedHash('dubsar.broker.idempotency.v2', { legacy: idempotencyFingerprint(proposal, approval), exact_action: verification.exactAction }),
        actionDigest: actionDigest(proposal),
        approvalDigest,
        approvalMaxActions: approval.scope.max_actions,
        pendingContext,
        observedAt: admissionTime,
      }
      return transaction === undefined ? this.#store.claim(input) : this.#store.claimInTransaction(input, transaction)
    }
    const claim = this.#exactActionGate === undefined ? await admit()
      : await this.#exactActionGate.withAuthorization({
        decisionRef: verification.exactAction.decision_ref, proposal, approval, clock: this.#clock,
        expected: verification.exactAction, material: this.#exactMaterial,
      }, admit)
    if (claim.kind === 'completed') return structuredClone(claim.receipt)
    if (claim.kind === 'in_flight') reject('BROKER_OPERATION_IN_PROGRESS')

    if (this.#lifecycle.afterClaim !== undefined) {
      try {
        await this.#lifecycle.afterClaim({ actionId })
      } catch {
        throw new BrokerRejection('BROKER_IN_FLIGHT_INTERRUPTED')
      }
    }

    const execution = await this.#executeSafely(proposal, claims, verification.exactAction)
    const recordedAt = this.#now()
    const afterState = execution === null ? 'INDETERMINATE' : 'SUCCEEDED'
    const receipt = sealExactReceipt(buildDurableReceipt({
      proposal,
      claims,
      approval,
      brokerIdentity: this.#brokerIdentity,
      previousEvidenceDigest: request.previousEvidenceDigest,
      afterState,
      result: execution === null ? indeterminateResult() : successfulResult(execution),
      recordedAt,
    }), verification.exactAction)
    try {
      return await this.#store.finalize({
        actionId,
        toState: afterState,
        receipt,
        reasonCode: afterState === 'SUCCEEDED' ? 'PILOT_EXECUTION_SUCCEEDED' : 'EXECUTION_OUTCOME_UNKNOWN',
        brokerIdentity: this.#brokerIdentity,
        observedAt: recordedAt,
      })
    } catch (error) {
      if (error?.code === 'BROKER_STORAGE_UNAVAILABLE') {
        throw new BrokerRejection('BROKER_FINALIZATION_UNCERTAIN')
      }
      throw error
    }
  }

  async recoverInFlight() {
    const rows = await this.#store.listInFlight()
    let recovered = 0
    for (const row of rows) {
      const context = row.pendingContext
      const recordedAt = this.#now()
      const receipt = sealExactReceipt(buildDurableReceipt({
        proposal: context.proposal,
        claims: context.capabilityClaims,
        approval: context.approval,
        brokerIdentity: context.brokerIdentity,
        previousEvidenceDigest: context.previousEvidenceDigest,
        afterState: 'INDETERMINATE',
        result: indeterminateResult(),
        recordedAt,
      }), context.exactAction)
      try {
        await this.#store.finalize({
          actionId: row.actionId,
          toState: 'INDETERMINATE',
          receipt,
          reasonCode: 'IN_FLIGHT_RECOVERED_WITH_UNKNOWN_OUTCOME',
          brokerIdentity: this.#brokerIdentity,
          observedAt: recordedAt,
        })
        recovered += 1
      } catch (error) {
        if (error?.code !== 'BROKER_TRANSITION_FORBIDDEN') throw error
      }
    }
    return { recovered }
  }

  getAction(proposalId) {
    return this.#store.getAction(actionIdFor(proposalId))
  }

  async #executeSafely(proposal, claims, exactAction) {
    try {
      const input = {
        proposal: structuredClone(proposal),
        capabilityClaims: structuredClone(claims),
        ...(exactAction === undefined ? {} : { exactAction: structuredClone(exactAction), exactMaterial: structuredClone(this.#exactMaterial) }),
      }
      const result = await this.#executor.execute(exactAction === undefined ? input : freezeExact(input))
      if (exactAction !== undefined && (result?.provider_status < 200 || result?.provider_status >= 300)) return null
      return validateExecutionResult(result)
    } catch {
      return null
    }
  }

  async #currentWorkloadIdentity() {
    try {
      const identity = await this.#workloadIdentityProvider.current()
      assertWorkloadIdentity(identity, 'BROKER_WORKLOAD_IDENTITY_INVALID')
      return structuredClone(identity)
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_WORKLOAD_IDENTITY_UNAVAILABLE')
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
