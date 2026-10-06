import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { ContractOnlyCapabilityVerifier } from '../src/broker/contract-only-capability-verifier.mjs'
import { DeterministicPilotExecutor } from '../src/broker/deterministic-pilot-executor.mjs'
import { InMemoryActionBroker } from '../src/broker/in-memory-action-broker.mjs'
import { InMemoryActionStateStore } from '../src/broker/in-memory-action-state-store.mjs'
import { assertContract, proposalPayloadDigest, receiptEvidenceDigest } from '../src/contracts.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const NOW = '2026-08-14T10:00:30.000Z'
const PREVIOUS_EVIDENCE = 'sha256:3333333333333333333333333333333333333333333333333333333333333333'
const CALLER_IDENTITY = Object.freeze({
  workload_id: 'workload_worker_demo_001',
  instance_id: 'instance_worker_demo_001',
})
const BROKER_IDENTITY = Object.freeze({
  workload_id: 'workload_broker_demo_001',
  instance_id: 'instance_broker_demo_001',
})

test('valid pilot executes once and emits a contract-valid chained Action Receipt', async () => {
  const { broker, executor } = makeBroker()
  const receipt = await broker.submit(validRequest())

  assert.doesNotThrow(() => assertContract('action-receipt', receipt))
  assert.equal(receipt.after_state, 'SUCCEEDED')
  assert.equal(receipt.result.kind, 'success')
  assert.equal(receipt.result.provider_status, 200)
  assert.equal(receipt.evidence_chain.previous_event_digest, PREVIOUS_EVIDENCE)
  assert.equal(receipt.evidence_chain.event_digest, receiptEvidenceDigest(receipt))
  assert.equal(executor.executionCount, 1)

  const action = broker.getAction(receipt.proposal_id)
  assert.equal(action.state, 'SUCCEEDED')
  assert.deepEqual(action.transitions.map(item => `${item.from_state}->${item.to_state}`), [
    'RECEIVED->AUTHORIZED',
    'AUTHORIZED->IN_FLIGHT',
    'IN_FLIGHT->SUCCEEDED',
  ])
  assert.equal(broker.snapshot().used_jtis.length, 1)
})

test('expired capability is refused before execution', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  request.capabilityClaims.expires_at = '2026-08-14T10:00:20.000Z'
  await rejectsCode(broker.submit(request), 'BROKER_CAPABILITY_EXPIRED')
  assert.equal(executor.executionCount, 0)
})

test('capability validity cannot extend beyond its approval', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  request.approval.expires_at = '2026-08-14T10:00:45.000Z'
  await rejectsCode(broker.submit(request), 'BROKER_CAPABILITY_APPROVAL_WINDOW_MISMATCH')
  assert.equal(executor.executionCount, 0)
})

test('a consumed jti cannot be replayed', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  await broker.submit(request)
  await rejectsCode(broker.submit(request), 'BROKER_CAPABILITY_REPLAY')
  assert.equal(executor.executionCount, 1)
})

test('workload identity must match the exact proposal identity', async () => {
  const { broker, executor } = makeBroker({
    callerIdentity: { workload_id: 'workload_wrong_demo_001', instance_id: 'instance_wrong_demo_001' },
  })
  await rejectsCode(broker.submit(validRequest()), 'BROKER_WORKLOAD_MISMATCH')
  assert.equal(executor.executionCount, 0)
})

test('wrong workflow and approval bindings are refused', async () => {
  const first = makeBroker()
  const wrongWorkflow = validRequest()
  wrongWorkflow.proposal.workflow_id = 'wf_wrong_demo_001'
  await rejectsCode(first.broker.submit(wrongWorkflow), 'BROKER_WORKFLOW_MISMATCH')
  assert.equal(first.executor.executionCount, 0)

  const second = makeBroker()
  const wrongApproval = validRequest()
  wrongApproval.proposal.approval_id = 'approval_wrong_demo_001'
  await rejectsCode(second.broker.submit(wrongApproval), 'BROKER_APPROVAL_MISMATCH')
  assert.equal(second.executor.executionCount, 0)
})

test('wrong run and step claims are refused', async () => {
  const first = makeBroker()
  const wrongRun = validRequest()
  wrongRun.capabilityClaims.run_id = 'run_wrong_demo_001'
  await rejectsCode(first.broker.submit(wrongRun), 'BROKER_RUN_MISMATCH')

  const second = makeBroker()
  const wrongStep = validRequest()
  wrongStep.capabilityClaims.step_id = 'step_wrong_demo_001'
  await rejectsCode(second.broker.submit(wrongStep), 'BROKER_STEP_MISMATCH')
})

test('an action outside the exact workflow pilot is refused', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  request.proposal.action.operation = 'delete_ticket'
  request.capabilityClaims.action.operation = 'delete_ticket'
  await rejectsCode(broker.submit(request), 'BROKER_ACTION_SCOPE_MISMATCH')
  assert.equal(executor.executionCount, 0)
})

test('a modified payload is refused by the capability digest', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  request.proposal.payload.summary = 'modified'
  await rejectsCode(broker.submit(request), 'BROKER_PAYLOAD_MISMATCH')
  assert.equal(executor.executionCount, 0)
})

test('an invalid Action Proposal fails closed', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  delete request.proposal.action
  await rejectsCode(broker.submit(request), 'BROKER_PROPOSAL_INVALID')
  assert.equal(executor.executionCount, 0)
})

test('the state store rejects every undeclared transition without mutation', () => {
  const store = new InMemoryActionStateStore()
  store.create('action_forbidden_demo_001', NOW)
  assert.throws(() => store.transition('action_forbidden_demo_001', 'SUCCEEDED', {
    authority: 'BROKER',
    identity_ref: 'workload_broker_demo_001',
    reason_code: 'INVALID_DIRECT_SUCCESS',
    observed_at: NOW,
  }), error => error?.code === 'BROKER_TRANSITION_FORBIDDEN')
  assert.equal(store.get('action_forbidden_demo_001').state, 'RECEIVED')
  assert.equal(store.get('action_forbidden_demo_001').transitions.length, 0)
})

test('an idempotency key cannot bind a different payload', async () => {
  const { broker, executor } = makeBroker()
  await broker.submit(validRequest())
  const changed = validRequest()
  changed.capabilityClaims.jti = 'jti_changed_payload_abcdefghijklmnopqrstuvwxyz'
  changed.proposal.payload.summary = 'changed but internally coherent'
  changed.capabilityClaims.payload_digest = proposalPayloadDigest(changed.proposal)
  await rejectsCode(broker.submit(changed), 'BROKER_IDEMPOTENCY_CONFLICT')
  assert.equal(executor.executionCount, 1)
})

test('a coherent completed operation returns the original receipt without re-execution', async () => {
  const { broker, executor } = makeBroker()
  const receipt = await broker.submit(validRequest())
  const repeated = validRequest()
  repeated.capabilityClaims.jti = 'jti_coherent_repeat_abcdefghijklmnopqrstuvwxyz'
  const repeatedReceipt = await broker.submit(repeated)
  assert.deepEqual(repeatedReceipt, receipt)
  assert.equal(executor.executionCount, 1)
  assert.equal(broker.snapshot().used_jtis.length, 2)
})

test('INDETERMINATE is retained and never automatically executed again', async () => {
  const executor = {
    executionCount: 0,
    assertSupported() {},
    async execute() {
      this.executionCount += 1
      throw new Error('opaque pilot uncertainty')
    },
  }
  const { broker } = makeBroker({ executor })
  const receipt = await broker.submit(validRequest())
  assert.equal(receipt.after_state, 'INDETERMINATE')
  assert.equal(receipt.result.kind, 'error')
  assert.equal(receipt.result.error.retryable, false)

  const repeated = validRequest()
  repeated.capabilityClaims.jti = 'jti_indeterminate_repeat_abcdefghijklmnopqrstu'
  assert.deepEqual(await broker.submit(repeated), receipt)
  assert.equal(executor.executionCount, 1)
  assert.equal(broker.getAction(receipt.proposal_id).state, 'INDETERMINATE')
})

test('a previous Evidence link is mandatory', async () => {
  const { broker, executor } = makeBroker()
  const request = validRequest()
  delete request.previousEvidenceDigest
  await rejectsCode(broker.submit(request), 'BROKER_PREVIOUS_EVIDENCE_REQUIRED')
  assert.equal(executor.executionCount, 0)
})

test('absence of an authority verifier fails closed', async () => {
  const { broker, executor } = makeBroker({ capabilityVerifier: null })
  await rejectsCode(broker.submit(validRequest()), 'BROKER_AUTHORITY_VERIFIER_REQUIRED')
  assert.equal(executor.executionCount, 0)
})

test('injected clock and executor admission failures are sanitized', async () => {
  const brokenClock = makeBroker({ clock: { now: () => { throw new Error('internal clock detail') } } })
  await rejectsCode(brokenClock.broker.submit(validRequest()), 'BROKER_CLOCK_UNAVAILABLE')

  const executor = {
    execute() { throw new Error('must not be reached') },
    assertSupported() { throw new Error('internal executor detail') },
  }
  const brokenExecutor = makeBroker({ executor })
  await rejectsCode(brokenExecutor.broker.submit(validRequest()), 'BROKER_ACTION_UNSUPPORTED')
})

function makeBroker(overrides = {}) {
  const executor = overrides.executor ?? new DeterministicPilotExecutor()
  const callerIdentity = overrides.callerIdentity ?? CALLER_IDENTITY
  const capabilityVerifier = Object.hasOwn(overrides, 'capabilityVerifier')
    ? overrides.capabilityVerifier
    : new ContractOnlyCapabilityVerifier()
  const broker = new InMemoryActionBroker({
    clock: overrides.clock ?? { now: () => NOW },
    capabilityVerifier,
    workloadIdentityProvider: { current: async () => structuredClone(callerIdentity) },
    executor,
    brokerIdentity: BROKER_IDENTITY,
  })
  return { broker, executor }
}

function validRequest() {
  return {
    proposal: fixture('action-proposal'),
    capabilityClaims: fixture('capability-claims'),
    workflow: fixture('workflow-ir'),
    approval: fixture('approval-record'),
    previousEvidenceDigest: PREVIOUS_EVIDENCE,
  }
}

function fixture(kind) {
  return JSON.parse(fs.readFileSync(path.join(root, 'fixtures', 'v1', kind, 'valid.json'), 'utf8'))
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, error => error?.code === code && error?.message === code)
}
