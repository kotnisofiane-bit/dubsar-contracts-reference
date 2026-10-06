import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import fs from 'node:fs'
import test from 'node:test'
import { BrokerRejection } from '../src/broker/broker-error.mjs'
import { DeterministicPilotExecutor } from '../src/broker/deterministic-pilot-executor.mjs'
import { idempotencyFingerprint } from '../src/broker/durable-broker-domain.mjs'
import { Ed25519CapabilityVerifier, StaticEd25519PublicKeyRing } from '../src/broker/ed25519-capability-verifier.mjs'
import { PostgresActionBroker } from '../src/broker/postgres-action-broker.mjs'
import { PostgresActionStore } from '../src/broker/postgres-action-store.mjs'
import { Ed25519CapabilityAuthority } from '../src/core/ed25519-capability-authority.mjs'
import { assertContract } from '../src/contracts.mjs'

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

test('durable Broker path requires a signed capability and produces a valid chained receipt', async () => {
  const fixture = setup()
  const request = fixture.request()
  const receipt = await fixture.broker.submit(request)
  assert.doesNotThrow(() => assertContract('action-receipt', receipt))
  assert.equal(receipt.after_state, 'SUCCEEDED')
  assert.equal(receipt.core_decision.decision_id, request.approval.policy_evaluation.decision_id)
  assert.equal(receipt.core_decision.policy_digest, request.approval.policy_evaluation.policy_digest)
  assert.equal(fixture.executor.executionCount, 1)
  assert.equal(fixture.store.claims.length, 1)
  assert.equal(fixture.store.finalizations.length, 1)
})

test('exact run, step, action and payload bindings are checked after signature verification', async () => {
  for (const [mutate, code] of [
    [proposal => { proposal.run_id = 'run_wrong_demo_001' }, 'BROKER_RUN_MISMATCH'],
    [proposal => { proposal.step_id = 'step_wrong_demo_001' }, 'BROKER_STEP_MISMATCH'],
    [proposal => { proposal.action.operation = 'delete_ticket' }, 'BROKER_ACTION_MISMATCH'],
    [proposal => { proposal.payload.summary = 'modified' }, 'BROKER_PAYLOAD_MISMATCH'],
    [proposal => { proposal.destination.host = 'other.example.invalid' }, 'BROKER_CAPABILITY_INCOHERENT'],
  ]) {
    const fixture = setup()
    const request = fixture.request()
    mutate(request.proposal)
    await rejectsCode(fixture.broker.submit(request), code)
    assert.equal(fixture.executor.executionCount, 0)
    assert.equal(fixture.store.claims.length, 0)
  }
})

test('workflow, approval and authenticated workload mismatches fail before PostgreSQL admission', async () => {
  const workflow = setup()
  const wrongWorkflow = workflow.request()
  wrongWorkflow.proposal.workflow_id = 'wf_wrong_demo_001'
  await rejectsCode(workflow.broker.submit(wrongWorkflow), 'BROKER_WORKFLOW_MISMATCH')

  const approval = setup()
  const wrongApproval = approval.request()
  wrongApproval.proposal.approval_id = 'approval_wrong_demo_001'
  await rejectsCode(approval.broker.submit(wrongApproval), 'BROKER_APPROVAL_MISMATCH')

  const workload = setup({
    callerIdentity: { workload_id: 'workload_wrong_demo_001', instance_id: 'instance_wrong_demo_001' },
  })
  await rejectsCode(workload.broker.submit(workload.request()), 'BROKER_WORKLOAD_MISMATCH')
  assert.equal(workload.store.claims.length, 0)
})

test('a signed capability cannot move between instances of the same workload', async () => {
  const callerIdentity = {
    workload_id: CALLER_IDENTITY.workload_id,
    instance_id: 'instance_worker_demo_002',
  }
  const runtime = setup({ callerIdentity })
  const request = runtime.request()
  request.proposal.workload_identity = structuredClone(callerIdentity)

  await rejectsCode(runtime.broker.submit(request), 'BROKER_WORKLOAD_MISMATCH')
  assert.equal(runtime.executor.executionCount, 0)
  assert.equal(runtime.store.claims.length, 0)
})

test('signed full-contract digests reject approval and proposal mutations omitted by field bindings', async () => {
  for (const mutate of [
    approval => { approval.policy_evaluation.decision_id = 'decision_forged_demo_001' },
    approval => { approval.policy_evaluation.policy_digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    approval => { approval.scope.max_actions += 1 },
    approval => { approval.scope.max_duration_seconds += 1 },
    approval => { approval.scope.destinations[0].host = 'other.example.invalid' },
  ]) {
    const runtime = setup()
    const request = runtime.request()
    mutate(request.approval)
    await rejectsCode(runtime.broker.submit(request), 'BROKER_APPROVAL_DIGEST_MISMATCH')
    assert.equal(runtime.executor.executionCount, 0)
    assert.equal(runtime.store.claims.length, 0)
  }

  for (const mutate of [
    proposal => { proposal.context.project_ref = 'project_contract_demo_002' },
    proposal => { proposal.idempotency_key = 'idem_ticketpilot_action_002' },
  ]) {
    const runtime = setup()
    const request = runtime.request()
    mutate(request.proposal)
    await rejectsCode(runtime.broker.submit(request), 'BROKER_PROPOSAL_DIGEST_MISMATCH')
    assert.equal(runtime.executor.executionCount, 0)
    assert.equal(runtime.store.claims.length, 0)
  }
})

test('idempotency identity binds the complete canonical approval as well as the proposal', () => {
  const proposal = fixture('action-proposal')
  const approval = fixture('approval-record')
  const modifiedApproval = structuredClone(approval)
  modifiedApproval.policy_evaluation.decision_id = 'decision_reissued_demo_002'

  assert.notEqual(
    idempotencyFingerprint(proposal, approval),
    idempotencyFingerprint(proposal, modifiedApproval),
  )
})

test('absence of cryptographic authority or PostgreSQL fails closed before execution', async () => {
  const fixture = setup()
  assert.throws(() => new PostgresActionBroker({
    clock: { now: () => NOW },
    capabilityVerifier: null,
    workloadIdentityProvider: { current: () => CALLER_IDENTITY },
    executor: fixture.executor,
    brokerIdentity: BROKER_IDENTITY,
    store: fixture.store,
  }), error => error?.code === 'BROKER_AUTHORITY_VERIFIER_REQUIRED')

  const unavailable = setup({
    store: {
      async claim() { throw new BrokerRejection('BROKER_STORAGE_UNAVAILABLE') },
      async finalize() { throw new Error('unreachable') },
      async listInFlight() { throw new Error('unreachable') },
    },
  })
  await rejectsCode(unavailable.broker.submit(unavailable.request()), 'BROKER_STORAGE_UNAVAILABLE')
  assert.equal(unavailable.executor.executionCount, 0)
})

test('durable Broker source has no provider transport, secret lookup or runtime integration', () => {
  const source = [
    'postgres-action-broker.mjs',
    'postgres-action-store.mjs',
    'durable-broker-domain.mjs',
  ].map(name => fs.readFileSync(new URL(`../src/broker/${name}`, import.meta.url), 'utf8')).join('\n')
  assert.doesNotMatch(source, /node:(?:http|https|net|tls|dns|dgram|child_process|worker_threads)/)
  assert.doesNotMatch(source, /\bfetch\s*\(|\bWebSocket\b|activepieces|scaleway|mcp automation/i)
  assert.doesNotMatch(source, /BEGIN [A-Z ]*PRIVATE KEY/)
  assert.match(source, /BROKER_POSTGRES_STORE_REQUIRED/)
  assert.match(source, /BROKER_AUTHORITY_VERIFIER_REQUIRED/)
})

test('the PostgreSQL adapter sanitizes an unavailable database', async () => {
  const store = new PostgresActionStore({
    pool: { async connect() { throw new Error('driver connection detail') } },
  })
  await rejectsCode(store.listInFlight(), 'BROKER_STORAGE_UNAVAILABLE')
})

function setup({ callerIdentity = CALLER_IDENTITY, store = new RecordingStore() } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  let jtiSequence = 0
  const authority = new Ed25519CapabilityAuthority({
    signingKey: privateKey,
    kid: 'core-key_durable_demo_001',
    clock: { now: () => NOW },
    jtiFactory: () => `jti_durable_unit_${String(++jtiSequence).padStart(3, '0')}_abcdefghijklmnopqrstu`,
  })
  const keyRing = new StaticEd25519PublicKeyRing({
    keys: [{ kid: 'core-key_durable_demo_001', publicKey }],
  })
  const executor = new DeterministicPilotExecutor()
  const broker = new PostgresActionBroker({
    clock: { now: () => NOW },
    capabilityVerifier: new Ed25519CapabilityVerifier({ keyRing }),
    workloadIdentityProvider: { current: async () => structuredClone(callerIdentity) },
    executor,
    brokerIdentity: BROKER_IDENTITY,
    store,
  })
  return {
    authority,
    broker,
    executor,
    store,
    request() {
      const proposal = fixture('action-proposal')
      const workflow = fixture('workflow-ir')
      const approval = fixture('approval-record')
      return {
        proposal,
        workflow,
        approval,
        signedCapability: authority.issue({
          proposal,
          workflow,
          approval,
          workloadIdentity: structuredClone(CALLER_IDENTITY),
        }),
        previousEvidenceDigest: PREVIOUS_EVIDENCE,
      }
    },
  }
}

class RecordingStore {
  claims = []
  finalizations = []

  async claim(input) {
    this.claims.push(structuredClone(input))
    return { kind: 'claimed', actionId: input.actionId }
  }

  async finalize(input) {
    this.finalizations.push(structuredClone(input))
    return structuredClone(input.receipt)
  }

  async listInFlight() {
    return []
  }
}

function fixture(kind) {
  return JSON.parse(fs.readFileSync(new URL(`../fixtures/v1/${kind}/valid.json`, import.meta.url), 'utf8'))
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, error => error?.code === code && error?.message === code)
}
