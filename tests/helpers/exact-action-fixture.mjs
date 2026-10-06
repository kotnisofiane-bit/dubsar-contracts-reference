import fs from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'
import { hashPayload } from '../../src/contracts.mjs'
import { ExactActionGate, prepareExactAction, hashExact } from '../../src/exact-action/contracts.mjs'
import { Ed25519CapabilityAuthority } from '../../src/core/ed25519-capability-authority.mjs'
import { Ed25519CapabilityVerifier, StaticEd25519PublicKeyRing } from '../../src/broker/ed25519-capability-verifier.mjs'
import { PostgresActionBroker } from '../../src/broker/postgres-action-broker.mjs'

const fixture = kind => JSON.parse(fs.readFileSync(new URL(`../../fixtures/v1/${kind}/valid.json`, import.meta.url)))
export function setupExact({ lifecycle = {}, failFinalize = false } = {}) {
  const state = { now: '2026-08-14T10:00:30.000Z', executions: [], failFinalize }
  const clock = { now: () => state.now }
  const proposal = fixture('action-proposal'), approval = fixture('approval-record'), workflow = fixture('workflow-ir')
  // Generic material payload: all email-like values are explicit, including empty defaults.
  proposal.payload = { from: 'sender@example.invalid', to: ['recipient@example.invalid'], cc: [], bcc: [],
    subject: 'Approved message', text: 'Approved body', html: null,
    attachments: [{ name: 'example.txt', content: 'approved attachment', content_type: 'text/plain' }] }
  const binding = { schema: 'dubsar.mission-binding.v2', tenant_ref: proposal.context.tenant_ref,
    mission: { namespace: 'scribe-backend', id: 'mis_1234567890abcdef' },
    legacy_refs: [{ namespace: 'task-runtime', id: 'mission_demo_001' }], project_ref: proposal.context.project_ref,
    run_id: proposal.run_id, step_id: proposal.step_id, proposal_id: proposal.proposal_id, workload_identity: proposal.workload_identity }
  const configuration = { mode: 'instrumented', defaults: {} }
  const material = { adapter_digest: `sha256:${'a'.repeat(64)}`, configuration_digest: hashPayload(configuration), configuration }
  const { prepared, display } = prepareExactAction({ binding, proposal, approval, material, expectedEffect: 'Instrumented exact content capture',
    artifactRef: 'artifact:content:1', displayRef: 'artifact:display:1', issuedAt: '2026-08-14T10:00:00.000Z', expiresAt: '2026-08-14T10:01:30.000Z' })
  const decision = { schema: 'dubsar.exact-decision.v2', decision_ref: 'decision:exact:1', binding_digest: hashExact('binding', binding),
    prepared_digest: hashExact('prepared', prepared), display_digest: prepared.display.digest,
    approver: { subject: 'test-user:1', active_function: 'reviewer' }, policy_digest: approval.policy_evaluation.policy_digest,
    decision: 'APPROVE', issued_at: '2026-08-14T10:00:10.000Z', expires_at: '2026-08-14T10:01:20.000Z' }
  state.record = { binding, prepared, decision, revoked: false,
    principal: { ...decision.approver, eligible: true, presented_digest: decision.display_digest } }
  state.artifacts = new Map([[prepared.artifact.ref, structuredClone(proposal.payload)], [prepared.display.ref, display]])
  // Test-only authority and serializable store. Neither authenticates a person nor runs PostgreSQL.
  let tail = Promise.resolve()
  const gate = new ExactActionGate({ records: { withCurrent(ref, callback) {
    const result = tail.then(() => {
      if (ref !== state.record.decision.decision_ref) throw new Error('TEST_RECORD_NOT_FOUND')
      return callback(state.record)
    })
    tail = result.catch(() => {})
    return result
  } }, artifacts: { async read(ref) { if (state.onRead) await state.onRead(ref); return state.artifacts.get(ref) } } })
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const kid = 'core-key_exact_demo_001'
  const keyRing = new StaticEd25519PublicKeyRing({ keys: [{ kid, publicKey }] })
  const authority = new Ed25519CapabilityAuthority({ signingKey: privateKey, kid, clock, exactActionGate: gate })
  const verifier = new Ed25519CapabilityVerifier({ keyRing, version: 2 })
  const store = new ExactTestStore(state)
  const executor = { exactMaterial: structuredClone(material),
    assertSupported() {},
    async execute(input) {
      if (!Object.isFrozen(input.proposal.payload) || !Object.isFrozen(input.exactMaterial.configuration)) throw new Error('TEST_INPUT_NOT_FROZEN')
      state.executions.push(structuredClone(input))
      if (state.onExecute) await state.onExecute()
      return { kind: 'success', provider_status: 202, output: { accepted: true } }
    } }
  const brokerOptions = { clock, capabilityVerifier: verifier, exactActionGate: gate, store, executor, lifecycle,
    workloadIdentityProvider: { current: async () => state.caller ?? proposal.workload_identity },
    brokerIdentity: { workload_id: 'workload_broker_demo_001', instance_id: 'instance_broker_demo_001' } }
  const broker = new PostgresActionBroker(brokerOptions)
  const issueInput = () => ({ proposal: structuredClone(proposal), approval: structuredClone(approval), workflow: structuredClone(workflow),
    workloadIdentity: structuredClone(proposal.workload_identity), decisionRef: decision.decision_ref })
  return { state, clock, proposal, approval, workflow, binding, material, prepared, display, decision, gate, store,
    authority, verifier, keyRing, privateKey, kid, broker, brokerOptions, issueInput,
    async request() { return { proposal: structuredClone(proposal), approval: structuredClone(approval), workflow: structuredClone(workflow),
      signedCapability: await authority.issueExact(issueInput()), previousEvidenceDigest: `sha256:${'3'.repeat(64)}` } } }
}

export class ExactTestStore {
  claims = []
  rows = new Map()
  jtis = new Set()
  constructor(state) { this.state = state }
  async claim(input) {
    const { assertAdmissionCurrent, ...data } = input
    if (assertAdmissionCurrent) await assertAdmissionCurrent()
    this.claims.push(structuredClone(data))
    if (this.jtis.has(input.claims.jti)) throw new Error('BROKER_CAPABILITY_REPLAY')
    this.jtis.add(input.claims.jti)
    const row = this.rows.get(input.actionId)
    if (row) {
      if (row.fingerprint !== input.fingerprint) throw new Error('BROKER_IDEMPOTENCY_CONFLICT')
      return row.receipt ? { kind: 'completed', receipt: row.receipt } : { kind: 'in_flight' }
    }
    this.rows.set(input.actionId, structuredClone(data))
    return { kind: 'claimed' }
  }
  async finalize(input) {
    if (this.state.failFinalize) throw Object.assign(new Error('storage unavailable'), { code: 'BROKER_STORAGE_UNAVAILABLE' })
    this.rows.get(input.actionId).receipt = structuredClone(input.receipt)
    return structuredClone(input.receipt)
  }
  async listInFlight() { return [...this.rows.values()].filter(row => !row.receipt) }
}
