import test from 'node:test'
import assert from 'node:assert/strict'
import { sign } from 'node:crypto'
import fs from 'node:fs'
import { PostgresActionStore } from '../src/broker/postgres-action-store.mjs'
import { setupExact } from './helpers/exact-action-fixture.mjs'
import { assertContract, hashPayload } from '../src/contracts.mjs'
import { ExactActionGate, exactSchemaRegistry, hashExact, prepareExactAction } from '../src/exact-action/contracts.mjs'
import { assertExactReceipt, exactReceiptDigest } from '../src/exact-action/receipt.mjs'
import { Ed25519CapabilityAuthority } from '../src/core/ed25519-capability-authority.mjs'
import { Ed25519CapabilityVerifier } from '../src/broker/ed25519-capability-verifier.mjs'
import { PostgresActionBroker } from '../src/broker/postgres-action-broker.mjs'
import { parseSignedCapability, encodeCapabilitySegment } from '../src/core/signed-capability-format.mjs'

test('A01/A08 exact preparation, authoritative test decision, signature and instrumented effect share one proof', async () => {
  const f = setupExact(), request = await f.request()
  const receipt = await f.broker.submit(request)
  assertExactReceipt(receipt)
  assert.equal(receipt.schema, 'dubsar.action-receipt.v2')
  assert.equal(receipt.after_state, 'SUCCEEDED')
  assert.equal(receipt.business_outcome, 'UNOBSERVED')
  assert.equal(receipt.result.provider_status, 202)
  assert.deepEqual(receipt.exact_action.binding, f.binding)
  assert.equal(receipt.exact_action.decision_digest, hashExact('decision', f.decision))
  assert.deepEqual(f.state.executions[0].proposal.payload, request.proposal.payload)
  assert.deepEqual(f.state.executions[0].exactMaterial, f.material)
  assert.deepEqual(f.store.claims[0].pendingContext.exactAction, receipt.exact_action)
  const corrupted = structuredClone(receipt)
  corrupted.exact_action.binding.mission.id = 'mis_other'
  assert.throws(() => assertExactReceipt(corrupted))
})

for (const field of ['tenant_ref', 'project_ref', 'run_id', 'step_id', 'proposal_id', 'mission', 'legacy_refs', 'workload_identity']) {
  test(`A02 server binding mutation ${field} is denied before durable consumption`, async () => {
    const f = setupExact(), request = await f.request()
    const binding = f.state.record.binding
    if (field === 'mission') binding.mission.id += 'other'
    else if (field === 'legacy_refs') binding.legacy_refs[0].namespace += '-other'
    else if (field === 'workload_identity') binding.workload_identity.instance_id += '_other'
    else binding[field] += '_other'
    await assert.rejects(f.broker.submit(request))
    assert.equal(f.store.claims.length, 0)
    assert.equal(f.state.executions.length, 0)
  })
}

for (const [name, mutate] of [
  ['recipient', f => { f.proposal.payload.to[0] = 'other@example.invalid' }],
  ['body', f => { f.proposal.payload.text = 'other' }],
  ['attachment', f => { f.proposal.payload.attachments[0].content = 'other' }],
  ['sender default', f => { f.proposal.payload.from = 'other@example.invalid' }],
  ['configuration', f => { f.prepared.material.configuration_digest = `sha256:${'b'.repeat(64)}` }],
  ['adapter', f => { f.prepared.material.adapter_digest = `sha256:${'b'.repeat(64)}` }],
  ['display', f => { f.state.artifacts.get(f.prepared.display.ref).proposal.payload.text = 'other' }],
  ['artifact', f => { f.state.artifacts.get(f.prepared.artifact.ref).text = 'other' }],
  ['connection', f => { f.proposal.connection_ref = 'conn_other_demo' }],
  ['destination', f => { f.proposal.destination.host = 'other.example.invalid' }],
]) {
  test(`A03 ${name} mutation invalidates issuance and consumption`, async () => {
    const f = setupExact(), request = await f.request()
    mutate(f)
    request.proposal = structuredClone(f.proposal)
    await assert.rejects(f.authority.issueExact(f.issueInput()))
    await assert.rejects(f.broker.submit(request))
    assert.equal(f.state.executions.length, 0)
    assert.equal(f.store.claims.length, 0)
  })
}

test('A04 copied APPROVE JSON and missing trusted ports have no authority', async () => {
  const f = setupExact()
  assert.throws(() => new ExactActionGate({ records: f.state.record, artifacts: f.state.artifacts }))
  const legacy = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock })
  await assert.rejects(legacy.issueExact(f.issueInput()), /CORE_EXACT_GATE_REQUIRED/)
  assert.throws(() => legacy.issue(f.issueInput()), /CORE_EXACT_MODE_REQUIRED/)
  assert.throws(() => f.authority.issue(f.issueInput()), /CORE_EXACT_MODE_REQUIRED/)
  await assert.rejects(f.authority.issueExact({ ...f.issueInput(), decision: f.decision }))
  for (const change of [r => { r.principal.eligible = false }, r => { r.principal.active_function = 'other' },
    r => { r.principal.presented_digest = `sha256:${'a'.repeat(64)}` }, r => { r.decision.policy_digest = `sha256:${'a'.repeat(64)}` }]) {
    const g = setupExact(), request = await g.request()
    change(g.state.record)
    await assert.rejects(g.broker.submit(request))
    assert.equal(g.store.claims.length, 0)
  }
})

for (const [name, change] of [
  ['refusal', f => { f.decision.decision = 'REFUSE' }],
  ['revocation', f => { f.state.record.revoked = true }],
  ['expiry equality', f => { f.state.now = f.decision.expires_at }],
  ['expiry during artifact read', f => { f.state.onRead = async () => { f.state.now = f.decision.expires_at } }],
]) {
  test(`A05 ${name} denies every new consumption`, async () => {
    const f = setupExact(), request = await f.request()
    change(f)
    await assert.rejects(f.broker.submit(request))
    assert.equal(f.store.claims.length, 0)
    assert.equal(f.state.executions.length, 0)
  })
}

test('A06 concurrent submissions and a completed replay emit once (serialized store double)', async () => {
  const f = setupExact(), request = await f.request()
  const results = await Promise.allSettled([f.broker.submit(request), f.broker.submit(request)])
  assert.equal(f.state.executions.length, 1)
  assert.ok(results.some(r => r.status === 'fulfilled'))
  const receipt = await f.broker.submit(await f.request())
  assertExactReceipt(receipt)
  assert.equal(f.state.executions.length, 1)
})

test('A06 crash after provider acceptance recovers INDETERMINATE with mission and never resends', async () => {
  const f = setupExact({ failFinalize: true }), request = await f.request()
  await assert.rejects(f.broker.submit(request), e => e.code === 'BROKER_FINALIZATION_UNCERTAIN')
  f.state.failFinalize = false
  const restarted = new PostgresActionBroker(f.brokerOptions)
  assert.deepEqual(await restarted.recoverInFlight(), { recovered: 1 })
  const receipt = await restarted.submit(await f.request())
  assertExactReceipt(receipt)
  assert.equal(receipt.after_state, 'INDETERMINATE')
  assert.equal(receipt.business_outcome, 'UNOBSERVED')
  assert.deepEqual(receipt.exact_action.binding.mission, f.binding.mission)
  assert.equal(f.state.executions.length, 1)
})

test('A06 crash before executor also recovers without inventing an effect', async () => {
  const f = setupExact({ lifecycle: { afterClaim: async () => { throw new Error('crash') } } })
  const request = await f.request()
  await assert.rejects(f.broker.submit(request), e => e.code === 'BROKER_IN_FLIGHT_INTERRUPTED')
  await f.broker.recoverInFlight()
  const receipt = await f.broker.submit(await f.request())
  assert.equal(receipt.after_state, 'INDETERMINATE')
  assert.equal(f.state.executions.length, 0)
})

test('A07 v1 rejects v2, v2 rejects v1, signed proof cannot be stripped or substituted', async () => {
  const f = setupExact(), request = await f.request()
  const legacyVerifier = new Ed25519CapabilityVerifier({ keyRing: f.keyRing })
  assert.throws(() => legacyVerifier.verifySigned({ signedCapability: request.signedCapability, now: f.state.now }))
  const legacyAuthority = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock })
  const { decisionRef, ...legacyInput } = f.issueInput()
  const legacyToken = legacyAuthority.issue(legacyInput)
  assert.throws(() => f.verifier.verifySigned({ signedCapability: legacyToken, now: f.state.now }))
  const { header, payload, signature } = parseSignedCapability(request.signedCapability)
  delete payload.exact_action
  header.v = 1
  payload.schema = 'dubsar.signed-capability.v1'
  const stripped = `${encodeCapabilitySegment(header)}.${encodeCapabilitySegment(payload)}.${signature.toString('base64url')}`
  assert.throws(() => legacyVerifier.verifySigned({ signedCapability: stripped, now: f.state.now }))
  const p = parseSignedCapability(request.signedCapability)
  p.payload.exact_action.binding.mission.id = 'mis_forged'
  const input = `${encodeCapabilitySegment(p.header)}.${encodeCapabilitySegment(p.payload)}`
  // Even a cryptographically valid but stale/incorrect Core binding must match authoritative records.
  request.signedCapability = `${input}.${sign(null, Buffer.from(input), f.privateKey).toString('base64url')}`
  await assert.rejects(f.broker.submit(request))
  assert.equal(f.store.claims.length, 0)
  assert.throws(() => assertContract('action-receipt', { schema: 'dubsar.action-receipt.v2' }))
})

test('exact Broker rejects a v1 verifier configuration even with a valid v1 token', async () => {
  const f = setupExact(), request = await f.request()
  const { decisionRef, ...input } = f.issueInput()
  request.signedCapability = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock }).issue(input)
  const broker = new PostgresActionBroker({ ...f.brokerOptions, capabilityVerifier: new Ed25519CapabilityVerifier({ keyRing: f.keyRing }) })
  await assert.rejects(broker.submit(request), e => e.code === 'BROKER_EXACT_MODE_REQUIRED')
  const noGate = new PostgresActionBroker({ ...f.brokerOptions, exactActionGate: undefined })
  await assert.rejects(noGate.submit(await f.request()), e => e.code === 'BROKER_EXACT_MODE_REQUIRED')
  assert.equal(f.store.claims.length, 0)
})

test('snapshot survives caller mutation during awaited artifact reads', async () => {
  const f = setupExact(), request = await f.request()
  f.state.onRead = async () => { request.proposal.payload.text = 'racing mutation'; request.previousEvidenceDigest = `sha256:${'b'.repeat(64)}` }
  const receipt = await f.broker.submit(request)
  assert.equal(f.state.executions[0].proposal.payload.text, 'Approved body')
  assert.equal(receipt.evidence_chain.previous_event_digest, `sha256:${'3'.repeat(64)}`)
})

test('changed mission with a new legitimate decision conflicts with already consumed idempotency', async () => {
  const f = setupExact()
  await f.broker.submit(await f.request())
  f.binding.mission.id = 'mis_new_mission'
  const next = prepareExactAction({ binding: f.binding, proposal: f.proposal, approval: f.approval, material: f.material,
    expectedEffect: f.prepared.expected_effect, artifactRef: f.prepared.artifact.ref, displayRef: f.prepared.display.ref,
    issuedAt: f.prepared.issued_at, expiresAt: f.prepared.expires_at })
  Object.assign(f.prepared, next.prepared)
  f.state.artifacts.set(f.prepared.display.ref, next.display)
  Object.assign(f.decision, { binding_digest: hashExact('binding', f.binding), prepared_digest: hashExact('prepared', f.prepared), display_digest: f.prepared.display.digest })
  f.state.record.principal.presented_digest = f.decision.display_digest
  await assert.rejects(f.broker.submit(await f.request()), /BROKER_IDEMPOTENCY_CONFLICT/)
  assert.equal(f.state.executions.length, 1)
})

test('v2 schemas are closed, hash deterministic and preparation refuses digest-only payload', () => {
  const f = setupExact()
  exactSchemaRegistry.assertAllReferencesClosed()
  assert.equal(hashExact('prepared', f.prepared), hashExact('prepared', structuredClone(f.prepared)))
  assert.throws(() => hashExact('decision', { ...f.decision, authoritative: true }))
  delete f.proposal.payload
  f.proposal.payload_digest = hashPayload({ data: 'digest only' })
  assert.throws(() => prepareExactAction({ binding: f.binding, proposal: f.proposal }), /INLINE_PAYLOAD_REQUIRED/)
})

test('v2 stored fixtures and independent fixed hash vectors remain valid', () => {
  const vectors = JSON.parse(fs.readFileSync(new URL('../contracts/v2/hash-vectors.json', import.meta.url)))
  for (const kind of ['binding', 'prepared', 'decision', 'proof', 'receipt']) {
    const read = name => JSON.parse(fs.readFileSync(new URL(`../fixtures/v2/${kind}/${name}.json`, import.meta.url)))
    exactSchemaRegistry.assertValid(`${kind}.schema.json`, read('valid'))
    assert.throws(() => exactSchemaRegistry.assertValid(`${kind}.schema.json`, read('invalid')))
    if (kind === 'receipt') assertExactReceipt(read('valid'))
    else assert.equal(hashExact(kind, read('valid')), vectors[kind])
  }
})

test('PostgreSQL adapter rolls back when admission expires during SQL lock wait', async () => {
  const calls = []
  const store = new PostgresActionStore({ pool: { async connect() { return {
    async query(sql) { calls.push(sql); return { rows: [{ claim: { kind: 'claimed' } }] } }, release() {},
  } } } })
  const f = setupExact()
  await f.broker.submit(await f.request())
  await assert.rejects(store.claim({ ...f.store.claims[0], assertAdmissionCurrent() { throw new Error('EXACT_ACTION_EXPIRED') } }))
  assert.ok(calls.includes('ROLLBACK'))
  assert.ok(!calls.includes('COMMIT'))
})

test('exact executor configuration must equal approved material and receives frozen data', async () => {
  const f = setupExact(), request = await f.request()
  const material = structuredClone(f.material)
  material.configuration.mode = 'other'
  material.configuration_digest = hashPayload(material.configuration)
  const broker = new PostgresActionBroker({ ...f.brokerOptions, executor: { ...f.brokerOptions.executor, exactMaterial: material } })
  await assert.rejects(broker.submit(request))
  assert.equal(f.store.claims.length, 0)
  const mutated = new PostgresActionBroker({ ...f.brokerOptions, executor: { ...f.brokerOptions.executor,
    async execute(input) { input.proposal.payload.text = 'unapproved'; throw new Error('unreachable') } } })
  const receipt = await mutated.submit(request)
  assert.equal(receipt.after_state, 'INDETERMINATE')
  assert.equal(f.state.executions.length, 0)
})

test('non-2xx provider result never becomes a successful exact receipt', async () => {
  const f = setupExact()
  const broker = new PostgresActionBroker({ ...f.brokerOptions, executor: { ...f.brokerOptions.executor,
    async execute() { return { kind: 'success', provider_status: 500, output: {} } } } })
  const receipt = await broker.submit(await f.request())
  assert.equal(receipt.after_state, 'INDETERMINATE')
  assert.equal(receipt.business_outcome, 'UNOBSERVED')
})

test('receipt validation rejects a rebound mission even with a recomputed receipt digest', async () => {
  const f = setupExact()
  const receipt = await f.broker.submit(await f.request())
  receipt.exact_action.binding.mission.id = 'mis_other_mission'
  receipt.evidence_chain.event_digest = exactReceiptDigest(receipt)
  assert.throws(() => assertExactReceipt(receipt), /EXACT_ACTION_BINDING_MISMATCH/)
})

test('receipt validation accepts only 2xx provider status for success after rehashing', async () => {
  const f = setupExact()
  const original = await f.broker.submit(await f.request())
  for (const status of [199, 200, 299, 300, 500]) {
    const receipt = structuredClone(original)
    receipt.result.provider_status = status
    receipt.evidence_chain.event_digest = exactReceiptDigest(receipt)
    if (status >= 200 && status < 300) assert.doesNotThrow(() => assertExactReceipt(receipt))
    else assert.throws(() => assertExactReceipt(receipt), /EXACT_RECEIPT_PROVIDER_STATUS_INVALID/)
  }
})
