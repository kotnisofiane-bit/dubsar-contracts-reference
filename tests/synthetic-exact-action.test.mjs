import test from 'node:test'
import assert from 'node:assert/strict'
import { assertExactReceipt } from '../src/exact-action/receipt.mjs'
import { setupSyntheticExact, reprepareSynthetic, applySyntheticVariant, syntheticCase, attachmentBytes } from './helpers/synthetic-exact-action-fixture.mjs'

test('SX09 exact synthetic preparation has no effect; refused content cannot consume', async () => {
  const f = setupSyntheticExact('SX09')
  const display = f.state.artifacts.get(f.prepared.display.ref)
  assert.deepEqual(display.proposal.payload, f.proposal.payload)
  assert.deepEqual(Buffer.from(display.proposal.payload.attachments[0].content, 'utf8'), attachmentBytes)
  assert.equal(display.proposal.payload.thread_ref, 'thread-fixture-0001')
  assert.equal(f.store.claims.length, 0)
  assert.equal(f.state.executions.length, 0)
  f.decision.decision = 'REFUSE'
  await assert.rejects(f.authority.issueExact(f.issueInput()))
  assert.equal(f.store.claims.length, 0)
  assert.equal(f.state.executions.length, 0)
})

test('SX09 control: an unchanged approved synthetic payload reaches the instrumented executor exactly', async () => {
  const f = setupSyntheticExact('SX09')
  const receipt = await f.broker.submit(await f.request())
  assertExactReceipt(receipt)
  assert.deepEqual(f.state.executions[0].proposal.payload, f.proposal.payload)
  assert.equal(f.store.rows.size, 1)
  assert.equal(f.state.executions.length, 1)
  assert.equal(receipt.business_outcome, 'UNOBSERVED')
})

test('SX10 editing produces a new display while the old approval and signed capability remain unusable', async () => {
  const f = setupSyntheticExact('SX10'), original = await f.request()
  const oldDisplay = f.prepared.display.digest
  const oldDecision = structuredClone(f.decision)
  const change = syntheticCase('SX10').edit
  applySyntheticVariant(f, change)
  reprepareSynthetic(f, 2)
  assert.notEqual(f.prepared.display.digest, oldDisplay)
  assert.deepEqual(f.decision, oldDecision)
  assert.equal(f.state.artifacts.get(f.prepared.display.ref).proposal.payload.text, change.value)
  await assert.rejects(f.authority.issueExact(f.issueInput()))
  await assert.rejects(f.broker.submit({ ...original, proposal: structuredClone(f.proposal) }))
  assert.equal(f.store.claims.length, 0)
  assert.equal(f.state.executions.length, 0)
})

for (const caseId of ['SX11', 'SX12', 'SX13']) {
  for (const variant of syntheticCase(caseId).variants) {
    test(`${caseId} ${variant.field} alteration denies issuance and admission before any effect`, async () => {
      const f = setupSyntheticExact(caseId), original = await f.request()
      applySyntheticVariant(f, variant)
      await assert.rejects(f.authority.issueExact(f.issueInput()))
      await assert.rejects(f.broker.submit({ ...original, proposal: structuredClone(f.proposal) }))
      assert.equal(f.store.claims.length, 0)
      assert.equal(f.state.executions.length, 0)
    })
  }
}

for (const variant of syntheticCase('SX14').variants) {
  test(`SX14 ${variant} denies previously signed content with no consumption`, async () => {
    const f = setupSyntheticExact('SX14'), original = await f.request()
    if (variant === 'refused') f.decision.decision = 'REFUSE'
    else f.state.record.revoked = true
    await assert.rejects(f.authority.issueExact(f.issueInput()))
    await assert.rejects(f.broker.submit(original))
    assert.equal(f.store.claims.length, 0)
    assert.equal(f.state.executions.length, 0)
  })
}
