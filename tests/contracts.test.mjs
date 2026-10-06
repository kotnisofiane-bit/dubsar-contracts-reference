import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  CONTRACT_KINDS,
  assertApprovalCurrent,
  assertContract,
  assertNoSecretMaterial,
  consumeCapabilityClaims,
  consumeExecutionLease,
  hashContract,
  proposalPayloadDigest,
  receiptEvidenceDigest,
  schemaRegistry,
  validateContract,
} from '../src/contracts.mjs'
import { canonicalJson, domainSeparatedHash } from '../src/canonical-json.mjs'
import { ACTION_STATES, STATE_MACHINE, isTransitionAllowed } from '../src/state-machine.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))

test('all schema references resolve locally and fixture pairs are discriminated', () => {
  const references = schemaRegistry.assertAllReferencesClosed()
  assert.ok(references.length > 0)
  assert.equal(schemaRegistry.schemaNames().length, 9)
  assert.equal(CONTRACT_KINDS.length, 8)
  for (const kind of CONTRACT_KINDS) {
    const valid = fixture(kind, 'valid')
    const invalid = fixture(kind, 'invalid')
    assert.deepEqual(validateContract(kind, valid), [], `${kind} valid fixture`)
    assert.notEqual(validateContract(kind, invalid).length, 0, `${kind} invalid fixture`)
  }
})

test('canonical hash ignores object key insertion order and binds business changes', () => {
  const workflow = fixture('workflow-ir', 'valid')
  const reordered = reverseObjectKeys(workflow)
  assert.equal(canonicalJson(workflow), canonicalJson(reordered))
  assert.equal(hashContract('workflow-ir', workflow), hashContract('workflow-ir', reordered))
  const changed = clone(workflow)
  changed.nodes[1].connector.version = '1.2.4'
  assert.notEqual(hashContract('workflow-ir', workflow), hashContract('workflow-ir', changed))
  assert.notEqual(
    domainSeparatedHash('dubsar.contract.workflow-ir.v1', workflow),
    domainSeparatedHash('dubsar.contract.action-proposal.v1', workflow),
  )
})

test('workflow graph changes invalidate the exact approval digest', () => {
  const workflow = fixture('workflow-ir', 'valid')
  const approval = fixture('approval-record', 'valid')
  approval.workflow.workflow_digest = hashContract('workflow-ir', workflow)
  assert.equal(assertApprovalCurrent(approval, workflow, '2026-08-14T10:30:00.000Z'), true)
  const changed = clone(workflow)
  changed.nodes[1].parameters.priority = 'urgent'
  assert.throws(
    () => assertApprovalCurrent(approval, changed, '2026-08-14T10:30:00.000Z'),
    /does not bind/,
  )
  assert.throws(
    () => assertApprovalCurrent(approval, workflow, '2026-08-14T11:00:00.000Z'),
    /expired/,
  )
})

test('execution lease is workload-bound, expiring and single-use', () => {
  const lease = fixture('execution-lease', 'valid')
  const expected = {
    run_id: lease.run_id,
    step_id: lease.step_id,
    workflow_id: lease.workflow.workflow_id,
    workflow_version: lease.workflow.workflow_version,
    workflow_digest: lease.workflow.workflow_digest,
    approval_id: lease.approval_id,
    worker: clone(lease.worker),
    expected_action: clone(lease.expected_action),
  }
  const replayCache = new Set()
  assert.equal(consumeExecutionLease(lease, expected, replayCache, '2026-08-14T10:00:30.000Z'), true)
  assert.throws(() => consumeExecutionLease(lease, expected, replayCache, '2026-08-14T10:00:31.000Z'), /replay/)
  const wrongWorkload = clone(expected)
  wrongWorkload.worker.workload_id = 'workload_wrong_demo_001'
  assert.throws(() => consumeExecutionLease(lease, wrongWorkload, new Set(), '2026-08-14T10:00:30.000Z'), /workload/)
  const wrongAction = clone(expected)
  wrongAction.expected_action.action.operation = 'delete_ticket'
  assert.throws(() => consumeExecutionLease(lease, wrongAction, new Set(), '2026-08-14T10:00:30.000Z'), /expected action/)
  const wrongApproval = clone(expected)
  wrongApproval.approval_id = 'approval_wrong_demo_001'
  assert.throws(() => consumeExecutionLease(lease, wrongApproval, new Set(), '2026-08-14T10:00:30.000Z'), /approval/)
  assert.throws(() => consumeExecutionLease(lease, expected, new Set(), '2026-08-14T10:01:00.000Z'), /expired/)
})

test('capability claims bind workload, proposal payload and one-use jti', () => {
  const proposal = fixture('action-proposal', 'valid')
  const claims = fixture('capability-claims', 'valid')
  claims.payload_digest = proposalPayloadDigest(proposal)
  const usedJtis = new Set()
  assert.equal(consumeCapabilityClaims(claims, proposal, proposal.workload_identity.workload_id, usedJtis, '2026-08-14T10:00:30.000Z'), true)
  assert.throws(() => consumeCapabilityClaims(claims, proposal, proposal.workload_identity.workload_id, usedJtis, '2026-08-14T10:00:31.000Z'), /replay/)

  const wrongPayload = clone(proposal)
  wrongPayload.payload.summary = 'changed'
  assert.throws(() => consumeCapabilityClaims(claims, wrongPayload, wrongPayload.workload_identity.workload_id, new Set(), '2026-08-14T10:00:30.000Z'), /payload digest/)
  const wrongWorkflow = clone(proposal)
  wrongWorkflow.workflow_id = 'wf_wrong_demo_001'
  assert.throws(() => consumeCapabilityClaims(claims, wrongWorkflow, wrongWorkflow.workload_identity.workload_id, new Set(), '2026-08-14T10:00:30.000Z'), /workflow id/)
  const wrongApproval = clone(proposal)
  wrongApproval.approval_id = 'approval_wrong_demo_001'
  assert.throws(() => consumeCapabilityClaims(claims, wrongApproval, wrongApproval.workload_identity.workload_id, new Set(), '2026-08-14T10:00:30.000Z'), /approval/)
  assert.throws(() => consumeCapabilityClaims(claims, proposal, 'workload_wrong_demo_001', new Set(), '2026-08-14T10:00:30.000Z'), /workload/)
  assert.throws(() => consumeCapabilityClaims(claims, proposal, proposal.workload_identity.workload_id, new Set(), '2026-08-14T10:01:00.000Z'), /expired/)
})

test('state transition matrix is exhaustive and undeclared moves fail closed', () => {
  const expected = new Set(STATE_MACHINE.allowed_transitions.map(({ from, to }) => `${from}->${to}`))
  assert.equal(expected.size, 11)
  let admitted = 0
  let refused = 0
  for (const from of ACTION_STATES) {
    for (const to of ACTION_STATES) {
      const allowed = isTransitionAllowed(from, to)
      assert.equal(allowed, expected.has(`${from}->${to}`), `${from} -> ${to}`)
      allowed ? admitted += 1 : refused += 1
    }
  }
  assert.equal(admitted, 11)
  assert.equal(refused, ACTION_STATES.length ** 2 - 11)
  assert.equal(isTransitionAllowed('INDETERMINATE', 'FAILED_RETRYABLE'), false)
  assert.equal(isTransitionAllowed('INDETERMINATE', 'IN_FLIGHT'), false)
})

test('fixtures contain no secret material and secret-shaped payloads are refused', () => {
  for (const kind of CONTRACT_KINDS) {
    assert.doesNotThrow(() => assertNoSecretMaterial(fixture(kind, 'valid')))
    assert.doesNotThrow(() => assertNoSecretMaterial(fixture(kind, 'invalid')))
  }
  const proposal = fixture('action-proposal', 'valid')
  proposal.payload.api_key = 'not-a-real-value'
  assert.throws(() => assertContract('action-proposal', proposal), /secret field/)
  const camelCase = fixture('action-proposal', 'valid')
  camelCase.payload.clientSecret = 'not-a-real-value'
  assert.throws(() => assertContract('action-proposal', camelCase), /secret field/)
})

test('action receipt evidence digest binds outcome and prior chain link', () => {
  const receipt = fixture('action-receipt', 'valid')
  assert.equal(receipt.evidence_chain.event_digest, receiptEvidenceDigest(receipt))
  assertContract('action-receipt', receipt)
  receipt.evidence_chain.previous_event_digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  assert.throws(() => assertContract('action-receipt', receipt), /evidence digest/)
})

test('canonical JSON rejects unsafe numeric and executable values', () => {
  assert.throws(() => canonicalJson({ value: 1.5 }), /safe integer/)
  assert.throws(() => canonicalJson({ value: Number.MAX_SAFE_INTEGER + 1 }), /safe integer/)
  assert.throws(() => canonicalJson({ value: () => true }), /non-JSON/)
})

function fixture(kind, verdict) {
  const filePath = path.join(root, 'fixtures', 'v1', kind, `${verdict}.json`)
  return JSON.parse(fs.readFileSync(filePath, 'utf8'))
}

function reverseObjectKeys(value) {
  if (Array.isArray(value)) return value.map(reverseObjectKeys)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).reverse().map(key => [key, reverseObjectKeys(value[key])]))
}

function clone(value) {
  return structuredClone(value)
}
