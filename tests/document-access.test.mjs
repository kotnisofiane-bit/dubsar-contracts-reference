import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { DocumentAuthority } from '../src/document-access/authority.mjs'
import { validate, resources, decision, digest } from '../src/document-access/contracts.mjs'
import { assertContract, CONTRACT_KINDS } from '../src/contracts.mjs'
import { identity, request, context } from './helpers/document-access-fixture.mjs'

test('DA03 closed schema rejects wildcard, injection, oversized and duplicate requests', () => {
  const req = request({})
  validate('request', req)
  for (const patch of [{ extra: true }, { request_ref: '*' }, { requested_resources: [] },
    { requested_resources: Array(101).fill(req.requested_resources[0]) }, { proof: { large: 'a'.repeat(65536) } },
    { context: { ...context, policy: 'allow' } }]) assert.throws(() => validate('request', { ...req, ...patch }))
  assert.throws(() => resources([...req.requested_resources, ...req.requested_resources]))
})
test('DA02 authenticates before SQL and never accepts an execution audience', async () => {
  const id = identity(); let calls = 0
  const authority = new DocumentAuthority({ ...id, context, pool: { connect() { calls++; throw new Error('no storage') } } })
  for (const patch of [{ audience: 'dubsar:exact' }, { issuer: 'wrong' }, { expires_at: 1 }, { kind: 'workload' }]) {
    assert.equal((await authority.authorize(request(id.proof(patch)))).status, 'deny')
  }
  assert.equal(calls, 0)
  assert.throws(() => new DocumentAuthority({ ...id, context, pool: {}, audience: 'dubsar:exact' }))
})
test('DA02 absent/revoked source denies, unavailable storage remains distinct', async () => {
  const id = identity()
  const pool = { async connect() { throw new Error('database down') } }
  const make = extra => new DocumentAuthority({ ...id, context, pool, ...extra })
  assert.equal((await make({ verifySession: undefined }).authorize(request(id.proof()))).status, 'deny')
  id.state.sourceEnabled = false
  assert.equal((await make({}).authorize(request(id.proof()))).status, 'deny')
  id.state.sourceEnabled = true
  assert.equal((await make({}).authorize(request(id.proof()))).status, 'unavailable')
})
test('DA08 document decision is rejected by every effect contract', () => {
  const body = { schema: 'dubsar.document-decision/1', decision_id: 'id', subject_ref: 'subject', tenant_ref: 'tenant', active_function: 'reader',
    session_ref: 'session', request_ref: 'request', resources: [{ corpus_ref: 'c', document_ref: 'd', resource_version: 'v1' }],
    policy_epoch: '1', issued_at: '2026-09-13T00:00:00.000Z', expires_at: '2026-09-13T00:01:00.000Z' }
  const value = decision({ ...body, scope_digest: digest(body) })
  for (const kind of CONTRACT_KINDS) assert.throws(() => assertContract(kind, value))
  assert.throws(() => decision({ ...value, subject_ref: 'other' }))
})
test('DA10 existing approver restriction remains explicit', () => {
  const text = fs.readFileSync(new URL('../src/human-identity/registry.mjs', import.meta.url), 'utf8')
  assert.ok(text.includes("member.active_function !== 'approver'"))
})
