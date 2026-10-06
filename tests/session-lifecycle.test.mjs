import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { Readable, Writable } from 'node:stream'
import { signMessage, verifyMessage, digestMessage, createSourceVerifier } from '../src/human-identity/lifecycle-wire.mjs'
import { serve, encodeFrame } from '../src/exact-action/stdio-authority.mjs'
import { PortalSessionLifecycle } from '../src/human-identity/lifecycle.mjs'
import { PostgresExactActionRecords } from '../src/exact-action/postgres-records.mjs'
import { EventEmitter } from 'node:events'

test('S07 transaction deadline destroys checkout and rejects late continuation', async () => {
  let resume, late, destroyed = false, ended = false
  const statements = []
  const client = Object.assign(new EventEmitter(), {
    async query(sql) { statements.push(sql); return { rows: [] } },
    release(broken) {
      destroyed = broken
      setImmediate(() => { client.emit('error', new Error('late socket close')); client.emit('end'); ended = true })
    },
  })
  const records = new PostgresExactActionRecords({ waitMs: 30,
    context: { tenant_ref: 't', project_ref: 'p', mission: { namespace: 'm', id: 'i' } },
    humanRegistry: { assertContext() {}, checkDecision() {} }, requireHuman: true,
    pool: { async connect() { return client } } })
  const pending = records.humanTransaction(async (query, client) => {
    late = () => client.query('SELECT late')
    await new Promise(r => { resume = r })
    await query('SELECT resumed')
  })
  await assert.rejects(pending, /EXACT_RECORDS_TRANSACTION_TIMEOUT/)
  assert.equal(destroyed, true)
  await assert.rejects(late(), /EXACT_RECORDS_STORAGE_UNAVAILABLE/)
  resume()
  await new Promise(r => setImmediate(r))
  assert.equal(ended, true)
  assert.equal(client.listenerCount('error'), 0)
  assert.equal(statements.some(sql => sql === 'COMMIT' || sql.includes('late') || sql.includes('resumed')), false)
})
test('S07 timed out pool checkout releases a late connection', async () => {
  let deliver, released = false
  const runtime = new PortalSessionLifecycle({ pool: { connect: () => new Promise(r => { deliver = r }) }, context: {},
    humanIssuer: 'portal', clock: { now: () => new Date().toISOString() }, verifySource: async () => 0 })
  await assert.rejects(runtime.connect(), /HUMAN_STORAGE_UNAVAILABLE/)
  deliver({ release: () => { released = true } })
  await new Promise(r => setImmediate(r))
  assert.equal(released, true)
})
const a = generateKeyPairSync('ed25519'), b = generateKeyPairSync('ed25519')
const now = 1800000000000
const clock = { now: () => new Date(now).toISOString() }
const request = () => signMessage({ issuer: 'portal', audience: 'core', operation: 'register', body: { parent_id: 'p' }, privateKey: a.privateKey, now })
const verifier = { issuer: 'portal', audience: 'core', operations: ['register'], publicKey: a.publicKey, now }
test('S04 signed lifecycle: bindings, unknown fields, expiry and wrong key refuse', () => {
  const r = request()
  assert.equal(verifyMessage(r, verifier).body.parent_id, 'p')
  for (const patch of [{ audience: 'other' }, { operation: 'revoke' }, { body: { parent_id: 'other' } }, { extra: true }, { expires_at: r.expires_at + 1 }])
    assert.throws(() => verifyMessage({ ...r, ...patch }, verifier))
  assert.throws(() => verifyMessage(r, { ...verifier, publicKey: b.publicKey }))
  assert.throws(() => verifyMessage(r, { ...verifier, now: now + 30000 }))
})
test('S07 source callback has one-use challenge and rejects replay/timeout/negative result', async () => {
  let previous, calls = 0
  const options = { issuer: 'core', audience: 'portal', privateKey: b.privateKey, publicKey: a.publicKey, clock }
  const source = createSourceVerifier({ ...options, exchange: async request => {
    calls++
    if (previous) return previous
    previous = signMessage({ issuer: 'portal', audience: 'core', operation: 'verified', privateKey: a.privateKey, now,
      body: { request_id: request.request_id, request_digest: digestMessage(request), active: true, expires_at: now / 1000 + 60 } })
    return previous
  } })
  assert.equal(await source({ session_id: 's' }), now / 1000 + 60)
  await assert.rejects(source({ session_id: 's' }))
  assert.equal(calls, 2)
  const hanging = createSourceVerifier({ ...options, timeoutMs: 20, exchange: () => new Promise(() => {}) })
  await assert.rejects(hanging({ session_id: 's' }))
})
test('S04 IPC lifecycle requires explicit v2 composition and preserves v1', async () => {
  const frame = { schema: 'dubsar.exact-ipc/2', generation: 'g', request_id: 'r', operation: 'lifecycle', params: {} }
  const sink = () => new Writable({ write(_, __, done) { done() } })
  let calls = 0
  const service = { handle: async () => { calls++; return {} } }
  await assert.rejects(serve({ input: Readable.from([encodeFrame(frame)]), output: sink(), service, generation: 'g' }))
  await assert.rejects(serve({ input: Readable.from([encodeFrame({ ...frame, schema: 'dubsar.exact-ipc/1' })]), output: sink(), service, generation: 'g' }))
  assert.equal(calls, 0)
  await serve({ input: Readable.from([encodeFrame(frame)]), output: sink(), service, generation: 'g', protocol: frame.schema })
  assert.equal(calls, 1)
})
