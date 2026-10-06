import assert from 'node:assert/strict'
import test from 'node:test'
import { EventEmitter } from 'node:events'
import { PostgresExactActionRecords } from '../src/exact-action/postgres-records.mjs'
import { setupExact } from './helpers/exact-action-fixture.mjs'
import { ExactActionGate } from '../src/exact-action/contracts.mjs'
import { PostgresActionStore } from '../src/broker/postgres-action-store.mjs'
import { PostgresActionBroker } from '../src/broker/postgres-action-broker.mjs'

const context = f => ({ tenant_ref: f.binding.tenant_ref, project_ref: f.binding.project_ref, mission: f.binding.mission })
const publication = f => ({ binding: f.binding, prepared: f.prepared, decision: f.decision, presentedDigest: f.decision.display_digest })

test('records require a trusted complete context and bounded wait before connecting', () => {
  const pool = { connect() { assert.fail('must not connect') } }
  assert.throws(() => new PostgresExactActionRecords({ pool }), /CONTEXT_REQUIRED/)
  assert.throws(() => new PostgresExactActionRecords({ pool, context: context(setupExact()), waitMs: 0 }), /WAIT_INVALID/)
})

test('publication rejects cross-mission, stale binding and forged presentation before SQL', async () => {
  for (const mutate of [f => { f.binding.mission.id = 'mis_other' }, f => { f.prepared.binding_digest = `sha256:${'0'.repeat(64)}` },
    f => { f.decision.display_digest = `sha256:${'0'.repeat(64)}` }]) {
    const f = setupExact()
    const records = new PostgresExactActionRecords({ pool: { connect() { assert.fail('must not connect') } }, context: context(f) })
    mutate(f)
    await assert.rejects(records.publish(publication(f)), /BINDING_MISMATCH/)
  }
})

test('late pool checkout after timeout is released without SQL or callback', async () => {
  let resolve, released = 0
  const pool = { connect: () => new Promise(r => { resolve = r }) }
  const records = new PostgresExactActionRecords({ pool, context: context(setupExact()), waitMs: 10 })
  await assert.rejects(records.withCurrent('decision:1', () => assert.fail()), /POOL_TIMEOUT/)
  resolve({ release() { released++ }, query() { assert.fail('late checkout used') } })
  await new Promise(r => setImmediate(r))
  assert.equal(released, 1)
})

test('pool rejection never discloses raw driver details', async () => {
  const records = new PostgresExactActionRecords({ pool: { connect() { throw new Error('sensitive driver detail') } }, context: context(setupExact()) })
  await assert.rejects(records.withCurrent('decision:1', () => assert.fail()), error => error.message === 'EXACT_RECORDS_STORAGE_UNAVAILABLE')
})

test('SQL timeout rolls back and returns the connection without invoking authority callback', async () => {
  const calls = [], releases = []
  const client = { async query(sql) { calls.push(sql); if (sql.startsWith('SELECT subject, documents')) throw { code: '55P03' }; return { rows: [] } },
    release(broken) { releases.push(broken) } }
  const records = new PostgresExactActionRecords({ pool: { connect: async () => client }, context: context(setupExact()) })
  await assert.rejects(records.withCurrent('decision:1', () => assert.fail()), /SQL_TIMEOUT/)
  assert.equal(calls.at(-1), 'ROLLBACK')
  assert.deepEqual(releases, [false])
})

test('failed rollback discards a broken connection', async () => {
  const releases = []
  const client = { async query() { throw new Error('offline') }, release(broken) { releases.push(broken) } }
  const records = new PostgresExactActionRecords({ pool: { connect: async () => client }, context: context(setupExact()) })
  await assert.rejects(records.withCurrent('decision:1', () => assert.fail()), /STORAGE_UNAVAILABLE/)
  assert.deepEqual(releases, [true])
})

function recordingAuthority(f) {
  const client = new EventEmitter(), sqlCalls = []
  client.release = () => {}
  client.query = async sql => {
    sqlCalls.push(sql)
    if (sql.startsWith('SELECT subject, documents')) return { rowCount: 1, rows: [{ subject: f.decision.approver.subject,
      documents: { binding: f.binding, prepared: f.prepared, decision: f.decision, presented_digest: f.decision.display_digest } }] }
    if (sql.includes('SELECT subject, active_function')) return { rowCount: 1, rows: [f.state.record.principal] }
    if (sql.startsWith('SELECT revoked')) return { rowCount: 1, rows: [{ revoked: false }] }
    if (sql.includes('dubsar_broker.claim_action(')) return { rows: [{ claim: { kind: 'claimed' } }] }
    return { rowCount: 0, rows: [] }
  }
  const records = new PostgresExactActionRecords({ pool: { connect: async () => client }, context: context(f) })
  return { client, sqlCalls, records }
}

test('session loss inside gate callback never reaches claim on another connection', async () => {
  const f = setupExact(), db = recordingAuthority(f)
  const gate = new ExactActionGate({ records: db.records, artifacts: { async read(ref) {
    db.client.emit('error', new Error('simulated loss'))
    return f.state.artifacts.get(ref)
  } } })
  const store = new PostgresActionStore({ pool: { connect() { assert.fail('independent claim connection') } } })
  const broker = new PostgresActionBroker({ ...f.brokerOptions, store, exactActionGate: gate })
  await assert.rejects(broker.submit(await f.request()), /STORAGE_UNAVAILABLE/)
  assert.equal(db.sqlCalls.some(sql => sql.includes('claim_action(')), false)
  assert.equal(f.state.executions.length, 0)
  assert.equal(db.sqlCalls.at(-1), 'ROLLBACK')
})

test('Broker refuses a store that would ignore the authority transaction', async () => {
  const f = setupExact(), db = recordingAuthority(f)
  const gate = new ExactActionGate({ records: db.records, artifacts: { read: async ref => f.state.artifacts.get(ref) } })
  const broker = new PostgresActionBroker({ ...f.brokerOptions, exactActionGate: gate })
  await assert.rejects(broker.submit(await f.request()), /ADMISSION_TRANSACTION_REQUIRED/)
  assert.equal(f.store.claims.length, 0)
  assert.equal(f.state.executions.length, 0)
})

test('shared claim has one commit, before execution, and no nested checkout', async () => {
  const f = setupExact(), db = recordingAuthority(f)
  const gate = new ExactActionGate({ records: db.records, artifacts: { read: async ref => f.state.artifacts.get(ref) } })
  const realStore = new PostgresActionStore({ pool: { connect() { assert.fail('independent claim connection') } } })
  const store = { claim: () => assert.fail('legacy claim'),
    claimInTransaction: (input, tx) => realStore.claimInTransaction(input, tx),
    listInFlight: async () => [], finalize: async ({ receipt }) => receipt }
  f.state.onExecute = async () => assert.equal(db.sqlCalls.at(-1), 'COMMIT')
  const broker = new PostgresActionBroker({ ...f.brokerOptions, store, exactActionGate: gate })
  assert.equal((await broker.submit(await f.request())).after_state, 'SUCCEEDED')
  assert.equal(db.sqlCalls.filter(sql => sql.startsWith('BEGIN')).length, 1)
  assert.equal(db.sqlCalls.filter(sql => sql === 'COMMIT').length, 1)
  assert.equal(f.state.executions.length, 1)
})

test('authority transaction handle is one-use and cannot escape the callback', async () => {
  const f = setupExact(), db = recordingAuthority(f)
  let escaped, escapedClient
  await db.records.withCurrent(f.decision.decision_ref, async (_row, tx) => {
    escaped = tx
    await tx.run(async client => { escapedClient = client; await client.query('SELECT 1') })
    await assert.rejects(tx.run(() => assert.fail()), /TRANSACTION_INVALID/)
  })
  await assert.rejects(escaped.run(() => assert.fail()), /TRANSACTION_INVALID/)
  assert.throws(() => escapedClient.query('SELECT 1'), /TRANSACTION_INVALID/)
})
