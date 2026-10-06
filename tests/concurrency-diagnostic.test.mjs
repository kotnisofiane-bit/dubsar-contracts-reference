import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { diagnosticPool, diagnosticOutcome } from './helpers/concurrency-diagnostic.mjs'

test('diagnostic observer preserves SQL errors and client lifecycle without logging values', async () => {
  const failure = Object.assign(new Error('private SQL details'), { code: '40P01' })
  const client = new EventEmitter()
  let released
  client.query = async (sql, values) => {
    assert.deepEqual(values, ['private-value'])
    throw failure
  }
  client.release = value => { released = value }
  const events = []
  const wrapped = await diagnosticPool({ connect: async () => client }, events, 'broker').connect()
  const listener = () => {}
  wrapped.on('error', listener)
  assert.equal(client.listenerCount('error'), 1)
  wrapped.removeListener('error', listener)
  assert.equal(client.listenerCount('error'), 0)
  let ended = 0
  wrapped.once('end', () => { ended++ })
  client.emit('end'); client.emit('end')
  assert.equal(ended, 1)
  await assert.rejects(wrapped.query('select claim_action($1)', ['private-value']), error => error === failure)
  wrapped.release(true)
  assert.equal(released, true)
  assert.deepEqual(events.map(x => [x.stage, x.event, x.sqlstate]), [
    ['claim', 'start', undefined], ['claim', 'error', '40P01'],
  ])
  assert.equal(JSON.stringify(events).includes('private'), false)
  assert.deepEqual(diagnosticOutcome({ status: 'rejected', reason: failure }), { status: 'rejected', code: 'UNCLASSIFIED' })
})
