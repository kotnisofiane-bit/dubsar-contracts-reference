import assert from 'node:assert/strict'
import { setupExact } from './exact-action-fixture.mjs'
import { PostgresActionStore } from '../../src/broker/postgres-action-store.mjs'
import { PostgresActionBroker } from '../../src/broker/postgres-action-broker.mjs'
import { assertExactReceipt } from '../../src/exact-action/receipt.mjs'

const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r }); return { promise, resolve } }
async function bounded(promise) {
  let timer
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('DEADLOCK_TEST_BARRIER_TIMEOUT')), 12000)
  })]) } finally { clearTimeout(timer) }
}
const settled = promise => promise.then(value => ({ value }), error => ({ error }))

export async function deadlockReproduction(t, { ownerPool, runtimePool, expectDeadlock }) {
  await t.test(expectDeadlock ? 'DL01 baseline controlled schedule reproduces 40P01'
    : 'DL01 fixed controlled schedule finalizes without deadlock or second effect', async () => {
    await ownerPool.query('TRUNCATE dubsar_broker.broker_approval_usage CASCADE')
    const f = setupExact(), finalReady = deferred(), permitFinal = deferred()
    const commitReady = deferred(), permitCommit = deferred(), errors = []
    let finalPid, claimPid, firstRun, secondRun
    function wrappedPool(pauseCommit) {
      return { async connect() {
        const client = await runtimePool.connect()
        let claimed = false
        return { async query(sql, values) {
          if (sql.includes('claim_action(')) { claimed = true; if (pauseCommit) claimPid = client.processID }
          if (sql.includes('finalize_action(')) finalPid = client.processID
          if (pauseCommit && claimed && sql === 'COMMIT') {
            commitReady.resolve()
            await bounded(permitCommit.promise)
          }
          try { return await client.query(sql, values) } catch (error) {
            errors.push({ stage: sql === 'COMMIT' ? 'COMMIT' : sql.includes('finalize_action(') ? 'finalize' : 'other',
              code: /^[A-Z0-9]{5}$/.test(error.code ?? '') ? error.code : 'OTHER' })
            throw error
          }
        }, release: (...args) => client.release(...args) }
      } }
    }
    const firstStore = new PostgresActionStore({ pool: wrappedPool(false) })
    const first = new PostgresActionBroker({ ...f.brokerOptions, store: {
      claim: input => firstStore.claim(input), listInFlight: () => firstStore.listInFlight(),
      async finalize(input) { finalReady.resolve(); await bounded(permitFinal.promise); return firstStore.finalize(input) },
    } })
    const second = new PostgresActionBroker({ ...f.brokerOptions,
      store: new PostgresActionStore({ pool: wrappedPool(true) }) })
    const requests = [await f.request(), await f.request()]
    let observed = false
    try {
      firstRun = settled(first.submit(requests[0]))
      await bounded(finalReady.promise)
      assert.equal(f.state.executions.length, 1)
      secondRun = settled(second.submit(requests[1]))
      await bounded(commitReady.promise)
      permitFinal.resolve()
      const deadline = Date.now() + 4000
      while (Date.now() < deadline) {
        const row = (await ownerPool.query('SELECT pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE pid=$1',
          [finalPid ?? null])).rows[0]
        if (row?.blockers.includes(claimPid)) { observed = true; break }
        await new Promise(r => setTimeout(r, 10))
      }
      assert.equal(observed, true, 'finalizer must be blocked by the held admission transaction')
      permitCommit.resolve()
      const [a, b] = await bounded(Promise.all([firstRun, secondRun]))
      t.diagnostic(JSON.stringify({ scenario: 'controlled-finalization', expectDeadlock, observed,
        errors, results: [a, b].map(x => x.error?.code ?? x.value?.after_state), executions: f.state.executions.length }))
      if (expectDeadlock) assert.ok(errors.some(e => e.code === '40P01'), 'baseline must exhibit the actual SQL deadlock')
      else {
        assert.deepEqual(errors, [])
        assert.equal(a.error, undefined)
        assertExactReceipt(a.value)
        assert.equal(a.value.after_state, 'SUCCEEDED')
        assert.equal(b.error?.code, 'BROKER_OPERATION_IN_PROGRESS')
      }
      const store = new PostgresActionStore({ pool: runtimePool })
      const resumed = new PostgresActionBroker({ ...f.brokerOptions, store })
      await resumed.recoverInFlight()
      const replay = await resumed.submit(await f.request())
      assertExactReceipt(replay)
      assert.equal(f.state.executions.length, 1)
      assert.equal((await ownerPool.query('SELECT consumed_actions FROM dubsar_broker.broker_approval_usage')).rows[0].consumed_actions, 1)
      assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_broker.broker_receipts')).rows[0].n, 1)
      if (!expectDeadlock) assert.equal(replay.after_state, 'SUCCEEDED')
    } finally {
      permitFinal.resolve(); permitCommit.resolve()
      await bounded(Promise.all([firstRun, secondRun].filter(Boolean)))
    }
  })
}
