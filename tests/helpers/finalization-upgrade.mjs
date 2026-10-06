import assert from 'node:assert/strict'
import fs from 'node:fs'
import { applyBrokerMigrations } from '../../src/broker/postgres-migrations.mjs'
import { PostgresActionStore } from '../../src/broker/postgres-action-store.mjs'
import { PostgresActionBroker } from '../../src/broker/postgres-action-broker.mjs'
import { setupExact } from './exact-action-fixture.mjs'
const version = '005_broker_finalization_lock_order.sql'
const original = fs.readFileSync(new URL('../../migrations/001_durable_action_broker.sql', import.meta.url), 'utf8')
const start = original.indexOf('CREATE OR REPLACE FUNCTION dubsar_broker.finalize_action(')
const oldFunction = original.slice(start, original.indexOf('$finalize$;', start) + '$finalize$;'.length)
const definition = pool => pool.query("SELECT pg_get_functiondef(oid) AS def, proowner, proacl::text, prosecdef, proconfig FROM pg_proc WHERE pronamespace='dubsar_broker'::regnamespace AND proname='finalize_action'").then(r => r.rows[0])
const evidence = async pool => {
  const result = {}
  for (const name of ['broker_actions', 'broker_receipts', 'broker_consumed_jtis', 'broker_idempotency', 'broker_approval_usage', 'broker_action_transitions']) {
    result[name] = (await pool.query('SELECT to_jsonb(t) AS row FROM dubsar_broker.' + name + ' t ORDER BY to_jsonb(t)::text')).rows
  }
  return result
}

export async function finalizationUpgradeTests(t, { ownerPool, runtimePool }) {
  await t.test('DL02 upgrade populated 001-004, rollback failed 005, preserve records and privileges, rerun idempotently', async () => {
    await ownerPool.query('TRUNCATE dubsar_broker.broker_approval_usage CASCADE')
    // Disposable fixture restoration to historical state; migrations on disk are never edited.
    await ownerPool.query(oldFunction)
    await ownerPool.query('DELETE FROM dubsar_broker.schema_migrations WHERE version=$1', [version])
    const f = setupExact(), store = new PostgresActionStore({ pool: runtimePool })
    try {
      const broker = new PostgresActionBroker({ ...f.brokerOptions, store })
      const receipt = await broker.submit(await f.request())
      const before = await evidence(ownerPool), old = await definition(ownerPool)
      const historical = (await ownerPool.query('SELECT version,sha256 FROM dubsar_broker.schema_migrations ORDER BY version')).rows
      // Later additive migrations remain installed in this disposable database.
      // The historical assertion still requires exactly the original 001-004.
      assert.deepEqual(historical.filter(row => row.version < version).map(row => row.version), [
        '001_durable_action_broker.sql', '002_exact_action_records.sql',
        '003_artifact_store.sql', '004_human_identity.sql',
      ])
      let injected = false
      const failingPool = { async connect() {
        const client = await ownerPool.connect()
        return { async query(sql, values) {
          const result = await client.query(sql, values)
          if (sql.includes('Match claim_action: idempotency before action')) {
            injected = true
            throw new Error('INJECTED_MIGRATION_FAILURE_AFTER_DDL')
          }
          return result
        }, release: (...args) => client.release(...args) }
      } }
      await assert.rejects(applyBrokerMigrations(failingPool), /INJECTED_MIGRATION_FAILURE_AFTER_DDL/)
      assert.equal(injected, true)
      assert.deepEqual(await definition(ownerPool), old)
      assert.deepEqual(await evidence(ownerPool), before)
      assert.deepEqual((await ownerPool.query('SELECT version,sha256 FROM dubsar_broker.schema_migrations ORDER BY version')).rows, historical)
      assert.deepEqual((await applyBrokerMigrations(ownerPool)).applied, [version])
      const upgraded = await definition(ownerPool)
      assert.notEqual(upgraded.def, old.def)
      assert.deepEqual({ ...upgraded, def: null }, { ...old, def: null })
      assert.deepEqual(await evidence(ownerPool), before)
      assert.deepEqual((await ownerPool.query('SELECT version,sha256 FROM dubsar_broker.schema_migrations WHERE version<>$1 ORDER BY version', [version])).rows, historical)
      assert.deepEqual((await applyBrokerMigrations(ownerPool)).applied, [])
      assert.deepEqual(await broker.submit(await f.request()), receipt)
      assert.equal(f.state.executions.length, 1)
    } finally {
      await applyBrokerMigrations(ownerPool)
    }
  })

  await t.test('DL03 concurrent finalizers return one receipt and missing idempotency rolls back atomically', async () => {
    await ownerPool.query('TRUNCATE dubsar_broker.broker_approval_usage CASCADE')
    const f = setupExact(), store = new PostgresActionStore({ pool: runtimePool })
    let input
    const broker = new PostgresActionBroker({ ...f.brokerOptions, store: {
      claim: x => store.claim(x), listInFlight: () => store.listInFlight(),
      async finalize(x) { input = x; throw Object.assign(new Error('fixture interruption'), { code: 'BROKER_STORAGE_UNAVAILABLE' }) },
    } })
    await assert.rejects(broker.submit(await f.request()), e => e.code === 'BROKER_FINALIZATION_UNCERTAIN')
    const idempotency = (await ownerPool.query('SELECT to_jsonb(i) AS row FROM dubsar_broker.broker_idempotency i')).rows[0].row
    await ownerPool.query('DELETE FROM dubsar_broker.broker_idempotency')
    const missing = await evidence(ownerPool)
    await assert.rejects(store.finalize(input), e => e.code === 'BROKER_TRANSITION_FORBIDDEN')
    assert.deepEqual(await evidence(ownerPool), missing)
    await ownerPool.query('INSERT INTO dubsar_broker.broker_idempotency SELECT * FROM jsonb_populate_record(NULL::dubsar_broker.broker_idempotency,$1::jsonb)', [JSON.stringify(idempotency)])
    const coherent = await evidence(ownerPool)
    let corrupted = false
    const incoherentPool = { async connect() {
      const client = await ownerPool.connect()
      return { async query(sql, values) {
        if (sql.includes('dubsar_broker.finalize_action(')) {
          // In this disposable transaction only, the deferred FK allows us to
          // present a completed lookup with a missing receipt to the real function.
          await client.query("UPDATE dubsar_broker.broker_idempotency SET status='completed', receipt_id='receipt_missing_fixture'")
          await client.query('SET LOCAL ROLE dubsar_broker_runtime')
          corrupted = true
        }
        return client.query(sql, values)
      }, release: (...args) => client.release(...args) }
    } }
    await assert.rejects(new PostgresActionStore({ pool: incoherentPool }).finalize(input), e => e.code === 'BROKER_TRANSITION_FORBIDDEN')
    assert.equal(corrupted, true)
    assert.deepEqual(await evidence(ownerPool), coherent, 'incoherent fixture and partial finalization both roll back')
    const other = new PostgresActionStore({ pool: runtimePool })
    const receipts = await Promise.all([store.finalize(input), other.finalize(input)])
    assert.deepEqual(receipts[0], receipts[1])
    assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_broker.broker_receipts')).rows[0].n, 1)
    assert.equal(f.state.executions.length, 1)
    // Preserve preexisting completed-action replay semantics even if owner corrupts its lookup row.
    await ownerPool.query('DELETE FROM dubsar_broker.broker_idempotency')
    assert.deepEqual(await store.finalize(input), receipts[0])
    assert.equal(f.state.executions.length, 1)
  })
}
