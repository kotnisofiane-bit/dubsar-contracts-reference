import assert from 'node:assert/strict'
import test from 'node:test'
import pg from 'pg'
import { applyBrokerMigrations } from '../../../src/broker/postgres-migrations.mjs'
import { applyOperationalContextMigration } from '../../../src/operational-context/migrate.mjs'
import { postgresUrl } from '../helpers/postgres.mjs'

const { Pool } = pg

async function withDisposableDatabase(name, fn) {
  if (!/^[a-z0-9_]+$/.test(name)) throw new Error('invalid disposable database name')
  const bootstrap = new Pool({ connectionString: postgresUrl(), max: 1 })
  const url = new URL(postgresUrl())
  url.pathname = `/${name}`
  const isolated = new Pool({ connectionString: url.toString(), max: 4, statement_timeout: 5000 })
  try {
    await bootstrap.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${name}' AND pid <> pg_backend_pid()`)
    await bootstrap.query(`DROP DATABASE IF EXISTS ${name}`)
    await bootstrap.query(`CREATE DATABASE ${name}`)
    await fn(isolated)
  } finally {
    await isolated.end()
    try {
      await bootstrap.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${name}' AND pid <> pg_backend_pid()`)
      await bootstrap.query(`DROP DATABASE IF EXISTS ${name}`)
    } finally {
      await bootstrap.end()
    }
  }
}

async function ensureBrokerRoles(pool) {
  for (const role of ['dubsar_broker_runtime', 'dubsar_exact_records_runtime', 'dubsar_artifact_runtime']) {
    await pool.query(`
      DO $role$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN
          CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
        END IF;
      END
      $role$
    `)
  }
}

async function assertContextReady(pool) {
  const rel = await pool.query("SELECT to_regclass('dubsar_context.observations') AS observations")
  assert.ok(rel.rows[0].observations)
  const count = await pool.query('SELECT count(*)::int AS n FROM dubsar_context.observations')
  assert.equal(count.rows[0].n, 0)
}

test('AC12 Broker then OC migrator is additive and non-destructive', async () => {
  await withDisposableDatabase('oc_mig_broker_first', async pool => {
    await ensureBrokerRoles(pool)
    const broker = await applyBrokerMigrations(pool)
    assert.ok(broker.applied.includes('008_operational_context.sql'))
    await assertContextReady(pool)
    const first = await applyOperationalContextMigration(pool)
    assert.equal(first.applied, false)
    const second = await applyOperationalContextMigration(pool)
    assert.equal(second.applied, false)
    await assertContextReady(pool)
    const versions = (await pool.query(
      "SELECT version FROM dubsar_broker.schema_migrations WHERE version='008_operational_context.sql'",
    )).rows
    assert.equal(versions.length, 1)
  })
})

test('AC12 OC migrator then Broker migrations does not recreate or false-succeed', async () => {
  await withDisposableDatabase('oc_mig_oc_first', async pool => {
    await ensureBrokerRoles(pool)
    const first = await applyOperationalContextMigration(pool)
    assert.equal(first.applied, true)
    await assertContextReady(pool)
    const broker = await applyBrokerMigrations(pool)
    assert.ok(broker.applied.includes('008_operational_context.sql'))
    await assertContextReady(pool)
    const again = await applyBrokerMigrations(pool)
    assert.deepEqual(again.applied, [])
    const ocAgain = await applyOperationalContextMigration(pool)
    assert.equal(ocAgain.applied, false)
    const dropped = await pool.query("SELECT to_regclass('dubsar_context.observations') AS observations")
    assert.ok(dropped.rows[0].observations)
  })
})
