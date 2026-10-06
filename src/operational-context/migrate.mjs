import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { ocError } from './errors.mjs'
import { applyStateProjectionMigration } from './state-migrate.mjs'

const FILE = '008_operational_context.sql'
const LOCK = 2_026_008
const sqlUrl = new URL('../../migrations/008_operational_context.sql', import.meta.url)

export function operationalContextMigrationSql() {
  return fs.readFileSync(sqlUrl, 'utf8')
}

export function operationalContextMigrationChecksum() {
  return createHash('sha256').update(operationalContextMigrationSql()).digest('hex')
}

async function schemaPresence(client) {
  const result = await client.query(`
    SELECT
      to_regclass('dubsar_context.observations') AS observations,
      to_regclass('dubsar_context.mappings') AS mappings,
      to_regclass('dubsar_context.rules') AS rules,
      to_regclass('dubsar_context.associations') AS associations,
      to_regclass('dubsar_context.resources') AS resources
  `)
  const present = Object.values(result.rows[0]).filter(value => value !== null).length
  if (present === 0) return 'absent'
  if (present === 5) return 'ready'
  return 'incomplete'
}

export async function applyOperationalContextMigration(pool) {
  const base = await applyBaseMigration(pool)
  const stateProjection = await applyStateProjectionMigration(pool)
  return { ...base, state_projection: stateProjection }
}

async function applyBaseMigration(pool) {
  if (typeof pool?.connect !== 'function') throw ocError('OC_UNAVAILABLE', 'PostgreSQL pool is required')
  const sql = operationalContextMigrationSql()
  const checksum = operationalContextMigrationChecksum()
  const client = await pool.connect()
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK])
    await client.query('BEGIN')
    const state = await schemaPresence(client)
    if (state === 'ready') {
      await client.query('COMMIT')
      return Object.freeze({ applied: false, checksum, version: FILE })
    }
    await client.query(sql)
    const after = await schemaPresence(client)
    if (after !== 'ready') {
      throw ocError('OC_UNAVAILABLE', 'operational context schema incomplete after migration')
    }
    await client.query('COMMIT')
    return Object.freeze({ applied: true, checksum, version: FILE })
  } catch (error) {
    try { await client.query('ROLLBACK') } catch { /* already failed */ }
    throw error
  } finally {
    try { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]) } finally { client.release() }
  }
}
