import fs from 'node:fs'
import { createHash } from 'node:crypto'

export function stateProjectionMigrationSql() {
  return fs.readFileSync(new URL('../../migrations/009_state_projection.sql', import.meta.url), 'utf8')
}

export async function applyStateProjectionMigration(pool) {
  const sql = stateProjectionMigrationSql()
  const checksum = createHash('sha256').update(sql).digest('hex')
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    await client.query('SELECT pg_advisory_xact_lock($1)', [2026009])
    const existing = await client.query("SELECT to_regclass('dubsar_context.state_policy_events') AS present")
    const applied = !existing.rows[0].present
    if (applied) await client.query(sql)
    await client.query('COMMIT')
    return { applied, checksum, version: '009_state_projection.sql' }
  } catch (error) {
    try { await client.query('ROLLBACK') } catch { /* preserve failure */ }
    throw error
  } finally { client.release() }
}
