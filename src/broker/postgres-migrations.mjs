import { createHash } from 'node:crypto'
import fs from 'node:fs'

const migrationDirectory = new URL('../../migrations/', import.meta.url)
const MIGRATION_LOCK = 2_002_003

export async function applyBrokerMigrations(pool) {
  if (typeof pool?.connect !== 'function') throw new TypeError('BROKER_POSTGRES_POOL_REQUIRED')
  const client = await pool.connect()
  const applied = []
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK])
    await client.query('CREATE SCHEMA IF NOT EXISTS dubsar_broker')
    await client.query(`
      CREATE TABLE IF NOT EXISTS dubsar_broker.schema_migrations (
        version text PRIMARY KEY,
        sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
      )
    `)
    const files = fs.readdirSync(migrationDirectory)
      .filter(name => /^\d{3}_[a-z0-9_]+\.sql$/.test(name))
      .sort()
    for (const file of files) {
      const sql = fs.readFileSync(new URL(file, migrationDirectory), 'utf8')
      const checksum = createHash('sha256').update(sql).digest('hex')
      await client.query('BEGIN')
      try {
        const existing = await client.query(
          'SELECT sha256 FROM dubsar_broker.schema_migrations WHERE version = $1 FOR UPDATE',
          [file],
        )
        if (existing.rowCount === 1) {
          if (existing.rows[0].sha256 !== checksum) throw new Error('BROKER_MIGRATION_CHECKSUM_MISMATCH')
          await client.query('COMMIT')
          continue
        }
        await client.query(sql)
        await client.query(
          'INSERT INTO dubsar_broker.schema_migrations(version, sha256) VALUES ($1, $2)',
          [file, checksum],
        )
        await client.query('COMMIT')
        applied.push(file)
      } catch (error) {
        await client.query('ROLLBACK')
        throw error
      }
    }
    return Object.freeze({ applied: Object.freeze(applied) })
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK])
    } finally {
      client.release()
    }
  }
}
