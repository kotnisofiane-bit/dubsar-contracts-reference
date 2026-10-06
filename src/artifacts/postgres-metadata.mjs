import { canonicalJson } from '../canonical-json.mjs'
import { artifactError, scopeKey } from './contracts.mjs'

export class PostgresArtifactMetadata {
  #pool
  scopeKey
  constructor({ pool, context }) {
    if (typeof pool?.connect !== 'function') throw artifactError('ARTIFACT_POOL_REQUIRED')
    this.#pool = pool; this.scopeKey = scopeKey(context)
  }
  async #connect() {
    return new Promise((resolve, reject) => {
      let expired = false
      const timer = setTimeout(() => { expired = true; reject(artifactError('ARTIFACT_POOL_TIMEOUT')) }, 3000)
      Promise.resolve().then(() => this.#pool.connect()).then(client => {
        if (expired) client.release()
        else { clearTimeout(timer); resolve(client) }
      }, () => { clearTimeout(timer); if (!expired) reject(artifactError('ARTIFACT_STORAGE_UNAVAILABLE')) })
    })
  }
  async #transaction(operation) {
    const client = await this.#connect()
    let broken = false
    const onError = () => { broken = true }
    client.on?.('error', onError)
    const query = async (sql, values) => {
      if (broken) throw artifactError('ARTIFACT_STORAGE_UNAVAILABLE')
      return client.query(sql, values)
    }
    try {
      await query('BEGIN ISOLATION LEVEL READ COMMITTED')
      await query("SET LOCAL lock_timeout = '3s'")
      await query("SET LOCAL statement_timeout = '3s'")
      await query("SET LOCAL idle_in_transaction_session_timeout = '0'")
      const result = await operation(query)
      await query('COMMIT')
      return result
    } catch (error) {
      try { await client.query('ROLLBACK') } catch { broken = true }
      if (error.code?.startsWith('ARTIFACT_')) throw error
      throw artifactError('ARTIFACT_STORAGE_UNAVAILABLE')
    } finally { client.removeListener?.('error', onError); client.release(broken) }
  }
  async reserve(idempotencyKey, request, reference, keyRef) {
    return this.#transaction(async query => {
      await query(`INSERT INTO dubsar_artifacts.objects(context_key, idempotency_key, artifact_id, request, reference, key_ref, state)
        VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, 'STAGING') ON CONFLICT (context_key, idempotency_key) DO NOTHING`,
      [this.scopeKey, idempotencyKey, reference.artifact_id, canonicalJson(request), canonicalJson(reference), keyRef])
      const result = await query(`SELECT artifact_id, request FROM dubsar_artifacts.objects
        WHERE context_key = $1 AND idempotency_key = $2`, [this.scopeKey, idempotencyKey])
      if (result.rowCount !== 1 || canonicalJson(result.rows[0].request) !== canonicalJson(request)) throw artifactError('ARTIFACT_IMMUTABLE_CONFLICT')
      return result.rows[0].artifact_id
    })
  }
  async withLocked(id, operation) {
    return this.#transaction(async query => {
      const result = await query(`SELECT artifact_id, reference, key_ref, state FROM dubsar_artifacts.objects
        WHERE context_key = $1 AND artifact_id = $2 FOR UPDATE`, [this.scopeKey, id])
      if (result.rowCount !== 1) throw artifactError('ARTIFACT_NOT_FOUND')
      return operation(structuredClone(result.rows[0]), async (state, reference) => {
        await query(`UPDATE dubsar_artifacts.objects SET state = $3, reference = $4::jsonb
          WHERE context_key = $1 AND artifact_id = $2`, [this.scopeKey, id, state, canonicalJson(reference)])
      })
    })
  }
  async get(id) {
    return this.#transaction(async query => {
      const result = await query(`SELECT artifact_id, reference, key_ref, state FROM dubsar_artifacts.objects
        WHERE context_key = $1 AND artifact_id = $2`, [this.scopeKey, id])
      if (result.rowCount !== 1) throw artifactError('ARTIFACT_NOT_FOUND')
      return result.rows[0]
    })
  }
  async knownLocation(location) {
    return this.#transaction(async query => {
      const result = await query(`SELECT artifact_id FROM dubsar_artifacts.objects
        WHERE context_key = $1 AND reference->>'location' = $2`, [this.scopeKey, location])
      return result.rowCount > 0
    })
  }
}
