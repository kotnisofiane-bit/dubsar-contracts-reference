import { canonicalJson } from '../canonical-json.mjs'
import { assertExact, hashExact, same } from './contracts.mjs'

const failure = code => Object.assign(new Error(code), { code })
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !value.includes('\0')

// Trusted internal service API, never a request-JSON authentication adapter.
export class PostgresExactActionRecords {
  #pool
  #context
  #waitMs
  #human
  constructor({ pool, context, waitMs = 3000, humanRegistry = null, requireHuman = false } = {}) {
    if (typeof pool?.connect !== 'function') throw new TypeError('EXACT_RECORDS_POOL_REQUIRED')
    if (!text(context?.tenant_ref) || !text(context?.project_ref)
      || !text(context?.mission?.namespace) || !text(context?.mission?.id)) throw failure('EXACT_RECORDS_CONTEXT_REQUIRED')
    if (!Number.isInteger(waitMs) || waitMs < 1 || waitMs > 60000) throw failure('EXACT_RECORDS_WAIT_INVALID')
    this.#pool = pool
    this.#context = canonicalJson({ tenant_ref: context.tenant_ref, project_ref: context.project_ref, mission: context.mission })
    this.#waitMs = waitMs
    if (requireHuman && (typeof humanRegistry?.checkDecision !== 'function' || typeof humanRegistry?.assertContext !== 'function')) throw failure('HUMAN_REGISTRY_REQUIRED')
    if (requireHuman) humanRegistry.assertContext(JSON.parse(this.#context))
    this.#human = requireHuman ? humanRegistry : null
  }
  assertHumanContext(context, registry) {
    if (!this.#human || this.#human !== registry || canonicalJson(context) !== this.#context) throw failure('HUMAN_CONTEXT_MISMATCH')
  }

  async setPrincipal({ subject, active_function, eligible }) {
    if (!text(subject) || !text(active_function) || typeof eligible !== 'boolean') throw failure('EXACT_RECORDS_PRINCIPAL_INVALID')
    return this.#transaction(async query => {
      // UPDATE conflicts with the SHARE lock held by every current reader.
      await query(`INSERT INTO dubsar_exact_records.authorities(context_key, subject, active_function, eligible)
        VALUES ($1, $2, $3, $4) ON CONFLICT (context_key, subject)
        DO UPDATE SET active_function = EXCLUDED.active_function, eligible = EXCLUDED.eligible`,
      [this.#context, subject, active_function, eligible])
    })
  }

  async publish({ binding, prepared, decision, presentedDigest }) {
    if (this.#human) throw failure('HUMAN_ATOMIC_PUBLICATION_REQUIRED')
    assertExact('binding', binding); assertExact('prepared', prepared); assertExact('decision', decision)
    same(this.#context, canonicalJson({ tenant_ref: binding.tenant_ref, project_ref: binding.project_ref, mission: binding.mission }))
    same(prepared.binding_digest, hashExact('binding', binding))
    same(decision.binding_digest, prepared.binding_digest)
    same(decision.prepared_digest, hashExact('prepared', prepared))
    same(decision.display_digest, prepared.display.digest)
    same(presentedDigest, decision.display_digest)
    ;({ binding, prepared, decision, presentedDigest } = structuredClone({ binding, prepared, decision, presentedDigest }))
    return this.#transaction(query => this.publishUsing(query, { binding, prepared, decision, presentedDigest }))
  }

  // Internal composition only: query must belong to the caller's active transaction.
  async publishUsing(query, { binding, prepared, decision, presentedDigest }) {
    // Validate and snapshot before acquiring a connection or awaiting anything.
    const documents = structuredClone({ binding, prepared, decision, presented_digest: presentedDigest })
    binding = documents.binding; prepared = documents.prepared; decision = documents.decision
    assertExact('binding', binding); assertExact('prepared', prepared); assertExact('decision', decision)
    same(this.#context, canonicalJson({ tenant_ref: binding.tenant_ref, project_ref: binding.project_ref, mission: binding.mission }))
    same(prepared.binding_digest, hashExact('binding', binding))
    same(decision.binding_digest, prepared.binding_digest)
    same(decision.prepared_digest, hashExact('prepared', prepared))
    same(decision.display_digest, prepared.display.digest)
    same(presentedDigest, decision.display_digest)
    const encoded = canonicalJson(documents)
    {
      await this.#principal(query, decision.approver.subject)
      await query(`INSERT INTO dubsar_exact_records.decisions(context_key, decision_ref, subject, documents)
        VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (context_key, decision_ref) DO NOTHING`,
      [this.#context, decision.decision_ref, decision.approver.subject, encoded])
      const row = await this.#decision(query, decision.decision_ref)
      if (canonicalJson(row.documents) !== encoded) throw failure('EXACT_RECORDS_IMMUTABLE_CONFLICT')
      await query(`INSERT INTO dubsar_exact_records.revocations(context_key, decision_ref, revoked)
        VALUES ($1, $2, false) ON CONFLICT (context_key, decision_ref) DO NOTHING`, [this.#context, decision.decision_ref])
    }
  }

  async humanTransaction(action) {
    if (!this.#human || typeof action !== 'function') throw failure('HUMAN_REGISTRY_REQUIRED')
    return this.#transaction(action)
  }

  async revoke(decisionRef) {
    this.#ref(decisionRef)
    return this.#transaction(async query => {
      const row = await this.#decision(query, decisionRef)
      await this.#principal(query, row.subject)
      // Monotone: neither this API nor the runtime DB role can undo revocation.
      await query(`UPDATE dubsar_exact_records.revocations SET revoked = true
        WHERE context_key = $1 AND decision_ref = $2`, [this.#context, decisionRef])
    })
  }

  async withCurrent(decisionRef, callback) {
    this.#ref(decisionRef)
    if (typeof callback !== 'function') throw failure('EXACT_RECORDS_CALLBACK_REQUIRED')
    return this.#transaction(async (query, client) => {
      const row = await this.#decision(query, decisionRef)
      if (this.#human) await this.#human.checkDecision(query, decisionRef, row.subject)
      const principal = await this.#principal(query, row.subject)
      const state = await query(`SELECT revoked FROM dubsar_exact_records.revocations
        WHERE context_key = $1 AND decision_ref = $2 FOR SHARE`, [this.#context, decisionRef])
      if (state.rowCount !== 1) throw failure('EXACT_RECORDS_NOT_FOUND')
      const { binding, prepared, decision, presented_digest } = row.documents
      let active = true, used = false
      const transaction = Object.freeze({ async run(operation) {
        if (!active || used || typeof operation !== 'function') throw failure('EXACT_RECORDS_TRANSACTION_INVALID')
        used = true
        return await operation(Object.freeze({ query(sql, values) {
          if (!active) throw failure('EXACT_RECORDS_TRANSACTION_INVALID')
          return client.query(sql, values)
        } }))
      } })
      try {
        return await callback(structuredClone({ binding, prepared, decision, revoked: state.rows[0].revoked,
          principal: { ...principal, presented_digest } }), transaction)
      } finally { active = false }
    })
  }

  #ref(ref) { if (!text(ref)) throw failure('EXACT_RECORDS_REFERENCE_INVALID') }
  async #decision(query, ref) {
    const result = await query(`SELECT subject, documents FROM dubsar_exact_records.decisions
      WHERE context_key = $1 AND decision_ref = $2`, [this.#context, ref])
    if (result.rowCount !== 1) throw failure('EXACT_RECORDS_NOT_FOUND')
    return result.rows[0]
  }
  async #principal(query, subject) {
    const result = await query(`SELECT subject, active_function, eligible FROM dubsar_exact_records.authorities
      WHERE context_key = $1 AND subject = $2 FOR SHARE`, [this.#context, subject])
    if (result.rowCount !== 1) throw failure('EXACT_RECORDS_PRINCIPAL_NOT_FOUND')
    return result.rows[0]
  }

  async #connect() {
    // Do not leak a late pool checkout after the caller has timed out.
    return new Promise((resolve, reject) => {
      let expired = false
      const timer = setTimeout(() => { expired = true; reject(failure('EXACT_RECORDS_POOL_TIMEOUT')) }, this.#waitMs)
      Promise.resolve().then(() => this.#pool.connect()).then(client => {
        if (expired) client.release()
        else { clearTimeout(timer); resolve(client) }
      }, () => { clearTimeout(timer); if (!expired) reject(failure('EXACT_RECORDS_STORAGE_UNAVAILABLE')) })
    })
  }

  async #transaction(action) {
    const client = await this.#connect()
    let broken = false, active = true, released = false, timer
    let rejectConnection
    const connectionLost = new Promise((_, reject) => { rejectConnection = reject })
    const onError = () => {
      broken = true; active = false
      rejectConnection(failure('EXACT_RECORDS_STORAGE_UNAVAILABLE'))
    }
    const onEnd = () => {
      client.removeListener?.('error', onError)
      if (active) onError()
    }
    client.on?.('error', onError)
    client.once?.('end', onEnd)
    const sharedClient = Object.freeze({ async query(sql, values) {
      if (broken || !active) throw failure('EXACT_RECORDS_STORAGE_UNAVAILABLE')
      return client.query(sql, values)
    } })
    const query = async (sql, values) => {
      if (broken || !active) throw failure('EXACT_RECORDS_STORAGE_UNAVAILABLE')
      try { return await client.query(sql, values) } catch (error) {
        throw failure(['55P03', '57014'].includes(error?.code) ? 'EXACT_RECORDS_SQL_TIMEOUT' : 'EXACT_RECORDS_STORAGE_UNAVAILABLE')
      }
    }
    try {
      return await Promise.race([(async () => {
        await query('BEGIN ISOLATION LEVEL READ COMMITTED')
        await query("SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $1, true), set_config('idle_in_transaction_session_timeout', $2, true)", [`${this.#waitMs}ms`, `${this.#waitMs + 2000}ms`])
        const result = await action(query, sharedClient)
        await query('COMMIT')
        return result
      })(), new Promise((_, reject) => {
        timer = setTimeout(() => {
          active = false; broken = true; released = true
          // Destroy, never recycle a connection whose transaction is still running.
          // Closing the socket rolls back SQL; guarded ports reject late continuations.
          client.release(true)
          reject(failure('EXACT_RECORDS_TRANSACTION_TIMEOUT'))
        // Leave SQL timeouts their existing error semantics; still bound JS waits.
        }, this.#waitMs + 1000)
      }), connectionLost])
    } catch (error) {
      if (!released) { try { await client.query('ROLLBACK') } catch { broken = true } }
      throw error
    } finally {
      clearTimeout(timer); active = false
      // Destruction is asynchronous: retain the error handler until end.
      if (!broken) {
        client.removeListener?.('error', onError)
        client.removeListener?.('end', onEnd)
      }
      if (!released) client.release(broken)
    }
  }
}
