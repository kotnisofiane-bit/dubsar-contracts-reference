import { deny, failure } from './contracts.mjs'

// All access and administrative mutations serialize on the context epoch first.
// Row values remain stable under this lock; no lower-order write lock is needed.
export class DocumentRegistry {
  constructor({ pool, context, clock }) {
    this.pool = pool; this.context = structuredClone(context); this.clock = clock
    if (typeof pool?.connect !== 'function' || typeof clock?.now !== 'function') throw failure('DOCUMENT_CONFIG_INVALID')
  }
  async transaction(run) {
    let client; let timer; let expired = false
    try {
      client = await Promise.race([
        Promise.resolve().then(() => this.pool.connect()).then(c => { if (expired) { c.release(); throw failure('DOCUMENT_UNAVAILABLE') } return c }),
        new Promise((_, reject) => { timer = setTimeout(() => { expired = true; reject(failure('DOCUMENT_UNAVAILABLE')) }, 1000) }),
      ])
      clearTimeout(timer)
      await client.query('BEGIN')
      await client.query("SET LOCAL statement_timeout='1000ms'")
      await client.query("SET LOCAL lock_timeout='750ms'")
      await client.query("SET LOCAL idle_in_transaction_session_timeout='3000ms'")
      const key = [this.context.tenant_ref, this.context.context_ref]
      const q = (sql, args = []) => client.query(sql, [...key, ...args])
      const epoch = (await q('SELECT policy_epoch FROM dubsar_document_access.contexts WHERE tenant_ref=$1 AND context_ref=$2 FOR SHARE')).rows[0]
      if (!epoch) deny()
      const result = await run(q, String(epoch.policy_epoch))
      await client.query('COMMIT')
      return result
    } catch (e) {
      if (client) await client.query('ROLLBACK').catch(() => {})
      if (e.code === 'DOCUMENT_DENIED') throw e
      throw failure('DOCUMENT_UNAVAILABLE')
    } finally { clearTimeout(timer); if (client) client.release() }
  }
  async current(q, claims) {
    const s = (await q('SELECT * FROM dubsar_document_access.sessions WHERE tenant_ref=$1 AND context_ref=$2 AND session_ref=$3', [claims.session])).rows[0]
    const now = Date.parse(this.clock.now())
    if (!Number.isFinite(now) || !s || s.revoked || s.issuer !== claims.issuer || s.external_subject !== claims.subject
      || Date.parse(s.expires_at) <= now) deny()
    const m = (await q('SELECT * FROM dubsar_document_access.memberships WHERE tenant_ref=$1 AND context_ref=$2 AND issuer=$3 AND external_subject=$4', [claims.issuer, claims.subject])).rows[0]
    if (!m?.enabled || m.active_function !== s.active_function) deny()
    return { subject_ref: m.principal, active_function: m.active_function, expires: Date.parse(s.expires_at) }
  }
  async allowed(q, member, requested) {
    const result = []
    for (const r of requested) {
      const found = (await q(`SELECT r.resource_version FROM dubsar_document_access.resources r
        JOIN dubsar_document_access.corpora c USING(tenant_ref,context_ref,corpus_ref)
        JOIN dubsar_document_access.grants g USING(tenant_ref,context_ref,corpus_ref,document_ref)
        WHERE r.tenant_ref=$1 AND r.context_ref=$2 AND r.corpus_ref=$3 AND r.document_ref=$4
          AND r.enabled AND c.enabled AND g.enabled AND g.principal=$5 AND g.active_function=$6`,
      [r.corpus_ref, r.document_ref, member.subject_ref, member.active_function])).rows[0]
      if (!found) deny()
      result.push({ ...r, resource_version: found.resource_version })
    }
    return result
  }
}
