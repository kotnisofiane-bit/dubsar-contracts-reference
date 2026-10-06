import { canonicalJson } from '../canonical-json.mjs'
import { closed, denied, text } from './proof.mjs'
import { digestMessage, verifyMessage, signMessage } from './lifecycle-wire.mjs'

export class PortalSessionLifecycle {
  async connect() {
    return new Promise((resolve, reject) => {
      let expired = false
      const timer = setTimeout(() => { expired = true; reject(denied('HUMAN_STORAGE_UNAVAILABLE')) }, 1000)
      Promise.resolve().then(() => this.pool.connect()).then(client => {
        if (expired) client.release(); else { clearTimeout(timer); resolve(client) }
      }, () => { clearTimeout(timer); reject(denied('HUMAN_STORAGE_UNAVAILABLE')) })
    })
  }
  constructor({ pool, context, humanIssuer, commandVerifier, replySigner, verifySource, clock }) {
    this.pool = pool; this.context = canonicalJson(context); this.humanIssuer = text(humanIssuer)
    this.commandVerifier = commandVerifier; this.replySigner = replySigner
    this.verifySource = verifySource; this.clock = clock
    if (typeof pool?.connect !== 'function' || typeof verifySource !== 'function' || typeof clock?.now !== 'function')
      throw denied('HUMAN_LIFECYCLE_CONFIG_INVALID')
  }
  async handle(envelope) {
    const now = () => Date.parse(this.clock.now())
    const command = verifyMessage(envelope, { ...this.commandVerifier, operations: ['register', 'revoke'], now: now() })
    const b = command.body
    closed(b, command.operation === 'register'
      ? ['context', 'human_issuer', 'subject', 'parent_id', 'session_id', 'expires_at']
      : ['context', 'human_issuer', 'subject', 'parent_id'])
    if (canonicalJson(b.context) !== this.context || b.human_issuer !== this.humanIssuer) throw denied('HUMAN_CONTEXT_MISMATCH')
    text(b.subject); text(b.parent_id)
    if (command.operation === 'register') {
      text(b.session_id)
      if (!Number.isSafeInteger(b.expires_at) || b.expires_at * 1000 <= now() || b.expires_at * 1000 > now() + 300000)
        throw denied('HUMAN_SESSION_DENIED')
    }
    const client = await this.connect()
    let broken = false
    try {
      await client.query('BEGIN')
      await client.query("SET LOCAL lock_timeout='1500ms'; SET LOCAL statement_timeout='2000ms'; SET LOCAL idle_in_transaction_session_timeout='3000ms'")
      // Serialize request IDs before parent locks, including conflicting replays.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [canonicalJson([this.context, command.issuer, command.request_id])])
      const previous = (await client.query('SELECT * FROM dubsar_human.lifecycle_requests WHERE context_key=$1 AND issuer=$2 AND request_id=$3',
        [this.context, command.issuer, command.request_id])).rows[0]
      let result
      if (previous) {
        if (previous.digest !== digestMessage(envelope)) throw denied('HUMAN_LIFECYCLE_CONFLICT')
        result = previous.result
      } else {
        // A revoke may precede registration: persist its tombstone immediately.
        await client.query(`INSERT INTO dubsar_human.portal_parents(context_key,issuer,parent_id,external_subject,revoked)
          VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, [this.context, b.human_issuer, b.parent_id, b.subject, command.operation === 'revoke'])
        const parent = (await client.query('SELECT * FROM dubsar_human.portal_parents WHERE context_key=$1 AND issuer=$2 AND parent_id=$3 FOR UPDATE',
          [this.context, b.human_issuer, b.parent_id])).rows[0]
        if (parent.external_subject !== b.subject) throw denied('HUMAN_SESSION_CONFLICT')
        if (command.operation === 'revoke') {
          await client.query('UPDATE dubsar_human.portal_parents SET revoked=true WHERE context_key=$1 AND issuer=$2 AND parent_id=$3', [this.context, b.human_issuer, b.parent_id])
          result = { parent_id: b.parent_id, revoked: true }
        } else {
          if (parent.revoked) throw denied('HUMAN_SESSION_DENIED')
          const sourceExpiry = await this.verifySource({ context: b.context, human_issuer: b.human_issuer, subject: b.subject,
            parent_id: b.parent_id, session_id: b.session_id, purpose: 'register' })
          if (b.expires_at > sourceExpiry || b.expires_at * 1000 <= now()) throw denied('HUMAN_SESSION_DENIED')
          await client.query(`INSERT INTO dubsar_human.portal_children(context_key,session_id,issuer,parent_id,external_subject,expires_at)
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, [this.context, b.session_id, b.human_issuer, b.parent_id, b.subject, new Date(b.expires_at * 1000).toISOString()])
          const child = (await client.query('SELECT * FROM dubsar_human.portal_children WHERE context_key=$1 AND session_id=$2', [this.context, b.session_id])).rows[0]
          if (child.issuer !== b.human_issuer || child.parent_id !== b.parent_id || child.external_subject !== b.subject
            || Date.parse(child.expires_at) !== b.expires_at * 1000) throw denied('HUMAN_SESSION_CONFLICT')
          result = { parent_id: b.parent_id, session_id: b.session_id, expires_at: b.expires_at, revoked: false }
        }
        await client.query('INSERT INTO dubsar_human.lifecycle_requests(context_key,issuer,request_id,digest,result) VALUES($1,$2,$3,$4,$5::jsonb)',
          [this.context, command.issuer, command.request_id, digestMessage(envelope), canonicalJson(result)])
      }
      await client.query('COMMIT')
      return signMessage({ ...this.replySigner, operation: 'result', now: now(), body: {
        request_id: command.request_id, request_digest: digestMessage(envelope), result } })
    } catch (error) { try { await client.query('ROLLBACK') } catch { broken = true }; throw error }
    finally { client.release(broken) }
  }
  async check(query, sessionId, claims = null, purpose = 'admit') {
    const child = (await query('SELECT * FROM dubsar_human.portal_children WHERE context_key=$1 AND session_id=$2', [this.context, sessionId])).rows[0]
    if (!child || child.issuer !== this.humanIssuer) throw denied('HUMAN_PARENT_REQUIRED')
    const parent = (await query('SELECT * FROM dubsar_human.portal_parents WHERE context_key=$1 AND issuer=$2 AND parent_id=$3 FOR SHARE',
      [this.context, child.issuer, child.parent_id])).rows[0]
    if (!parent || parent.revoked || parent.external_subject !== child.external_subject
      || (claims && (claims.issuer !== child.issuer || claims.subject !== child.external_subject || claims.expires_at * 1000 !== Date.parse(child.expires_at))))
      throw denied('HUMAN_SESSION_DENIED')
    const expiry = await this.verifySource({ context: JSON.parse(this.context), human_issuer: child.issuer,
      subject: child.external_subject, parent_id: child.parent_id, session_id: sessionId, purpose })
    if (Date.parse(child.expires_at) > expiry * 1000 || Date.parse(child.expires_at) <= Date.parse(this.clock.now())) throw denied('HUMAN_SESSION_DENIED')
  }
}
