import { canonicalJson } from '../canonical-json.mjs'
import { denied, text } from './proof.mjs'

export class HumanRegistry {
  #context; #clock; #environment; #portal
  constructor({ context, clock, environment, portalLifecycle = null }) {
    this.#portal = portalLifecycle
    if (portalLifecycle && (typeof portalLifecycle.check !== 'function' || portalLifecycle.context !== canonicalJson(context))) throw denied('HUMAN_CONTEXT_MISMATCH')
    this.#environment = text(environment)
    this.#context = canonicalJson(context); this.#clock = clock
    if (typeof clock?.now !== 'function') throw denied('HUMAN_CLOCK_REQUIRED')
  }
  assertContext(context) {
    if (canonicalJson(context) !== this.#context) throw denied('HUMAN_CONTEXT_MISMATCH')
  }
  async current(query, sessionId, expectedVersion = null, parentChecked = false) {
    text(sessionId)
    if (this.#portal && !parentChecked) await this.#portal.check(query, sessionId)
    // Common ordering: session then membership, before exact authority locks.
    const s = await query('SELECT * FROM dubsar_human.sessions WHERE context_key=$1 AND session_id=$2 FOR SHARE', [this.#context, sessionId])
    const session = s.rows[0]
    const now = Date.parse(this.#clock.now())
    if (!session || session.revoked || !Number.isFinite(now) || Date.parse(session.expires_at) <= now) throw denied('HUMAN_SESSION_DENIED')
    const m = await query('SELECT * FROM dubsar_human.memberships WHERE context_key=$1 AND issuer=$2 AND external_subject=$3 FOR SHARE',
      [this.#context, session.issuer, session.external_subject])
    const member = m.rows[0]
    if (!member?.enabled || member.environment !== this.#environment || member.active_function !== 'approver'
      || (expectedVersion !== null && String(member.version) !== String(expectedVersion))) throw denied('HUMAN_MEMBERSHIP_DENIED')
    return { subject: member.principal, active_function: member.active_function, version: String(member.version), expires_at: new Date(session.expires_at).toISOString() }
  }
  async open(query, claims, operation = 'prepare') {
    if (this.#portal) await this.#portal.check(query, claims.session, claims, operation)
    // Only callers holding the verified proof adapter may invoke this internal method.
    await query(`INSERT INTO dubsar_human.sessions(context_key,session_id,issuer,external_subject,expires_at)
      VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
    [this.#context, claims.session, claims.issuer, claims.subject, new Date(claims.expires_at * 1000).toISOString()])
    const s = await query('SELECT issuer,external_subject,expires_at FROM dubsar_human.sessions WHERE context_key=$1 AND session_id=$2', [this.#context, claims.session])
    if (s.rows[0]?.issuer !== claims.issuer || s.rows[0]?.external_subject !== claims.subject
      || Date.parse(s.rows[0]?.expires_at) !== claims.expires_at * 1000) throw denied('HUMAN_SESSION_CONFLICT')
    return this.current(query, claims.session, null, Boolean(this.#portal))
  }
  async checkDecision(query, decisionRef, subject) {
    const r = await query('SELECT * FROM dubsar_human.decision_sessions WHERE context_key=$1 AND decision_ref=$2', [this.#context, decisionRef])
    if (!r.rows[0] || r.rows[0].principal !== subject) throw denied('HUMAN_DECISION_LINK_REQUIRED')
    const principal = await this.current(query, r.rows[0].session_id, r.rows[0].membership_version)
    if (principal.subject !== subject) throw denied('HUMAN_DECISION_LINK_REQUIRED')
  }
  async link(query, decisionRef, sessionId, member) {
    await query('INSERT INTO dubsar_human.decision_sessions(context_key,decision_ref,session_id,membership_version,principal) VALUES($1,$2,$3,$4,$5)',
      [this.#context, decisionRef, sessionId, member.version, member.subject])
  }
}
