import { randomUUID } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { HumanProofVerifier } from '../human-identity/proof.mjs'
import { DocumentRegistry } from './registry.mjs'
import { validate, resources, digest, decision, deny, failure } from './contracts.mjs'

export class DocumentAuthority {
  constructor({ pool, context, clock, issuer, publicKey, audience = 'dubsar:document-access', verifySession }) {
    // The documentary audience cannot be widened to execution by composition.
    if (audience !== 'dubsar:document-access') throw failure('DOCUMENT_CONFIG_INVALID')
    validate('request', { context, request_ref: 'configuration', requested_resources: [{ corpus_ref: 'configuration', document_ref: 'configuration' }], proof: {} })
    this.context = structuredClone(context); this.clock = clock; this.verifySession = verifySession
    this.verifier = new HumanProofVerifier({ issuer, audience, publicKey, clock })
    this.registry = new DocumentRegistry({ pool, context, clock })
  }
  async source(claims) {
    if (typeof this.verifySession !== 'function') deny()
    let timer
    const controller = new AbortController()
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => this.verifySession(Object.freeze({ ...claims }), { signal: controller.signal, context: structuredClone(this.context) })),
        new Promise((_, reject) => { timer = setTimeout(() => reject(failure('DOCUMENT_UNAVAILABLE')), 500) }),
      ])
      if (result !== true) deny()
    } finally { clearTimeout(timer); controller.abort() }
  }
  authenticate(proof) { try { return this.verifier.authenticate(proof) } catch { deny() } }
  async guard(run) {
    try { return await run() } catch (e) {
      return { status: e.code === 'DOCUMENT_DENIED' ? 'deny' : 'unavailable', reason: e.code === 'DOCUMENT_DENIED' ? 'DOCUMENT_DENIED' : 'DOCUMENT_UNAVAILABLE' }
    }
  }
  async authorize(input) {
    return this.guard(async () => {
      const req = validate('request', input)
      if (canonicalJson(req.context) !== canonicalJson(this.context)) deny()
      const requested = resources(req.requested_resources)
      const claims = this.authenticate(req.proof)
      await this.source(claims)
      const result = await this.registry.transaction(async (q, policy_epoch) => {
        const member = await this.registry.current(q, claims)
        const found = await this.registry.allowed(q, member, requested)
        await this.source(claims)
        this.authenticate(req.proof)
        const now = Date.parse(this.clock.now())
        const expires = Math.min(now + 60000, claims.expires_at * 1000, member.expires)
        if (!Number.isFinite(now) || expires <= now) deny()
        const body = { schema: 'dubsar.document-decision/1', decision_id: randomUUID(),
          subject_ref: member.subject_ref, tenant_ref: this.context.tenant_ref, active_function: member.active_function,
          session_ref: claims.session, request_ref: req.request_ref, resources: found, policy_epoch,
          issued_at: new Date(now).toISOString(), expires_at: new Date(expires).toISOString() }
        const value = decision({ ...body, scope_digest: digest(body) })
        await q('INSERT INTO dubsar_document_access.decisions VALUES($1,$2,$3,$4)', [value.decision_id, value])
        return { status: 'allow', decision: value }
      })
      this.authenticate(req.proof)
      if (Date.parse(result.decision.expires_at) <= Date.parse(this.clock.now())) deny()
      return result
    })
  }
  async revalidate(input) {
    return this.guard(async () => {
      const req = validate('revalidation', input)
      const claims = this.authenticate(req.proof)
      await this.source(claims)
      const result = await this.registry.transaction(async (q, epoch) => {
        const member = await this.registry.current(q, claims)
        const row = (await q('SELECT document FROM dubsar_document_access.decisions WHERE tenant_ref=$1 AND context_ref=$2 AND decision_id=$3', [req.decision_id])).rows[0]
        if (!row) deny()
        const value = decision(row.document)
        if (value.scope_digest !== req.scope_digest || value.session_ref !== claims.session
          || value.subject_ref !== member.subject_ref || value.active_function !== member.active_function
          || value.tenant_ref !== this.context.tenant_ref || value.policy_epoch !== epoch
          || Date.parse(value.expires_at) <= Date.parse(this.clock.now())) deny()
        const found = await this.registry.allowed(q, member, value.resources.map(({ corpus_ref, document_ref }) => ({ corpus_ref, document_ref })))
        if (canonicalJson(found) !== canonicalJson(value.resources)) deny()
        await this.source(claims)
        this.authenticate(req.proof)
        if (Date.parse(value.expires_at) <= Date.parse(this.clock.now()) || member.expires <= Date.parse(this.clock.now())) deny()
        return { status: 'allow', decision: value }
      })
      this.authenticate(req.proof)
      if (Date.parse(result.decision.expires_at) <= Date.parse(this.clock.now())) deny()
      return result
    })
  }
}
