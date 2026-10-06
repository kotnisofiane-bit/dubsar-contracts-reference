import { randomUUID } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { hashPayload, hashContract } from '../contracts.mjs'
import { assertExact, hashExact, same, assertIdentity, displayManifest } from './contracts.mjs'
import { closed, denied, text } from '../human-identity/proof.mjs'

export class ApprovalService {
  #records; #registry; #verifier; #context; #reader; #resolve; #clock
  constructor({ records, registry, verifier, context, artifacts, resolveAction, clock }) {
    this.#records = records; this.#registry = registry; this.#verifier = verifier
    this.#context = canonicalJson(context); this.#reader = artifacts
    this.#resolve = resolveAction; this.#clock = clock
    if (typeof resolveAction !== 'function' || typeof artifacts?.read !== 'function') throw denied('EXACT_SERVICE_PORTS_REQUIRED')
    registry.assertContext(context)
    records.assertHumanContext(context, registry)
  }
  async #material(documents) {
    const { binding, prepared } = documents
    assertExact('binding', binding); assertExact('prepared', prepared)
    same(canonicalJson({ tenant_ref: binding.tenant_ref, project_ref: binding.project_ref, mission: binding.mission }), this.#context)
    same(prepared.binding_digest, hashExact('binding', binding))
    const display = await this.#reader.read(prepared.display.ref)
    const payload = await this.#reader.read(prepared.artifact.ref)
    same(hashPayload(display), prepared.display.digest); same(hashPayload(payload), prepared.artifact.digest)
    same(display.binding, binding); same(display.proposal.payload, payload)
    assertIdentity(binding, display.proposal)
    same(hashContract('action-proposal', display.proposal), prepared.proposal_digest)
    same(display, displayManifest({ binding, proposal: display.proposal, material: prepared.material, expectedEffect: prepared.expected_effect }))
    const now = Date.parse(this.#clock.now())
    if (!Number.isFinite(now) || Date.parse(prepared.expires_at) <= now || Date.parse(prepared.issued_at) > now) throw denied('EXACT_PRESENTATION_EXPIRED')
    return display
  }
  async handle(operation, params) {
    const fields = { prepare: ['proof', 'action_ref'], view: ['proof', 'presentation_id'],
      decide: ['proof', 'presentation_id', 'display_digest', 'choice', 'idempotency_key'] }
    if (!Object.hasOwn(fields, operation)) throw denied('EXACT_OPERATION_DENIED')
    closed(params, fields[operation])
    const claims = this.#verifier.authenticate(params.proof)
    return this.#records.humanTransaction(async query => {
      const member = await this.#registry.open(query, claims, operation)
      if (operation === 'prepare') {
        const documents = structuredClone(await this.#resolve(text(params.action_ref)))
        closed(documents, ['binding', 'prepared', 'policy_digest'])
        const display = await this.#material(documents)
        documents.server_action_ref = params.action_ref
        const presentationId = `presentation:${randomUUID()}`
        const expires = new Date(Math.min(Date.parse(documents.prepared.expires_at), Date.parse(member.expires_at))).toISOString()
        await query(`INSERT INTO dubsar_human.presentations(context_key,presentation_id,session_id,membership_version,principal,documents,expires_at)
          VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`,
        [this.#context, presentationId, claims.session, member.version, member.subject, canonicalJson(documents), expires])
        return { presentation_id: presentationId, display_digest: documents.prepared.display.digest, expires_at: expires, display, result: null }
      }
      const rows = await query('SELECT * FROM dubsar_human.presentations WHERE context_key=$1 AND presentation_id=$2 AND session_id=$3 FOR UPDATE',
        [this.#context, text(params.presentation_id), claims.session])
      const row = rows.rows[0]
      if (!row || row.principal !== member.subject || String(row.membership_version) !== member.version) throw denied('EXACT_PRESENTATION_DENIED')
      if (row.result !== null) {
        if (operation === 'decide' && (row.idempotency_key !== params.idempotency_key || row.result.choice !== params.choice
          || row.documents.prepared.display.digest !== params.display_digest)) throw denied('EXACT_DECISION_CONFLICT')
        return { presentation_id: row.presentation_id, result: row.result }
      }
      if (Date.parse(row.expires_at) <= Date.parse(this.#clock.now())) throw denied('EXACT_PRESENTATION_EXPIRED')
      const current = structuredClone(await this.#resolve(row.documents.server_action_ref))
      const { server_action_ref, ...stored } = row.documents
      same(current, stored)
      const display = await this.#material(row.documents)
      if (operation === 'view') return { presentation_id: row.presentation_id, display_digest: row.documents.prepared.display.digest,
        expires_at: new Date(row.expires_at).toISOString(), display, result: null }
      text(params.idempotency_key)
      if (!['APPROVE', 'REFUSE'].includes(params.choice)) throw denied('EXACT_CHOICE_INVALID')
      same(params.display_digest, row.documents.prepared.display.digest)
      const { binding, prepared, policy_digest } = row.documents
      const decision = { schema: 'dubsar.exact-decision.v2', decision_ref: `decision:${randomUUID()}`,
        binding_digest: prepared.binding_digest, prepared_digest: hashExact('prepared', prepared), display_digest: prepared.display.digest,
        approver: { subject: member.subject, active_function: member.active_function }, policy_digest,
        decision: params.choice, issued_at: new Date(this.#clock.now()).toISOString(), expires_at: new Date(row.expires_at).toISOString() }
      assertExact('decision', decision)
      if (params.choice === 'APPROVE') {
        await this.#records.publishUsing(query, { binding, prepared, decision, presentedDigest: prepared.display.digest })
        await this.#registry.link(query, decision.decision_ref, claims.session, member)
      }
      const result = { choice: params.choice, decision_ref: decision.decision_ref, decision }
      await query('UPDATE dubsar_human.presentations SET result=$1::jsonb,idempotency_key=$2 WHERE context_key=$3 AND presentation_id=$4',
        [canonicalJson(result), params.idempotency_key, this.#context, row.presentation_id])
      return { presentation_id: row.presentation_id, result }
    })
  }
}
