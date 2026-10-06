import { fileURLToPath } from 'node:url'
import { SchemaRegistry } from '../schema-validator.mjs'
import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import { assertNoSecretMaterial, hashContract, hashPayload } from '../contracts.mjs'

export const exactSchemaRegistry = new SchemaRegistry(fileURLToPath(new URL('../../schemas/v2/', import.meta.url)))
export function assertExact(kind, value) {
  exactSchemaRegistry.assertValid(`${kind}.schema.json`, value)
  assertNoSecretMaterial(value)
  canonicalJson(value)
  if (value.material !== undefined) same(value.material.configuration_digest, hashPayload(value.material.configuration))
  return value
}
export function freezeExact(value) {
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) freezeExact(item)
    Object.freeze(value)
  }
  return value
}
export function hashExact(kind, value) {
  return domainSeparatedHash(`dubsar.exact-action.${kind}.v2`, assertExact(kind, value))
}
export function same(actual, expected) {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error('EXACT_ACTION_BINDING_MISMATCH')
}
export function assertIdentity(binding, proposal) {
  assertExact('binding', binding)
  for (const key of ['run_id', 'step_id', 'proposal_id', 'workload_identity']) same(binding[key], proposal[key])
  same(binding.tenant_ref, proposal.context.tenant_ref)
  same(binding.project_ref, proposal.context.project_ref)
}
export function displayManifest({ binding, proposal, material, expectedEffect }) {
  return { schema: 'dubsar.exact-display.v2', binding: structuredClone(binding),
    proposal: structuredClone(proposal), material: structuredClone(material), expected_effect: expectedEffect }
}

// Preparation is data, not approval authority. Persist both immutable artifacts
// before presenting this manifest through an authenticated Human Gate.
export function prepareExactAction({ binding, proposal, approval, material, expectedEffect,
  artifactRef, displayRef, issuedAt, expiresAt }) {
  assertIdentity(binding, proposal)
  if (!Object.hasOwn(proposal, 'payload')) throw new Error('EXACT_ACTION_INLINE_PAYLOAD_REQUIRED')
  const display = displayManifest({ binding, proposal, material, expectedEffect })
  const prepared = {
    schema: 'dubsar.prepared-action.v2', binding_digest: hashExact('binding', binding),
    proposal_digest: hashContract('action-proposal', proposal), approval_digest: hashContract('approval-record', approval),
    artifact: { ref: artifactRef, digest: hashPayload(proposal.payload) }, material: structuredClone(material),
    display: { ref: displayRef, digest: hashPayload(display) }, expected_effect: expectedEffect,
    issued_at: issuedAt, expires_at: expiresAt,
  }
  assertExact('prepared', prepared)
  if (Date.parse(issuedAt) >= Date.parse(expiresAt)) throw new Error('EXACT_ACTION_WINDOW_INVALID')
  return { prepared, display }
}

// records.withCurrent must serialize revocation/identity eligibility changes with
// the awaited callback (including durable claim). Never populate this port from
// request JSON. Artifact reads must return immutable content by reference.
export class ExactActionGate {
  #records
  #artifacts
  constructor({ records, artifacts } = {}) {
    if (typeof records?.withCurrent !== 'function' || typeof artifacts?.read !== 'function') {
      throw new TypeError('EXACT_ACTION_TRUSTED_PORTS_REQUIRED')
    }
    this.#records = records
    this.#artifacts = artifacts
  }
  async withAuthorization({ decisionRef, proposal, approval, clock, expected, material }, action) {
    if (typeof decisionRef !== 'string' || !decisionRef || typeof clock?.now !== 'function') {
      throw new Error('EXACT_ACTION_REFERENCE_REQUIRED')
    }
    let calls = 0
    const result = await this.#records.withCurrent(decisionRef, async (source, transaction) => {
      if (++calls !== 1) throw new Error('EXACT_ACTION_PORT_PROTOCOL_INVALID')
      const { binding, prepared, decision, revoked, principal } = structuredClone(source)
      assertIdentity(binding, proposal)
      assertExact('prepared', prepared)
      assertExact('decision', decision)
      same(decision.decision_ref, decisionRef)
      same(prepared.binding_digest, hashExact('binding', binding))
      same(prepared.proposal_digest, hashContract('action-proposal', proposal))
      same(prepared.approval_digest, hashContract('approval-record', approval))
      same(decision.binding_digest, prepared.binding_digest)
      same(decision.prepared_digest, hashExact('prepared', prepared))
      same(decision.display_digest, prepared.display.digest)
      same(decision.policy_digest, approval.policy_evaluation.policy_digest)
      if (revoked !== false || decision.decision !== 'APPROVE' || principal?.eligible !== true) {
        throw new Error('EXACT_ACTION_DECISION_DENIED')
      }
      same(decision.approver, { subject: principal.subject, active_function: principal.active_function })
      same(principal.presented_digest, decision.display_digest)
      if (Date.parse(decision.issued_at) < Date.parse(prepared.issued_at)
        || Date.parse(decision.issued_at) >= Date.parse(prepared.expires_at)) throw new Error('EXACT_ACTION_WINDOW_INVALID')
      const content = structuredClone(await this.#artifacts.read(prepared.artifact.ref))
      same(hashPayload(content), prepared.artifact.digest)
      same(content, proposal.payload)
      const display = structuredClone(await this.#artifacts.read(prepared.display.ref))
      same(hashPayload(display), prepared.display.digest)
      same(display, displayManifest({ binding, proposal, material: prepared.material, expectedEffect: prepared.expected_effect }))
      if (material !== undefined) same(material, prepared.material)
      const proof = {
        decision_ref: decisionRef, binding, binding_digest: prepared.binding_digest,
        prepared_digest: hashExact('prepared', prepared), decision_digest: hashExact('decision', decision),
        display_digest: decision.display_digest, material: prepared.material, expected_effect: prepared.expected_effect,
        expires_at: new Date(Math.min(Date.parse(prepared.expires_at), Date.parse(decision.expires_at), Date.parse(approval.expires_at))).toISOString(),
      }
      assertExact('proof', proof)
      if (expected !== undefined) same(proof, expected)
      const now = new Date(clock.now()).getTime()
      if (!Number.isFinite(now) || now < Date.parse(decision.issued_at) || now < Date.parse(prepared.issued_at)
        || now >= Date.parse(proof.expires_at)) throw new Error('EXACT_ACTION_EXPIRED')
      return action(structuredClone(proof), transaction)
    })
    if (calls !== 1) throw new Error('EXACT_ACTION_PORT_PROTOCOL_INVALID')
    return result
  }
}
