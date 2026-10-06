import { verify, createPublicKey } from 'node:crypto'
import { canonicalBytes } from '../canonical-json.mjs'
import { fileURLToPath } from 'node:url'
import { SchemaRegistry } from '../schema-validator.mjs'
const schemas = new SchemaRegistry(fileURLToPath(new URL('../../schemas/human-identity/v1/', import.meta.url)))

export const denied = code => Object.assign(new Error(code), { code })
export function closed(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...names].sort().join(',')) throw denied('HUMAN_INPUT_INVALID')
}
export function text(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256 || /[\u0000-\u001f]/.test(value)) throw denied('HUMAN_INPUT_INVALID')
  return value
}

// This is an adapter proof, not a claim to implement an OIDC provider.
export class HumanProofVerifier {
  #issuer; #audience; #key; #clock; #maxAge
  constructor({ issuer, audience, publicKey, clock, maxAgeSeconds = 300 }) {
    this.#issuer = text(issuer); this.#audience = text(audience)
    this.#key = createPublicKey(publicKey)
    if (this.#key.asymmetricKeyType !== 'ed25519' || typeof clock?.now !== 'function'
      || !Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 1 || maxAgeSeconds > 300) throw denied('HUMAN_VERIFIER_INVALID')
    this.#clock = clock; this.#maxAge = maxAgeSeconds
  }
  authenticate(proof) {
    schemas.assertValid('proof.schema.json', proof)
    closed(proof, ['claims', 'signature'])
    const c = structuredClone(proof.claims)
    closed(c, ['schema', 'issuer', 'audience', 'subject', 'session', 'kind', 'issued_at', 'expires_at'])
    for (const field of ['issuer', 'audience', 'subject', 'session']) text(c[field])
    const now = Date.parse(this.#clock.now())
    if (c.schema !== 'dubsar.human-proof/1' || c.kind !== 'human' || c.issuer !== this.#issuer
      || c.audience !== this.#audience || !Number.isFinite(now)
      || !Number.isSafeInteger(c.issued_at) || !Number.isSafeInteger(c.expires_at)
      || c.issued_at * 1000 > now || c.expires_at * 1000 <= now || c.expires_at <= c.issued_at
      || c.expires_at - c.issued_at > this.#maxAge || now - c.issued_at * 1000 > this.#maxAge * 1000
      || typeof proof.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(proof.signature)) throw denied('HUMAN_PROOF_DENIED')
    if (!verify(null, canonicalBytes(c), this.#key, Buffer.from(proof.signature, 'base64url'))) throw denied('HUMAN_PROOF_DENIED')
    return Object.freeze(c)
  }
}
