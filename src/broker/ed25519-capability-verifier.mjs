import { verify } from 'node:crypto'
import { assertContract } from '../contracts.mjs'
import { assertExact } from '../exact-action/contracts.mjs'
import {
  CAPABILITY_ALGORITHM,
  CAPABILITY_AUDIENCE,
  CAPABILITY_ISSUER,
  CAPABILITY_SCHEMA,
  CAPABILITY_TYPE,
  exactObjectKeys,
  parseSignedCapability,
} from '../core/signed-capability-format.mjs'
import { BrokerRejection } from './broker-error.mjs'

const KEY_ID = /^core-key_[a-z0-9][a-z0-9_-]{7,63}$/
const DIGEST = /^sha256:[a-f0-9]{64}$/
const MAX_VALIDITY_SECONDS = 120

export class Ed25519CapabilityVerifier {
  #keyRing
  #version

  constructor({ keyRing, version = 1 } = {}) {
    if (typeof keyRing?.resolve !== 'function') throw new TypeError('BROKER_PUBLIC_KEY_RING_REQUIRED')
    this.#keyRing = keyRing
    if (![1, 2].includes(version)) throw new TypeError('BROKER_CAPABILITY_VERSION_INVALID')
    this.#version = version
  }

  verify({ signedCapability, now } = {}) {
    return this.verifySigned({ signedCapability, now }).claims
  }

  verifySigned({ signedCapability, now } = {}) {
    let parsed
    try {
      parsed = parseSignedCapability(signedCapability)
    } catch {
      throw new BrokerRejection('BROKER_CAPABILITY_FORMAT_INVALID')
    }
    const { header, payload, signature, signingInput } = parsed
    if (!exactObjectKeys(header, ['alg', 'kid', 'typ', 'v'])
      || header.alg !== CAPABILITY_ALGORITHM
      || header.typ !== CAPABILITY_TYPE
      || header.v !== this.#version) {
      throw new BrokerRejection('BROKER_CAPABILITY_ALGORITHM_INVALID')
    }
    if (!KEY_ID.test(header.kid ?? '')) throw new BrokerRejection('BROKER_CAPABILITY_KEY_UNKNOWN')
    if (!exactObjectKeys(payload, [
      'approval_digest',
      'claims',
      'exp',
      'iat',
      'nbf',
      'proposal_digest',
      'schema',
      'subject_workload',
      ...(this.#version === 2 ? ['exact_action'] : []),
    ])
      || payload.schema !== (this.#version === 1 ? CAPABILITY_SCHEMA : 'dubsar.signed-capability.v2')
      || !DIGEST.test(payload.proposal_digest ?? '')
      || !DIGEST.test(payload.approval_digest ?? '')
      || !isWorkloadIdentity(payload.subject_workload)) {
      throw new BrokerRejection('BROKER_CAPABILITY_FORMAT_INVALID')
    }
    assertTemporalEnvelope(payload, now)

    if (payload.claims?.issuer !== CAPABILITY_ISSUER) {
      throw new BrokerRejection('BROKER_CAPABILITY_ISSUER_INVALID')
    }
    if (payload.claims?.audience !== CAPABILITY_AUDIENCE) {
      throw new BrokerRejection('BROKER_CAPABILITY_AUDIENCE_INVALID')
    }
    let claims
    try {
      claims = structuredClone(payload.claims)
      assertContract('capability-claims', claims)
    } catch {
      throw new BrokerRejection('BROKER_CAPABILITY_INVALID')
    }
    if (Date.parse(claims.issued_at) !== payload.iat * 1000
      || Date.parse(claims.not_before) !== payload.nbf * 1000
      || Date.parse(claims.expires_at) !== payload.exp * 1000) {
      throw new BrokerRejection('BROKER_CAPABILITY_TEMPORAL_INVALID')
    }

    const publicKey = this.#keyRing.resolve(header.kid, normalizedInstant(now))
    if (signature.length !== 64 || !verify(null, signingInput, publicKey, signature)) {
      throw new BrokerRejection('BROKER_CAPABILITY_SIGNATURE_INVALID')
    }
    if (this.#version === 2) {
      try {
        assertExact('proof', payload.exact_action)
        if (payload.exp * 1000 > Date.parse(payload.exact_action.expires_at)) throw new Error('window')
      } catch { throw new BrokerRejection('BROKER_EXACT_PROOF_INVALID') }
    }
    return Object.freeze({
      ...(this.#version === 2 ? { exactAction: structuredClone(payload.exact_action) } : {}),
      approvalDigest: payload.approval_digest,
      claims,
      kid: header.kid,
      proposalDigest: payload.proposal_digest,
      workloadIdentity: structuredClone(payload.subject_workload),
    })
  }
}

export class StaticEd25519PublicKeyRing {
  #records = new Map()

  constructor({ keys = [] } = {}) {
    if (!Array.isArray(keys)) throw new TypeError('BROKER_PUBLIC_KEYS_INVALID')
    for (const key of keys) this.admit(key)
  }

  admit({ kid, publicKey, notBefore = null, notAfter = null } = {}) {
    if (!KEY_ID.test(kid ?? '') || this.#records.has(kid)) throw new TypeError('BROKER_PUBLIC_KEY_INVALID')
    if (publicKey?.type !== 'public' || publicKey?.asymmetricKeyType !== 'ed25519') {
      throw new TypeError('BROKER_ED25519_PUBLIC_KEY_REQUIRED')
    }
    const window = normalizeKeyWindow(notBefore, notAfter)
    this.#records.set(kid, { key: publicKey, revoked: false, ...window })
  }

  revoke(kid) {
    const record = this.#records.get(kid)
    if (record === undefined) throw new TypeError('BROKER_PUBLIC_KEY_UNKNOWN')
    record.revoked = true
  }

  resolve(kid, now) {
    const record = this.#records.get(kid)
    if (record === undefined) throw new BrokerRejection('BROKER_CAPABILITY_KEY_UNKNOWN')
    if (record.revoked) throw new BrokerRejection('BROKER_CAPABILITY_KEY_REVOKED')
    const instant = Date.parse(now)
    if ((record.notBefore !== null && instant < record.notBefore)
      || (record.notAfter !== null && instant >= record.notAfter)) {
      throw new BrokerRejection('BROKER_CAPABILITY_KEY_INACTIVE')
    }
    return record.key
  }
}

function assertTemporalEnvelope(payload, now) {
  if (![payload.iat, payload.nbf, payload.exp].every(Number.isSafeInteger)
    || payload.iat > payload.nbf
    || payload.nbf >= payload.exp
    || payload.exp - payload.nbf > MAX_VALIDITY_SECONDS
    || payload.nbf - payload.iat > 5) {
    throw new BrokerRejection('BROKER_CAPABILITY_TEMPORAL_INVALID')
  }
  const instant = Math.floor(Date.parse(normalizedInstant(now)) / 1000)
  if (instant < payload.nbf) throw new BrokerRejection('BROKER_CAPABILITY_NOT_YET_VALID')
  if (instant >= payload.exp) throw new BrokerRejection('BROKER_CAPABILITY_EXPIRED')
}

function normalizeKeyWindow(notBefore, notAfter) {
  const start = notBefore === null ? null : Date.parse(normalizedInstant(notBefore))
  const end = notAfter === null ? null : Date.parse(normalizedInstant(notAfter))
  if (start !== null && end !== null && start >= end) throw new TypeError('BROKER_PUBLIC_KEY_WINDOW_INVALID')
  return { notBefore: start, notAfter: end }
}

function normalizedInstant(value) {
  const instant = value instanceof Date ? value.getTime() : Date.parse(value)
  if (!Number.isFinite(instant)) throw new BrokerRejection('BROKER_CLOCK_INVALID')
  return new Date(instant).toISOString()
}

function isWorkloadIdentity(identity) {
  return identity !== null
    && typeof identity === 'object'
    && !Array.isArray(identity)
    && Object.keys(identity).sort().join(',') === 'instance_id,workload_id'
    && /^workload_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.workload_id)
    && /^instance_[a-z0-9][a-z0-9_-]{7,127}$/.test(identity.instance_id)
}
