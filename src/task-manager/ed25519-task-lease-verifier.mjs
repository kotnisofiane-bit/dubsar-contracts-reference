import { verify } from 'node:crypto'
import { assertContract, consumeTaskLease, hashContract } from '../contracts.mjs'
import { exactObjectKeys } from '../core/signed-capability-format.mjs'
import {
  TASK_LEASE_ALGORITHM,
  TASK_LEASE_AUDIENCE,
  TASK_LEASE_HEADER_KEYS,
  TASK_LEASE_ISSUER,
  TASK_LEASE_MAX_VALIDITY_SECONDS,
  TASK_LEASE_PAYLOAD_KEYS,
  TASK_LEASE_SCHEMA,
  TASK_LEASE_TYPE,
  parseSignedTaskLease,
} from '../core/signed-task-lease-format.mjs'
import { TaskManagerRejection } from './task-manager-error.mjs'

const KEY_ID = /^core-key_[a-z0-9][a-z0-9_-]{7,63}$/
const DIGEST = /^sha256:[a-f0-9]{64}$/
const MAX_CLOCK_SKEW_SECONDS = 5

/**
 * Reference Task Manager verifier for the compact Ed25519 task-lease envelope.
 *
 * Every check fails closed: format, algorithm, key, temporal envelope, issuer,
 * audience, contract validity, digest binding and signature are verified
 * independently, and `admit` additionally requires the Task Manager's local
 * closed profile, re-hashes it, binds identities, and consumes the lease once.
 */
export class Ed25519TaskLeaseVerifier {
  #keyRing

  constructor({ keyRing } = {}) {
    if (typeof keyRing?.resolve !== 'function') throw new TypeError('TASK_MANAGER_PUBLIC_KEY_RING_REQUIRED')
    this.#keyRing = keyRing
  }

  verify({ signedTaskLease, now } = {}) {
    return this.verifySigned({ signedTaskLease, now }).lease
  }

  verifySigned({ signedTaskLease, now } = {}) {
    let parsed
    try {
      parsed = parseSignedTaskLease(signedTaskLease)
    } catch {
      throw new TaskManagerRejection('TASK_LEASE_FORMAT_INVALID')
    }
    const { header, payload, signature, signingInput } = parsed
    if (!exactObjectKeys(header, TASK_LEASE_HEADER_KEYS)
      || header.alg !== TASK_LEASE_ALGORITHM
      || header.typ !== TASK_LEASE_TYPE
      || header.v !== 1) {
      throw new TaskManagerRejection('TASK_LEASE_ALGORITHM_INVALID')
    }
    if (!KEY_ID.test(header.kid ?? '')) throw new TaskManagerRejection('TASK_LEASE_KEY_UNKNOWN')
    if (!exactObjectKeys(payload, TASK_LEASE_PAYLOAD_KEYS)
      || payload.schema !== TASK_LEASE_SCHEMA
      || !DIGEST.test(payload.lease_digest ?? '')
      || !DIGEST.test(payload.policy_digest ?? '')) {
      throw new TaskManagerRejection('TASK_LEASE_FORMAT_INVALID')
    }
    assertTemporalEnvelope(payload, now)
    if (payload.issuer !== TASK_LEASE_ISSUER) throw new TaskManagerRejection('TASK_LEASE_ISSUER_INVALID')

    let lease
    try {
      lease = structuredClone(payload.lease)
      assertContract('task-lease', lease)
    } catch {
      throw new TaskManagerRejection('TASK_LEASE_INVALID')
    }
    if (lease.audience !== TASK_LEASE_AUDIENCE) throw new TaskManagerRejection('TASK_LEASE_AUDIENCE_INVALID')
    if (Date.parse(lease.issued_at) !== payload.iat * 1000
      || Date.parse(lease.not_before) !== payload.nbf * 1000
      || Date.parse(lease.expires_at) !== payload.exp * 1000) {
      throw new TaskManagerRejection('TASK_LEASE_TEMPORAL_INVALID')
    }
    if (hashContract('task-lease', lease) !== payload.lease_digest) {
      throw new TaskManagerRejection('TASK_LEASE_DIGEST_MISMATCH')
    }

    const issuedAt = new Date(payload.iat * 1000).toISOString()
    const publicKey = this.#keyRing.resolve(header.kid, normalizedInstant(now), issuedAt)
    if (signature.length !== 64 || !verify(null, signingInput, publicKey, signature)) {
      throw new TaskManagerRejection('TASK_LEASE_SIGNATURE_INVALID')
    }
    return Object.freeze({
      kid: header.kid,
      lease,
      leaseDigest: payload.lease_digest,
      policyDigest: payload.policy_digest,
    })
  }

  async admit({ signedTaskLease, closedProfile, expected, replayStore, now } = {}) {
    const verification = this.verifySigned({ signedTaskLease, now })
    if (closedProfile === undefined || closedProfile === null) {
      throw new TaskManagerRejection('TASK_LEASE_CLOSED_PROFILE_REQUIRED')
    }
    if (typeof replayStore?.consumeOnce !== 'function') {
      throw new TaskManagerRejection('TASK_LEASE_REPLAY_STORE_REQUIRED')
    }
    const expectedIdentities = isPlainExpectation(expected) ? { ...expected } : {}
    delete expectedIdentities.task
    try {
      await consumeTaskLease(
        verification.lease,
        { ...expectedIdentities, closedProfile },
        replayStore,
        normalizedInstant(now),
      )
    } catch (error) {
      throw new TaskManagerRejection(rejectionCodeFor(error))
    }
    return verification
  }
}

export function assertOperationAllowed(lease, operation) {
  if (typeof operation !== 'string' || !lease?.task?.allowed_operations?.includes(operation)) {
    throw new TaskManagerRejection('TASK_LEASE_OPERATION_FORBIDDEN')
  }
  return true
}

export class TaskManagerPublicKeyRing {
  #records = new Map()

  constructor({ keys = [] } = {}) {
    if (!Array.isArray(keys)) throw new TypeError('TASK_MANAGER_PUBLIC_KEYS_INVALID')
    for (const key of keys) this.admit(key)
  }

  admit({ kid, publicKey, notBefore = null, notAfter = null } = {}) {
    if (!KEY_ID.test(kid ?? '') || this.#records.has(kid)) throw new TypeError('TASK_MANAGER_PUBLIC_KEY_INVALID')
    if (publicKey?.type !== 'public' || publicKey?.asymmetricKeyType !== 'ed25519') {
      throw new TypeError('TASK_MANAGER_ED25519_PUBLIC_KEY_REQUIRED')
    }
    const window = normalizeKeyWindow(notBefore, notAfter)
    this.#records.set(kid, { key: publicKey, revoked: false, ...window })
  }

  revoke(kid) {
    const record = this.#records.get(kid)
    if (record === undefined) throw new TypeError('TASK_MANAGER_PUBLIC_KEY_UNKNOWN')
    record.revoked = true
  }

  resolve(kid, now, issuedAt = now) {
    const record = this.#records.get(kid)
    if (record === undefined) throw new TaskManagerRejection('TASK_LEASE_KEY_UNKNOWN')
    if (record.revoked) throw new TaskManagerRejection('TASK_LEASE_KEY_REVOKED')
    const instant = Date.parse(now)
    const issued = Date.parse(issuedAt)
    if (!Number.isFinite(instant) || !Number.isFinite(issued)) {
      throw new TaskManagerRejection('TASK_MANAGER_CLOCK_INVALID')
    }
    if ((record.notBefore !== null && issued < record.notBefore)
      || (record.notAfter !== null && issued >= record.notAfter)) {
      throw new TaskManagerRejection('TASK_LEASE_KEY_INACTIVE')
    }
    return record.key
  }
}

function assertTemporalEnvelope(payload, now) {
  if (![payload.iat, payload.nbf, payload.exp].every(Number.isSafeInteger)
    || payload.iat > payload.nbf
    || payload.nbf >= payload.exp
    || payload.exp - payload.nbf > TASK_LEASE_MAX_VALIDITY_SECONDS
    || payload.nbf - payload.iat > MAX_CLOCK_SKEW_SECONDS) {
    throw new TaskManagerRejection('TASK_LEASE_TEMPORAL_INVALID')
  }
  const instant = Math.floor(Date.parse(normalizedInstant(now)) / 1000)
  if (instant < payload.nbf) throw new TaskManagerRejection('TASK_LEASE_NOT_YET_VALID')
  if (instant >= payload.exp) throw new TaskManagerRejection('TASK_LEASE_EXPIRED')
}

function rejectionCodeFor(error) {
  const message = error instanceof Error ? error.message : ''
  if (/closed profile is required/.test(message)) return 'TASK_LEASE_CLOSED_PROFILE_REQUIRED'
  if (/replay store is required/.test(message)) return 'TASK_LEASE_REPLAY_STORE_REQUIRED'
  if (/closed profile is invalid/.test(message)) return 'TASK_LEASE_CLOSED_PROFILE_INVALID'
  if (/closed profile/.test(message)) return 'TASK_LEASE_PROFILE_MISMATCH'
  if (/replay detected/.test(message)) return 'TASK_LEASE_REPLAY_DETECTED'
  if (/not yet valid/.test(message)) return 'TASK_LEASE_NOT_YET_VALID'
  if (/is expired/.test(message)) return 'TASK_LEASE_EXPIRED'
  return 'TASK_LEASE_BINDING_MISMATCH'
}

function normalizeKeyWindow(notBefore, notAfter) {
  const start = notBefore === null ? null : Date.parse(normalizedInstant(notBefore))
  const end = notAfter === null ? null : Date.parse(normalizedInstant(notAfter))
  if (start !== null && end !== null && start >= end) throw new TypeError('TASK_MANAGER_PUBLIC_KEY_WINDOW_INVALID')
  return { notBefore: start, notAfter: end }
}

function normalizedInstant(value) {
  const instant = value instanceof Date ? value.getTime() : Date.parse(value)
  if (!Number.isFinite(instant)) throw new TaskManagerRejection('TASK_MANAGER_CLOCK_INVALID')
  return new Date(instant).toISOString()
}

function isPlainExpectation(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
