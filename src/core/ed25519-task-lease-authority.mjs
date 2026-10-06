import { randomBytes, sign } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { assertContract, bindTaskAuthorization, hashContract, taskAuthorizationSlice } from '../contracts.mjs'
import { isPlainObject } from './signed-capability-format.mjs'
import {
  TASK_LEASE_ALGORITHM,
  TASK_LEASE_AUDIENCE,
  TASK_LEASE_ISSUER,
  TASK_LEASE_MAX_VALIDITY_SECONDS,
  TASK_LEASE_SCHEMA,
  TASK_LEASE_TYPE,
  encodeTaskLeaseSegment,
} from './signed-task-lease-format.mjs'

const KEY_ID = /^core-key_[a-z0-9][a-z0-9_-]{7,63}$/
const DIGEST = /^sha256:[a-f0-9]{64}$/
const LEASE_ID = /^lease_[a-z0-9][a-z0-9_-]{7,127}$/
const NONCE = /^nonce_[A-Za-z0-9_-]{32,128}$/
const REPLAY_KEY = /^replay_[A-Za-z0-9_-]{32,128}$/

/**
 * Reference Core issuer for `dubsar.task-lease.v1`.
 *
 * The lease authorizes an exact closed Task profile decided by Core policy; it
 * never derives that profile from the requester. The caller supplies the
 * policy-admitted closed profile; the issuer hashes it (`profile_digest`,
 * `runtime_lock_digest`) and copies only the authorization slice into the lease.
 */
export class Ed25519TaskLeaseAuthority {
  #signingKey
  #kid
  #clock
  #leaseIdFactory
  #nonceFactory
  #replayKeyFactory
  #issued = new Set()

  constructor({
    signingKey,
    kid,
    clock,
    leaseIdFactory = defaultLeaseId,
    nonceFactory = defaultNonce,
    replayKeyFactory = defaultReplayKey,
  } = {}) {
    if (signingKey?.type !== 'private' || signingKey?.asymmetricKeyType !== 'ed25519') {
      throw new TypeError('CORE_ED25519_PRIVATE_KEY_REQUIRED')
    }
    if (!KEY_ID.test(kid ?? '')) throw new TypeError('CORE_KEY_ID_INVALID')
    if (typeof clock?.now !== 'function') throw new TypeError('CORE_CLOCK_REQUIRED')
    for (const factory of [leaseIdFactory, nonceFactory, replayKeyFactory]) {
      if (typeof factory !== 'function') throw new TypeError('CORE_IDENTIFIER_FACTORY_REQUIRED')
    }
    this.#signingKey = signingKey
    this.#kid = kid
    this.#clock = clock
    this.#leaseIdFactory = leaseIdFactory
    this.#nonceFactory = nonceFactory
    this.#replayKeyFactory = replayKeyFactory
  }

  issue({
    taskId,
    actionId,
    tenantId,
    missionId,
    taskManagerIdentity,
    task,
    closedProfile,
    evidenceCorrelationId,
    policyDigest,
    validitySeconds = 60,
  } = {}) {
    if (!isPlainObject(closedProfile)) throw new TypeError('CORE_CLOSED_PROFILE_REQUIRED')
    if (!isPlainObject(taskManagerIdentity)) throw new TypeError('CORE_TASK_MANAGER_IDENTITY_REQUIRED')
    let boundTask
    try {
      boundTask = bindTaskAuthorization(closedProfile)
    } catch (error) {
      throw new TypeError(`CORE_CLOSED_PROFILE_INVALID: ${error instanceof Error ? error.message : 'rejected'}`)
    }
    if (isPlainObject(task)
      && canonicalJson(taskAuthorizationSlice(task)) !== canonicalJson(taskAuthorizationSlice(boundTask))) {
      throw new Error('CORE_TASK_PROFILE_MISMATCH')
    }
    if (!DIGEST.test(policyDigest ?? '')) throw new TypeError('CORE_POLICY_DIGEST_INVALID')
    if (!Number.isInteger(validitySeconds) || validitySeconds < 1 || validitySeconds > TASK_LEASE_MAX_VALIDITY_SECONDS) {
      throw new TypeError('CORE_TASK_LEASE_VALIDITY_INVALID')
    }

    const issuedAt = normalizedInstant(this.#clock.now(), 'CORE_CLOCK_INVALID')
    const iat = Math.floor(Date.parse(issuedAt) / 1000)
    const nbf = iat
    const exp = iat + validitySeconds

    const leaseId = this.#leaseIdFactory()
    const nonce = this.#nonceFactory()
    const replayKey = this.#replayKeyFactory()
    if (!LEASE_ID.test(leaseId ?? '')) throw new TypeError('CORE_LEASE_ID_INVALID')
    if (!NONCE.test(nonce ?? '')) throw new TypeError('CORE_NONCE_INVALID')
    if (!REPLAY_KEY.test(replayKey ?? '')) throw new TypeError('CORE_REPLAY_KEY_INVALID')
    for (const identifier of [leaseId, nonce, replayKey]) {
      if (this.#issued.has(identifier)) throw new Error('CORE_TASK_LEASE_IDENTIFIER_REUSE_REFUSED')
    }

    const lease = {
      schema: 'dubsar.task-lease.v1',
      contract_version: '1.0.0',
      lease_id: leaseId,
      authority: 'DUBSAR_CORE',
      audience: TASK_LEASE_AUDIENCE,
      task_id: taskId,
      action_id: actionId,
      tenant_id: tenantId,
      mission_id: missionId,
      task_manager: structuredClone(taskManagerIdentity),
      task: boundTask,
      evidence_correlation_id: evidenceCorrelationId,
      issued_at: new Date(iat * 1000).toISOString(),
      not_before: new Date(nbf * 1000).toISOString(),
      expires_at: new Date(exp * 1000).toISOString(),
      nonce,
      replay_protection: { replay_key: replayKey, single_use: true },
    }
    try {
      assertContract('task-lease', lease)
    } catch (error) {
      throw new Error(`CORE_TASK_LEASE_INVALID: ${error instanceof Error ? error.message : 'rejected'}`)
    }
    for (const identifier of [leaseId, nonce, replayKey]) this.#issued.add(identifier)

    const header = {
      alg: TASK_LEASE_ALGORITHM,
      kid: this.#kid,
      typ: TASK_LEASE_TYPE,
      v: 1,
    }
    const payload = {
      exp,
      iat,
      issuer: TASK_LEASE_ISSUER,
      lease,
      lease_digest: hashContract('task-lease', lease),
      nbf,
      policy_digest: policyDigest,
      schema: TASK_LEASE_SCHEMA,
    }
    const protectedSegment = encodeTaskLeaseSegment(header)
    const payloadSegment = encodeTaskLeaseSegment(payload)
    const signingInput = Buffer.from(`${protectedSegment}.${payloadSegment}`, 'ascii')
    const signature = sign(null, signingInput, this.#signingKey)
    return `${protectedSegment}.${payloadSegment}.${signature.toString('base64url')}`
  }
}

function normalizedInstant(value, code) {
  const instant = value instanceof Date ? value.getTime() : Date.parse(value)
  if (!Number.isFinite(instant)) throw new TypeError(code)
  return new Date(Math.floor(instant / 1000) * 1000).toISOString()
}

function defaultLeaseId() {
  return `lease_${randomBytes(12).toString('hex')}`
}

function defaultNonce() {
  return `nonce_${randomBytes(24).toString('base64url')}`
}

function defaultReplayKey() {
  return `replay_${randomBytes(24).toString('base64url')}`
}
