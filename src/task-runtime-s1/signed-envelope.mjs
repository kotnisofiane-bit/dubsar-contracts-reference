// Wire-format validation only. Signature verification, key trust and replay
// consumption remain responsibilities of the future Core/Task Runtime adapters.
import {
  encodeCompactSegment, exactObjectKeys, parseCompactSignedEnvelope,
} from '../core/signed-capability-format.mjs'
import { assertS1TaskLease, hashS1TaskLease, rejectS1 } from './contracts.mjs'

export const S1_SIGNED_SCHEMA = 'dubsar.signed-task-lease.v2'
export const S1_HEADER_KEYS = Object.freeze(['alg', 'kid', 'typ', 'v'])
export const S1_PAYLOAD_KEYS = Object.freeze(['exp', 'iat', 'issuer', 'lease', 'lease_digest', 'nbf', 'policy_digest', 'schema'])
export const encodeS1LeaseSegment = encodeCompactSegment

export function assertS1Envelope(header, payload) {
  if (!exactObjectKeys(header, S1_HEADER_KEYS) || header.v !== 2
    || header.alg !== 'EdDSA' || header.typ !== 'DUBSAR-TASK-LEASE+JSON') {
    rejectS1('S1_ENVELOPE_VERSION_INVALID')
  }
  if (typeof header.kid !== 'string' || !/^core-key_[a-z0-9][a-z0-9_-]{7,63}$/.test(header.kid)) {
    rejectS1('S1_ENVELOPE_KEY_INVALID')
  }
  if (!exactObjectKeys(payload, S1_PAYLOAD_KEYS) || payload.schema !== S1_SIGNED_SCHEMA
    || payload.issuer !== 'dubsar-governance-core'
    || typeof payload.policy_digest !== 'string'
    || !/^sha256:[a-f0-9]{64}$/.test(payload.policy_digest)) {
    rejectS1('S1_ENVELOPE_PAYLOAD_INVALID')
  }
  assertS1TaskLease(payload.lease)
  const seconds = [payload.iat, payload.nbf, payload.exp]
  if (!seconds.every(n => Number.isSafeInteger(n) && !Object.is(n, -0))
    || payload.iat > payload.nbf || payload.nbf >= payload.exp
    || payload.exp - payload.nbf > 300 || payload.nbf - payload.iat > 5
    || Date.parse(payload.lease.issued_at) !== payload.iat * 1000
    || Date.parse(payload.lease.not_before) !== payload.nbf * 1000
    || Date.parse(payload.lease.expires_at) !== payload.exp * 1000) {
    rejectS1('S1_ENVELOPE_TEMPORAL_INVALID')
  }
  if (payload.lease_digest !== hashS1TaskLease(payload.lease)) rejectS1('S1_ENVELOPE_DIGEST_MISMATCH')
  return { header, payload }
}
export function parseS1SignedTaskLease(compact) {
  let parsed
  try {
    parsed = parseCompactSignedEnvelope(compact, 'S1 signed task lease')
    if (parsed.signature.length !== 64
      || parsed.signature.toString('base64url') !== compact.split('.')[2]) throw new Error()
  } catch { rejectS1('S1_ENVELOPE_FORMAT_INVALID') }
  assertS1Envelope(parsed.header, parsed.payload)
  return parsed
}
