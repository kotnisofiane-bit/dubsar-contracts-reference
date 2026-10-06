import {
  decodeCompactSegment,
  encodeCompactSegment,
  parseCompactSignedEnvelope,
} from './signed-capability-format.mjs'

export const TASK_LEASE_ALGORITHM = 'EdDSA'
export const TASK_LEASE_TYPE = 'DUBSAR-TASK-LEASE+JSON'
export const TASK_LEASE_SCHEMA = 'dubsar.signed-task-lease.v1'
export const TASK_LEASE_ISSUER = 'dubsar-governance-core'
export const TASK_LEASE_AUDIENCE = 'dubsar-task-manager'
export const TASK_LEASE_HEADER_KEYS = Object.freeze(['alg', 'kid', 'typ', 'v'])
export const TASK_LEASE_PAYLOAD_KEYS = Object.freeze([
  'exp',
  'iat',
  'issuer',
  'lease',
  'lease_digest',
  'nbf',
  'policy_digest',
  'schema',
])
export const TASK_LEASE_MAX_VALIDITY_SECONDS = 300

const LABEL = 'signed task lease'

export function encodeTaskLeaseSegment(value) {
  return encodeCompactSegment(value)
}

export function decodeTaskLeaseSegment(segment) {
  return decodeCompactSegment(segment, LABEL)
}

export function parseSignedTaskLease(compact) {
  const parsed = parseCompactSignedEnvelope(compact, LABEL)
  const signatureSegment = compact.split('.')[2]
  if (parsed.signature.toString('base64url') !== signatureSegment) {
    throw new TypeError('signed task lease signature is not canonical')
  }
  return parsed
}
