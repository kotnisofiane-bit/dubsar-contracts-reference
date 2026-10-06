import { canonicalJson } from '../canonical-json.mjs'

export const CAPABILITY_ALGORITHM = 'EdDSA'
export const CAPABILITY_TYPE = 'DUBSAR-CAPABILITY+JSON'
export const CAPABILITY_SCHEMA = 'dubsar.signed-capability.v1'
export const CAPABILITY_ISSUER = 'dubsar-governance-core'
export const CAPABILITY_AUDIENCE = 'dubsar-action-broker'

const COMPACT_SEGMENT = /^[A-Za-z0-9_-]+$/
const MAX_COMPACT_LENGTH = 32768

export function encodeCompactSegment(value) {
  return Buffer.from(canonicalJson(value), 'utf8').toString('base64url')
}

export function decodeCompactSegment(segment, label = 'signed capability') {
  if (typeof segment !== 'string' || !COMPACT_SEGMENT.test(segment)) {
    throw new TypeError(`${label} segment is invalid`)
  }
  const bytes = Buffer.from(segment, 'base64url')
  const value = JSON.parse(bytes.toString('utf8'))
  if (encodeCompactSegment(value) !== segment) {
    throw new TypeError(`${label} segment is not canonical`)
  }
  return value
}

export function parseCompactSignedEnvelope(compact, label = 'signed capability') {
  if (typeof compact !== 'string' || compact.length > MAX_COMPACT_LENGTH) {
    throw new TypeError(`${label} is invalid`)
  }
  const segments = compact.split('.')
  if (segments.length !== 3 || segments.some(segment => !COMPACT_SEGMENT.test(segment))) {
    throw new TypeError(`${label} compact serialization is invalid`)
  }
  const [protectedSegment, payloadSegment, signatureSegment] = segments
  return {
    header: decodeCompactSegment(protectedSegment, label),
    payload: decodeCompactSegment(payloadSegment, label),
    signature: Buffer.from(signatureSegment, 'base64url'),
    signingInput: Buffer.from(`${protectedSegment}.${payloadSegment}`, 'ascii'),
  }
}

export function encodeCapabilitySegment(value) {
  return encodeCompactSegment(value)
}

export function decodeCapabilitySegment(segment) {
  return decodeCompactSegment(segment, 'signed capability')
}

export function parseSignedCapability(compact) {
  return parseCompactSignedEnvelope(compact, 'signed capability')
}

export function exactObjectKeys(value, expected) {
  return isPlainObject(value)
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',')
}

export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
}
