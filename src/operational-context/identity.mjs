import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import { OC_BOUNDS, OC_HASH_DOMAINS } from './bounds.mjs'
import { ocError } from './errors.mjs'

export function requireToken(value, name) {
  if (typeof value !== 'string'
    || value.length < OC_BOUNDS.identifier_min_length
    || value.length > OC_BOUNDS.identifier_max_length
    || /[\u0000-\u001f]/.test(value)) {
    throw ocError('OC_CONTRACT_INVALID', `${name} is not an admitted token`)
  }
  return value
}

export function incarnationOf(value) {
  if (value === undefined || value === null) return { absence: 'not_available' }
  if (typeof value === 'object' && !Array.isArray(value) && value.absence === 'not_available') {
    return { absence: 'not_available' }
  }
  return requireToken(value, 'incarnation')
}

export function resourceIdentity(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw ocError('OC_CONTRACT_INVALID', 'resource identity must be an object')
  }
  const identity = {
    tenant_id: requireToken(input.tenant_id, 'tenant_id'),
    environment_id: requireToken(input.environment_id, 'environment_id'),
    source_instance_id: requireToken(input.source_instance_id, 'source_instance_id'),
    namespace: requireToken(input.namespace, 'namespace'),
    type: requireToken(input.type, 'type'),
    source_id: requireToken(input.source_id, 'source_id'),
    incarnation: incarnationOf(input.incarnation),
  }
  const fingerprint = domainSeparatedHash(OC_HASH_DOMAINS.resource, identity)
  const local_ref = `ocr_${fingerprint.slice(7, 39)}`
  return { identity, fingerprint, local_ref }
}

export function pairFingerprint(leftIdentity, rightIdentity, type) {
  const left = canonicalJson(leftIdentity)
  const right = canonicalJson(rightIdentity)
  if (left === right) throw ocError('OC_CONTRACT_INVALID', 'association ends must be distinct')
  const [a, b] = left < right ? [leftIdentity, rightIdentity] : [rightIdentity, leftIdentity]
  return domainSeparatedHash(OC_HASH_DOMAINS.pair, { a, b, type })
}

export function aggregateKey(resourceLocalRef, property) {
  return canonicalJson({ property: requireToken(property, 'property'), resource_local_ref: requireToken(resourceLocalRef, 'resource_local_ref') })
}

export function assertSameScope(trust, identity) {
  if (trust.tenant_id !== identity.tenant_id || trust.environment_id !== identity.environment_id) {
    throw ocError('OC_UNAUTHORIZED', 'tenant or environment mismatch')
  }
}
