import { fileURLToPath } from 'node:url'
import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import { SchemaRegistry } from '../schema-validator.mjs'
import { OC_BOUNDS, OC_CONTRACTS, OC_HASH_DOMAINS } from './bounds.mjs'
import { ocError } from './errors.mjs'
import { compareUtc, normalizeUtcDateTime, sourceInstant } from './time.mjs'
import { resourceIdentity } from './identity.mjs'

export const ocRegistry = new SchemaRegistry(fileURLToPath(new URL('../../schemas/operational-context/v1/', import.meta.url)))

const SCHEMA_BY_CONTRACT = Object.freeze({
  'dubsar.operational-context.state-projection/1': 'state-projection.schema.json',
  'dubsar.operational-context.view/2': 'view-v2.schema.json',
  'dubsar.operational-context.observation/2': 'observation-v2.schema.json',
  'dubsar.operational-context.mapping/2': 'mapping-v2.schema.json',
  'dubsar.operational-context.state-binding/1': 'state-binding.schema.json',
  'dubsar.operational-context.view-request/2': 'view-request-v2.schema.json',
  [OC_CONTRACTS.observation]: 'observation.schema.json',
  [OC_CONTRACTS.resource]: 'resource.schema.json',
  [OC_CONTRACTS.association]: 'association.schema.json',
  [OC_CONTRACTS.qualification]: 'qualification.schema.json',
  [OC_CONTRACTS.viewRequest]: 'view-request.schema.json',
  [OC_CONTRACTS.view]: 'view.schema.json',
  [OC_CONTRACTS.mapping]: 'mapping.schema.json',
  [OC_CONTRACTS.rule]: 'rule.schema.json',
  [OC_CONTRACTS.ingestResult]: 'ingest-result.schema.json',
  [OC_CONTRACTS.trust]: 'trust.schema.json',
})

export function assertUtf8Bound(value, limit, code = 'OC_BOUND_EXCEEDED') {
  const encoded = canonicalJson(value)
  const bytes = Buffer.byteLength(encoded, 'utf8')
  if (bytes > limit) throw ocError(code, `payload exceeds ${limit} UTF-8 bytes`, { bytes, limit })
  return { encoded, bytes }
}

export function assertContractName(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || typeof value.contract !== 'string') {
    throw ocError('OC_CONTRACT_INVALID', 'contract field is required')
  }
  if (!Object.hasOwn(SCHEMA_BY_CONTRACT, value.contract)) {
    throw ocError('OC_CONTRACT_UNKNOWN', `unknown contract ${value.contract}`)
  }
  return value.contract
}

export function validateClosed(name, value) {
  const contract = assertContractName(value)
  const expected = Object.entries(SCHEMA_BY_CONTRACT).find(([, file]) => file === name)?.[0]
  if (expected !== undefined && contract !== expected) {
    throw ocError('OC_CONTRACT_INVALID', 'contract does not match schema')
  }
  try {
    ocRegistry.assertValid(name, value)
  } catch (error) {
    throw ocError('OC_CONTRACT_INVALID', error instanceof Error ? error.message : 'schema rejected')
  }
  return structuredClone(value)
}

export function validateTrust(value) {
  const trust = validateClosed('trust.schema.json', value)
  return structuredClone(trust)
}

export function validateResource(value) {
  const resource = validateClosed('resource.schema.json', value)
  return resourceIdentity(resource)
}

export function validateObservation(value) {
  assertUtf8Bound(value, OC_BOUNDS.observation_utf8_bytes)
  const observation = validateClosed(value?.contract === 'dubsar.operational-context.observation/2'
    ? 'observation-v2.schema.json' : 'observation.schema.json', value)
  if (observation.correction_of !== undefined && observation.retraction_of !== undefined) {
    throw ocError('OC_CONTRACT_INVALID', 'correction and retraction cannot combine')
  }
  const result = observation.result
  switch (result.kind) {
    case 'measured':
      assertMeasuredValue(result)
      break
    case 'proven_absence':
      if (observation.scope.complete !== true) {
        throw ocError('OC_CONTRACT_INVALID', 'proven absence requires a complete declared scope')
      }
      break
    case 'collection_impossible':
    case 'collection_partial':
      break
    default: {
      const exhausted = result.kind
      throw ocError('OC_CONTRACT_UNKNOWN', `unknown result kind ${exhausted}`)
    }
  }
  if (compareUtc(observation.scope.period.start, observation.scope.period.end) > 0) {
    throw ocError('OC_CONTRACT_INVALID', 'scope period is inverted')
  }
  observation.scope.period.start = normalizeUtcDateTime(observation.scope.period.start)
  observation.scope.period.end = normalizeUtcDateTime(observation.scope.period.end)
  const source = sourceInstant(observation.source_observed_at)
  if (source.kind === 'known') observation.source_observed_at = source.normalized
  return observation
}

function assertMeasuredValue(result) {
  switch (result.value_type) {
    case 'boolean':
      if (typeof result.value !== 'boolean') throw ocError('OC_CONTRACT_INVALID', 'boolean value required')
      break
    case 'integer':
      if (!Number.isSafeInteger(result.value)) throw ocError('OC_CONTRACT_INVALID', 'integer value required')
      break
    case 'string':
      if (typeof result.value !== 'string') throw ocError('OC_CONTRACT_INVALID', 'string value required')
      break
    case 'null':
      if (result.value !== null) throw ocError('OC_CONTRACT_INVALID', 'null value required')
      break
    default: {
      const exhausted = result.value_type
      throw ocError('OC_CONTRACT_UNKNOWN', `unknown value type ${exhausted}`)
    }
  }
}

export function observationContent(observation) {
  return {
    ...(observation.contract === 'dubsar.operational-context.observation/2'
      ? { state_order: observation.state_order, observation_contract: observation.contract } : {}),
    correction_of: observation.correction_of ?? null,
    measurement_id: observation.measurement_id,
    property: observation.property,
    provenance: observation.provenance,
    result: observation.result,
    retraction_of: observation.retraction_of ?? null,
    rule_ref: observation.rule_ref ?? null,
    rule_version: observation.rule_version ?? null,
    scope: observation.scope,
    source_observed_at: observation.source_observed_at,
    subject: {
      environment_id: observation.subject.environment_id,
      incarnation: observation.subject.incarnation,
      namespace: observation.subject.namespace,
      source_id: observation.subject.source_id,
      source_instance_id: observation.subject.source_instance_id,
      tenant_id: observation.subject.tenant_id,
      type: observation.subject.type,
    },
  }
}

export function observationFingerprint(observation) {
  return domainSeparatedHash(OC_HASH_DOMAINS.observation, observationContent(observation))
}

export function validateAssociation(value) {
  const association = validateClosed('association.schema.json', value)
  if (association.left.tenant_id !== association.right.tenant_id
    || association.left.environment_id !== association.right.environment_id) {
    throw ocError('OC_UNAUTHORIZED', 'association cannot cross tenant or environment')
  }
  return association
}

export function validateMapping(value) {
  return validateClosed(value?.contract === 'dubsar.operational-context.mapping/2'
    ? 'mapping-v2.schema.json' : 'mapping.schema.json', value)
}

export function validateStateBinding(value) {
  return validateClosed('state-binding.schema.json', value)
}

export function validateRule(value) {
  return validateClosed('rule.schema.json', value)
}

export function validateViewRequest(value) {
  const request = validateClosed(value?.contract === 'dubsar.operational-context.view-request/2'
    ? 'view-request-v2.schema.json' : 'view-request.schema.json', value)
  if (request.resources.length > OC_BOUNDS.max_resources_per_call) {
    throw ocError('OC_BOUND_EXCEEDED', 'too many resources requested')
  }
  if (request.relation_depth > OC_BOUNDS.max_relation_depth) {
    throw ocError('OC_BOUND_EXCEEDED', 'relation depth exceeds profile')
  }
  if (request.instant !== undefined) request.instant = normalizeUtcDateTime(request.instant)
  return request
}

export function qualificationFingerprint(document) {
  return domainSeparatedHash(OC_HASH_DOMAINS.qualification, document)
}

export function assertNoInstructionExecution(value) {
  canonicalJson(value)
  return value
}
