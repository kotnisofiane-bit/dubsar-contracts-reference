import { OC_BOUNDS } from './bounds.mjs'
import { OC_CODES, ocError } from './errors.mjs'

export const OC_BRIDGE_CONTRACTS = Object.freeze({
  request: 'dubsar.operational-context.bridge-request/1',
  response: 'dubsar.operational-context.bridge-response/1',
})

export const OC_BRIDGE_OPERATIONS = Object.freeze(['observe', 'get_context_view'])

export const OC_BRIDGE_BOUNDS = Object.freeze({
  version: 1,
  request_id_min_length: 1,
  request_id_max_length: 128,
  max_request_utf8_bytes: OC_BOUNDS.max_response_utf8_bytes,
  max_response_utf8_bytes: OC_BOUNDS.max_response_utf8_bytes,
  max_error_message_length: 256,
})

const REQUEST_KEYS = Object.freeze(['contract', 'version', 'request_id', 'operation', 'payload'])
const FORBIDDEN_CLIENT_KEYS = Object.freeze([
  'trust',
  'tenant_id',
  'environment_id',
  'principal_id',
  'grants',
  'permissions',
  'dsn',
  'credentials',
  'authority',
  'connection_string',
  'password',
  'secret',
])

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:~-]{1,128}$/

export const OC_BRIDGE_PUBLIC_MESSAGES = Object.freeze({
  [OC_CODES.OC_CONTRACT_UNKNOWN]: 'unknown contract',
  [OC_CODES.OC_CONTRACT_INVALID]: 'invalid contract',
  [OC_CODES.OC_BOUND_EXCEEDED]: 'bound exceeded',
  [OC_CODES.OC_UNAUTHORIZED]: 'authorization denied',
  [OC_CODES.OC_AUTHORITY_UNAVAILABLE]: 'authority unavailable',
  [OC_CODES.OC_AUTHORITY_MISSING]: 'authority missing',
  [OC_CODES.OC_REFUSED]: 'refused',
  [OC_CODES.OC_INTEGRITY_CONFLICT]: 'integrity conflict',
  [OC_CODES.OC_VERSION_CONFLICT]: 'version conflict',
  [OC_CODES.OC_UNAVAILABLE]: 'unavailable',
  [OC_CODES.OC_AMBIGUOUS]: 'ambiguous',
  [OC_CODES.OC_STALE_DERIVATIVE]: 'stale derivative',
  [OC_CODES.OC_INJECTION_REFUSED]: 'injection refused',
})

for (const code of Object.values(OC_CODES)) {
  if (!Object.hasOwn(OC_BRIDGE_PUBLIC_MESSAGES, code)) {
    throw new TypeError(`missing public bridge message for ${code}`)
  }
}

export function utf8Bytes(value) {
  if (typeof value === 'string') return Buffer.byteLength(value, 'utf8')
  if (Buffer.isBuffer(value)) return value.length
  return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

export function assertRequestBound(input) {
  try {
    const bytes = utf8Bytes(input)
    if (bytes > OC_BRIDGE_BOUNDS.max_request_utf8_bytes) {
      throw ocError('OC_BOUND_EXCEEDED', 'request exceeds UTF-8 bound', { bytes, limit: OC_BRIDGE_BOUNDS.max_request_utf8_bytes })
    }
    return bytes
  } catch (error) {
    if (error?.code === 'OC_BOUND_EXCEEDED') throw error
    throw ocError('OC_CONTRACT_INVALID', 'request is not serializable')
  }
}

export function peekRequestId(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return ''
  if (typeof value.request_id !== 'string') return ''
  if (!REQUEST_ID_PATTERN.test(value.request_id)) return ''
  return value.request_id
}

export function parseJsonRequest(input) {
  if (typeof input === 'string' || Buffer.isBuffer(input)) {
    const text = typeof input === 'string' ? input : input.toString('utf8')
    try {
      return JSON.parse(text)
    } catch {
      throw ocError('OC_CONTRACT_INVALID', 'malformed JSON')
    }
  }
  return input
}

function rejectForbiddenKeys(keys, layer) {
  const injected = keys.filter(key => FORBIDDEN_CLIENT_KEYS.includes(key))
  if (injected.length > 0) {
    throw ocError('OC_INJECTION_REFUSED', `${layer} must not control authority fields`)
  }
}

export function parseBridgeRequest(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw ocError('OC_CONTRACT_INVALID', 'request must be an object')
  }
  const keys = Object.keys(input)
  rejectForbiddenKeys(keys, 'request')
  const unknown = keys.filter(key => !REQUEST_KEYS.includes(key))
  if (unknown.length > 0) {
    throw ocError('OC_CONTRACT_UNKNOWN', 'unknown request field')
  }
  for (const key of REQUEST_KEYS) {
    if (!Object.hasOwn(input, key)) {
      throw ocError('OC_CONTRACT_INVALID', `${key} is required`)
    }
  }
  if (input.contract !== OC_BRIDGE_CONTRACTS.request) {
    throw ocError('OC_CONTRACT_UNKNOWN', 'unknown bridge request contract')
  }
  if (input.version !== OC_BRIDGE_BOUNDS.version) {
    throw ocError('OC_VERSION_CONFLICT', 'unsupported bridge version')
  }
  if (typeof input.request_id !== 'string' || !REQUEST_ID_PATTERN.test(input.request_id)) {
    throw ocError('OC_CONTRACT_INVALID', 'request_id is not an admitted token')
  }
  if (!OC_BRIDGE_OPERATIONS.includes(input.operation)) {
    throw ocError('OC_CONTRACT_UNKNOWN', 'unknown bridge operation')
  }
  if (input.payload === null || typeof input.payload !== 'object' || Array.isArray(input.payload)) {
    throw ocError('OC_CONTRACT_INVALID', 'payload must be an object')
  }
  rejectForbiddenKeys(Object.keys(input.payload), 'payload')
  return {
    contract: input.contract,
    version: input.version,
    request_id: input.request_id,
    operation: input.operation,
    payload: input.payload,
  }
}

export function publicErrorMessage(code) {
  if (Object.hasOwn(OC_BRIDGE_PUBLIC_MESSAGES, code)) return OC_BRIDGE_PUBLIC_MESSAGES[code]
  return OC_BRIDGE_PUBLIC_MESSAGES[OC_CODES.OC_UNAVAILABLE]
}

export function sanitizeErrorMessage(_error, code) {
  return publicErrorMessage(code)
}

export function bridgeSuccess(requestId, result) {
  const response = {
    contract: OC_BRIDGE_CONTRACTS.response,
    version: OC_BRIDGE_BOUNDS.version,
    request_id: requestId,
    ok: true,
    result,
  }
  const bytes = utf8Bytes(response)
  if (bytes > OC_BRIDGE_BOUNDS.max_response_utf8_bytes) {
    return bridgeFailure(requestId, ocError('OC_BOUND_EXCEEDED', 'response exceeds UTF-8 bound'))
  }
  return response
}

export function bridgeFailure(requestId, error) {
  const code = typeof error?.code === 'string' && error.code.startsWith('OC_') ? error.code : 'OC_UNAVAILABLE'
  return {
    contract: OC_BRIDGE_CONTRACTS.response,
    version: OC_BRIDGE_BOUNDS.version,
    request_id: typeof requestId === 'string' && REQUEST_ID_PATTERN.test(requestId) ? requestId : '',
    ok: false,
    error: {
      code,
      message: sanitizeErrorMessage(error, code),
    },
  }
}
