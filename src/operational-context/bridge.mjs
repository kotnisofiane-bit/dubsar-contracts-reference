import { OC_CODES } from './errors.mjs'
import { ocError } from './errors.mjs'
import { validateTrust } from './contracts.mjs'
import {
  assertRequestBound,
  bridgeFailure,
  bridgeSuccess,
  parseBridgeRequest,
  parseJsonRequest,
  peekRequestId,
} from './bridge-protocol.mjs'

const ADMITTED_CODES = new Set(Object.values(OC_CODES))

function requireKernelPorts(kernel) {
  if (kernel === undefined || kernel === null) {
    throw ocError('OC_UNAVAILABLE', 'kernel is required')
  }
  if (typeof kernel.ingestObservation !== 'function' || typeof kernel.readView !== 'function') {
    throw ocError('OC_UNAVAILABLE', 'kernel ports are required')
  }
  if (kernel.authority === undefined || kernel.authority === null) {
    throw ocError('OC_AUTHORITY_MISSING', 'authorization port is required')
  }
}

function mapFailure(error) {
  if (ADMITTED_CODES.has(error?.code)) return error
  return ocError('OC_UNAVAILABLE', 'kernel invocation failed')
}

async function dispatch(kernel, operation, trust, payload) {
  switch (operation) {
    case 'observe':
      return kernel.ingestObservation(trust, payload)
    case 'get_context_view':
      return kernel.readView(trust, payload)
    default: {
      const exhausted = operation
      throw ocError('OC_CONTRACT_UNKNOWN', `unknown bridge operation ${exhausted}`)
    }
  }
}

export function createOperationalContextBridge({ kernel, resolveTrust } = {}) {
  requireKernelPorts(kernel)
  if (typeof resolveTrust !== 'function') {
    throw ocError('OC_AUTHORITY_MISSING', 'host trust provider is required')
  }

  return Object.freeze({
    async handle(input) {
      let peekedId = ''
      try {
        assertRequestBound(input)
        const raw = parseJsonRequest(input)
        peekedId = peekRequestId(raw)
        const request = parseBridgeRequest(raw)
        peekedId = request.request_id
        const trust = await resolveTrust({
          request_id: request.request_id,
          operation: request.operation,
        })
        if (trust === undefined || trust === null) {
          throw ocError('OC_AUTHORITY_MISSING', 'host trust is required')
        }
        validateTrust(trust)
        const result = await dispatch(kernel, request.operation, trust, request.payload)
        return bridgeSuccess(request.request_id, result)
      } catch (error) {
        return bridgeFailure(peekedId, mapFailure(error))
      }
    },
  })
}
