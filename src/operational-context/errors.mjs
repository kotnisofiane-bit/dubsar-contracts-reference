export const OC_CODES = Object.freeze({
  OC_CONTRACT_UNKNOWN: 'OC_CONTRACT_UNKNOWN',
  OC_CONTRACT_INVALID: 'OC_CONTRACT_INVALID',
  OC_BOUND_EXCEEDED: 'OC_BOUND_EXCEEDED',
  OC_UNAUTHORIZED: 'OC_UNAUTHORIZED',
  OC_AUTHORITY_UNAVAILABLE: 'OC_AUTHORITY_UNAVAILABLE',
  OC_AUTHORITY_MISSING: 'OC_AUTHORITY_MISSING',
  OC_REFUSED: 'OC_REFUSED',
  OC_INTEGRITY_CONFLICT: 'OC_INTEGRITY_CONFLICT',
  OC_VERSION_CONFLICT: 'OC_VERSION_CONFLICT',
  OC_UNAVAILABLE: 'OC_UNAVAILABLE',
  OC_AMBIGUOUS: 'OC_AMBIGUOUS',
  OC_STALE_DERIVATIVE: 'OC_STALE_DERIVATIVE',
  OC_INJECTION_REFUSED: 'OC_INJECTION_REFUSED',
})

export function ocError(code, message = code, extra = {}) {
  const known = OC_CODES[code]
  if (known === undefined) throw new TypeError('unknown operational-context error code')
  return Object.assign(new Error(message), { code: known, ...extra })
}

export function isOcError(error, code) {
  return error instanceof Error && error.code === code
}
