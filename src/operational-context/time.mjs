import { ocError } from './errors.mjs'

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/

function pad(value, width) {
  return String(value).padStart(width, '0')
}

/** Normalize an RFC 3339 instant to millisecond UTC so lexical order matches chronology. */
export function normalizeUtcDateTime(value) {
  if (typeof value !== 'string' || !RFC3339.test(value)) {
    throw ocError('OC_CONTRACT_INVALID', 'date-time is not RFC 3339')
  }
  const epoch = Date.parse(value)
  if (!Number.isFinite(epoch)) throw ocError('OC_CONTRACT_INVALID', 'date-time is not a finite instant')
  const date = new Date(epoch)
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1, 2)}-${pad(date.getUTCDate(), 2)}T${pad(date.getUTCHours(), 2)}:${pad(date.getUTCMinutes(), 2)}:${pad(date.getUTCSeconds(), 2)}.${pad(date.getUTCMilliseconds(), 3)}Z`
}

export function epochMs(value) {
  return Date.parse(normalizeUtcDateTime(value))
}

export function compareUtc(left, right) {
  const a = normalizeUtcDateTime(left)
  const b = normalizeUtcDateTime(right)
  if (a < b) return -1
  if (a > b) return 1
  return 0
}

export function sourceInstant(value) {
  if (value === undefined || value === null) return { kind: 'unknown' }
  if (typeof value === 'object' && !Array.isArray(value) && value.absence === 'unknown') return { kind: 'unknown' }
  return { kind: 'known', normalized: normalizeUtcDateTime(value), epoch_ms: epochMs(value) }
}

export function nowIso(clock) {
  if (clock === undefined || typeof clock.now !== 'function') {
    throw ocError('OC_CONTRACT_INVALID', 'clock.now is required')
  }
  return normalizeUtcDateTime(clock.now())
}
