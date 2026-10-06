import assert from 'node:assert/strict'
import test from 'node:test'
import { compareUtc, normalizeUtcDateTime, sourceInstant } from '../../src/operational-context/time.mjs'

test('AC03 UTC normalization prevents lexical inversion between values with and without milliseconds', () => {
  const withMs = normalizeUtcDateTime('2026-09-18T10:00:00.000Z')
  const without = normalizeUtcDateTime('2026-09-18T10:00:00Z')
  const earlierMs = normalizeUtcDateTime('2026-09-18T10:00:00.001Z')
  assert.equal(withMs, without)
  assert.equal(compareUtc('2026-09-18T10:00:00Z', '2026-09-18T10:00:00.000Z'), 0)
  assert.equal(compareUtc('2026-09-18T10:00:00Z', '2026-09-18T10:00:00.001Z'), -1)
  assert.ok(without < earlierMs)
  assert.equal(sourceInstant({ absence: 'unknown' }).kind, 'unknown')
})
