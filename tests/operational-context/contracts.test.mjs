import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import {
  ocRegistry,
  validateClosed,
  validateObservation,
  validateTrust,
  createOperationalContextKernel,
  OC_BOUNDS,
  OC_CONTRACTS,
  ocError,
} from '../../src/operational-context/index.mjs'
import { observation } from './helpers/fixtures.mjs'

const validDir = new URL('../../fixtures/operational-context/valid/', import.meta.url)
const invalidDir = new URL('../../fixtures/operational-context/invalid/', import.meta.url)

const FILES = ['observation', 'resource', 'trust', 'mapping', 'rule', 'view-request', 'association']

test('AC01 closed schemas accept valid fixtures and reject invalid/unknown contracts', () => {
  ocRegistry.assertAllReferencesClosed()
  for (const name of FILES) {
    const valid = JSON.parse(fs.readFileSync(new URL(`${name}.json`, validDir)))
    const invalid = JSON.parse(fs.readFileSync(new URL(`${name}.json`, invalidDir)))
    validateClosed(`${name}.schema.json`, valid)
    assert.throws(() => validateClosed(`${name}.schema.json`, invalid))
  }
  assert.throws(() => validateTrust({ contract: 'dubsar.operational-context.trust/9', tenant_id: 't', environment_id: 'e', principal_id: 'p', principal_kind: 'human' }))
  assert.throws(() => validateObservation({ ...observation(), contract: 'dubsar.operational-context.observation/99' }))
})

test('AC01 kernel is importable outside a test-only interface and refuses missing authority', () => {
  assert.equal(typeof createOperationalContextKernel, 'function')
  assert.throws(() => createOperationalContextKernel({ pool: { connect() {} } }), /authorization port is required/)
  const error = ocError('OC_CONTRACT_UNKNOWN', 'nope')
  assert.equal(error.code, 'OC_CONTRACT_UNKNOWN')
  assert.equal(OC_CONTRACTS.observation, 'dubsar.operational-context.observation/1')
  assert.equal(OC_BOUNDS.observation_utf8_bytes, 65536)
})

test('AC03 proven absence is refused on a partial collection scope', () => {
  assert.throws(() => validateObservation(observation({
    result: { kind: 'proven_absence', method: 'list-complete', scope_complete: true },
    scope: { period: { start: '2026-09-18T08:00:00Z', end: '2026-09-18T12:00:00Z' }, complete: false },
  })))
})

test('AC11 oversize observation is refused before any interpretation', () => {
  assert.throws(() => validateObservation(observation({
    result: { kind: 'measured', value_type: 'string', value: 'x'.repeat(70_000) },
  })))
})

test('observe refuses mutation fields before authority or storage, for v1 and v2', async () => {
  const kernel = createOperationalContextKernel({
    pool: { connect() { throw new Error('storage must not be reached') } },
    authority: { authorize() { throw new Error('authority must not be reached') }, revalidate() {} },
  })
  const trust = JSON.parse(fs.readFileSync(new URL('trust.json', validDir)))
  for (const version of [1, 2]) {
    for (const field of ['correction_of', 'retraction_of']) {
      const payload = observation({ [field]: 'oco_antecedent' })
      if (version === 2) {
        payload.contract = 'dubsar.operational-context.observation/2'
        payload.state_order = { producer_epoch: 'epoch:test', sequence: 1 }
      }
      const result = await kernel.ingestObservation(trust, payload)
      assert.equal(result.outcome, 'rejected')
      assert.equal(result.code, 'OC_CONTRACT_INVALID')
    }
  }
})
