import assert from 'node:assert/strict'
import test from 'node:test'
import { qualifyAt, semanticQualification } from '../../src/operational-context/qualify.mjs'
import { observationFingerprint, qualificationFingerprint, validateClosed } from '../../src/operational-context/contracts.mjs'
import { resourceIdentity } from '../../src/operational-context/identity.mjs'
import { observation, resource, mapping, rule } from './helpers/fixtures.mjs'

function row(obs, extra = {}) {
  const resolved = resourceIdentity(obs.subject)
  return {
    local_ref: extra.local_ref ?? `oco_${obs.delivery_id.replaceAll(':', '')}`,
    resource_local_ref: resolved.local_ref,
    property: obs.property,
    document: obs,
    fingerprint: extra.fingerprint ?? observationFingerprint(obs),
    producer_id: obs.provenance.producer_id,
    source_instance_id: obs.subject.source_instance_id,
    correction_of: obs.correction_of,
    retraction_of: obs.retraction_of,
    mapping_ref: obs.provenance.mapping_ref,
    mapping_version: obs.provenance.mapping_version,
    ...extra,
  }
}

test('AC06 comparable conflict is not last-message-wins and is reproducible', () => {
  const aRes = resource({ source_instance_id: 'src:n8n-a' })
  const bRes = resource({ source_instance_id: 'src:n8n-b' })
  const a = observation({ subject: aRes, delivery_id: 'delivery:a', result: { kind: 'measured', value_type: 'boolean', value: true } })
  const b = observation({ subject: bRes, delivery_id: 'delivery:b', result: { kind: 'measured', value_type: 'boolean', value: false }, provenance: { ...observation().provenance, producer_id: 'producer:b' } })
  const aId = resourceIdentity(aRes).local_ref
  const bId = resourceIdentity(bRes).local_ref
  const associations = [{ association_type: 'same_resource', status: 'admitted', left_ref: aId, right_ref: bId }]
  const map = { ...mapping(), status: 'admitted' }
  const fresh = { ...rule(), status: 'admitted' }
  const instant = '2026-09-18T09:10:00.000Z'
  const first = qualifyAt({
    observations: [row(a), row(b)],
    associations,
    mapping: map,
    rule: fresh,
    instant,
    resource_ref: aId,
    property: 'enabled',
  })
  const reversed = qualifyAt({
    observations: [row(b), row(a)],
    associations,
    mapping: map,
    rule: fresh,
    instant,
    resource_ref: aId,
    property: 'enabled',
  })
  assert.equal(first.document.agreement, 'conflict')
  assert.deepEqual(semanticQualification(first.document), semanticQualification(reversed.document))
})

test('AC06 non-comparable homonyms coexist and revoked mapping limits the conclusion', () => {
  const aRes = resource({ source_instance_id: 'src:n8n-a' })
  const other = resource({ source_instance_id: 'src:crm', source_id: 'commandes', label: 'export commandes' })
  const a = observation({ subject: aRes, delivery_id: 'delivery:a' })
  const b = observation({
    subject: other,
    delivery_id: 'delivery:other',
    result: { kind: 'measured', value_type: 'boolean', value: false },
  })
  const instant = '2026-09-18T09:10:00.000Z'
  const map = { ...mapping(), status: 'admitted' }
  const fresh = { ...rule(), status: 'admitted' }
  const qualified = qualifyAt({
    observations: [row(a), row(b)],
    associations: [],
    mapping: map,
    rule: fresh,
    instant,
    resource_ref: resourceIdentity(aRes).local_ref,
    property: 'enabled',
  })
  assert.notEqual(qualified.document.agreement, 'conflict')
  const revoked = qualifyAt({
    observations: [row(a)],
    associations: [],
    mapping: { ...map, status: 'revoked' },
    rule: fresh,
    instant,
    resource_ref: resourceIdentity(aRes).local_ref,
    property: 'enabled',
  })
  assert.equal(revoked.document.admissibility, 'limited')
})

test('AC03 false, absence, impossible, partial, unknown date and stale stay distinct', () => {
  const subject = resource()
  const ref = resourceIdentity(subject).local_ref
  const map = { ...mapping(), status: 'admitted' }
  const fresh = { ...rule(), freshness_max_age_ms: 60_000, status: 'admitted' }
  const cases = [
    observation({ delivery_id: 'd-false', result: { kind: 'measured', value_type: 'boolean', value: false } }),
    observation({ delivery_id: 'd-abs', result: { kind: 'proven_absence', method: 'full-list', scope_complete: true } }),
    observation({ delivery_id: 'd-imp', result: { kind: 'collection_impossible', reason: 'timeout' } }),
    observation({ delivery_id: 'd-part', result: { kind: 'collection_partial', reason: 'page-limit' }, scope: { period: { start: '2026-09-18T08:00:00Z', end: '2026-09-18T12:00:00Z' }, complete: false } }),
    observation({ delivery_id: 'd-unk', source_observed_at: { absence: 'unknown' } }),
    observation({ delivery_id: 'd-stale', source_observed_at: '2026-09-18T08:00:00Z' }),
  ]
  const results = cases.map(item => qualifyAt({
    observations: [row({ ...item, subject })],
    associations: [],
    mapping: map,
    rule: fresh,
    instant: '2026-09-18T09:30:00.000Z',
    resource_ref: ref,
    property: 'enabled',
  }).document)
  assert.equal(results[0].coverage, 'measured')
  assert.equal(results[0].values[0].value, false)
  assert.equal(results[1].coverage, 'proven_absence')
  assert.equal(results[2].coverage, 'collection_impossible')
  assert.equal(results[3].coverage, 'collection_partial')
  assert.equal(results[4].freshness, 'unknown_source_date')
  assert.equal(results[5].freshness, 'stale')
  const signatures = results.map(item => `${item.coverage}|${item.freshness}|${item.agreement}|${JSON.stringify(item.values?.[0]?.value)}`)
  assert.equal(new Set(signatures).size, signatures.length)
})

test('T19 two incompatible corrections expose divergence rather than last writer', () => {
  const subject = resource()
  const base = observation({ subject, delivery_id: 'delivery:base' })
  const c1 = observation({
    subject,
    delivery_id: 'delivery:c1',
    correction_of: 'oco_base',
    result: { kind: 'measured', value_type: 'boolean', value: true },
  })
  const c2 = observation({
    subject,
    delivery_id: 'delivery:c2',
    correction_of: 'oco_base',
    result: { kind: 'measured', value_type: 'boolean', value: false },
  })
  const qualified = qualifyAt({
    observations: [
      row(base, { local_ref: 'oco_base' }),
      row(c1, { local_ref: 'oco_c1' }),
      row(c2, { local_ref: 'oco_c2' }),
    ],
    associations: [],
    mapping: { ...mapping(), status: 'admitted' },
    rule: { ...rule(), status: 'admitted' },
    instant: '2026-09-18T09:10:00.000Z',
    resource_ref: resourceIdentity(subject).local_ref,
    property: 'enabled',
  })
  assert.equal(qualified.document.agreement, 'divergent_corrections')
})

function correctionQualification(rows, options = {}) {
  return qualifyAt({ observations: rows, mapping: { ...mapping(), status: 'admitted' },
    rule: { ...rule(), status: 'admitted' }, instant: '2026-09-18T09:10:00.000Z',
    resource_ref: resourceIdentity(resource()).local_ref, property: 'enabled', ...options })
}

test('correction chains select the terminal assertion through retracted ancestors', () => {
  const base = row(observation(), { local_ref: 'oco_base' })
  const first = row(observation({ delivery_id: 'c1', correction_of: base.local_ref,
    result: { kind: 'measured', value_type: 'boolean', value: false } }), { local_ref: 'oco_c1' })
  const last = row(observation({ delivery_id: 'c2', correction_of: first.local_ref }), { local_ref: 'oco_c2' })
  const retract = target => row(observation({ delivery_id: `retract:${target}`, retraction_of: target }), { local_ref: `oco_r_${target}` })
  for (const rows of [[base, first, last], [base, first, last, retract(base.local_ref)],
    [base, first, last, retract(first.local_ref)], [base, first, last, retract(base.local_ref), retract(first.local_ref)]]) {
    const result = correctionQualification(rows)
    assert.deepEqual(result.document.support_refs, [last.local_ref])
    assert.deepEqual(result.document.values.map(v => v.value), [true])
    assert.equal(result.document.agreement, 'single')
    assert.deepEqual(result, correctionQualification([...rows].reverse()))
  }
  const noResurrection = correctionQualification([base, first, last, retract(base.local_ref), retract(first.local_ref), retract(last.local_ref)])
  assert.deepEqual(noResurrection.document.values, [])
  assert.equal(noResurrection.document.coverage, 'empty')
  const fallback = correctionQualification([base, first, last, retract(last.local_ref)])
  assert.deepEqual(fallback.document.support_refs, [first.local_ref])
  assert.deepEqual(fallback.document.values.map(v => v.value), [false])
})

test('retracting a superseded base preserves its correction and divergent live branches', () => {
  const base = row(observation(), { local_ref: 'oco_base' })
  const first = row(observation({ delivery_id: 'c1', correction_of: base.local_ref,
    result: { kind: 'measured', value_type: 'boolean', value: false } }), { local_ref: 'oco_c1' })
  const retract = row(observation({ delivery_id: 'r', retraction_of: base.local_ref }), { local_ref: 'oco_r' })
  const result = correctionQualification([base, first, retract])
  assert.deepEqual(result.document.support_refs, [first.local_ref])
  assert.deepEqual(result.document.values.map(v => v.value), [false])
  const branch = row(observation({ delivery_id: 'c2', correction_of: base.local_ref }), { local_ref: 'oco_c2' })
  const fork = correctionQualification([base, first, branch, retract])
  assert.equal(fork.document.agreement, 'divergent_corrections')
  assert.deepEqual(fork.document.support_refs, [first.local_ref, branch.local_ref])
  assert.deepEqual(fork, correctionQualification([retract, branch, first, base]))
})

test('incomplete support windows never certify apparent current values and are fingerprinted', () => {
  const base = row(observation(), { local_ref: 'oco_base' })
  const complete = correctionQualification([base])
  const partial = correctionQualification([base], { complete: false })
  assert.equal(partial.document.status, 'pending_recalculation')
  assert.equal(partial.document.admissibility, 'limited')
  assert.equal(partial.document.coverage, 'collection_partial')
  assert.deepEqual(partial.document.values, [])
  assert.deepEqual(partial.document.support_refs, [])
  assert.ok(partial.document.limits.some(v => v.code === 'SUPPORT_WINDOW_TRUNCATED'))
  assert.equal(partial.fingerprint, qualificationFingerprint(partial.document))
  assert.notEqual(partial.fingerprint, complete.fingerprint)
  validateClosed('qualification.schema.json', partial.document)
})
