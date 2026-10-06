import test from 'node:test'
import assert from 'node:assert/strict'
import { projectState, STATE_OBSERVATION_CONTRACT } from '../../src/operational-context/state-projection.mjs'
import { canonicalJson } from '../../src/canonical-json.mjs'
import { validateClosed } from '../../src/operational-context/contracts.mjs'

const shaA = 'a'.repeat(40), shaB = 'b'.repeat(40)
const baseTime = Date.parse('2026-09-21T10:00:00Z')
const time = ms => new Date(baseTime + ms).toISOString()
const binding = {
  binding_ref: 'binding:state', version: 1, status: 'admitted', effective_at: time(-3600000),
  tenant_id: 'tenant:lab', environment_id: 'env:lab', resource_local_ref: 'ocr_state',
  property: 'mywork.release.current_sha', producer_id: 'producer:mywork-release',
  source_instance_id: 'instance:mywork-v1', producer_epoch: 'epoch:first',
  mapping_ref: 'mapping:state', mapping_version: 1, rule_ref: 'rule:state', rule_version: 1,
  legacy_observation_refs: [],
}
const mapping = { ...binding, temporal_mode: 'ordered_snapshot', value_type: 'string', version: 1 }
const rule = { rule_ref: 'rule:state', version: 1, status: 'admitted', freshness_max_age_ms: 900000 }
function row(sequence, value = shaA, sourceMs = sequence * 1000, receivedMs = sourceMs + 100) {
  return {
    local_ref: `oco_${sequence}`, tenant_id: binding.tenant_id, environment_id: binding.environment_id,
    resource_local_ref: binding.resource_local_ref, property: binding.property,
    producer_id: binding.producer_id, source_instance_id: binding.source_instance_id,
    received_at: time(receivedMs),
    document: {
      contract: STATE_OBSERVATION_CONTRACT, subject: { source_instance_id: binding.source_instance_id },
      property: binding.property, result: { kind: 'measured', value_type: 'string', value },
      provenance: { producer_id: binding.producer_id, mapping_ref: binding.mapping_ref, mapping_version: 1 },
      rule_ref: binding.rule_ref, rule_version: 1,
      source_observed_at: time(sourceMs), scope: { complete: true, period: { start: time(sourceMs), end: time(sourceMs) } },
      state_order: { producer_epoch: binding.producer_epoch, sequence },
    },
  }
}
function view(observations, overrides = {}) {
  return projectState({ observations, binding, mapping, rule, resource_ref: binding.resource_local_ref,
    property: binding.property, instant: time(10000), complete: true, ...overrides })
}

test('non-measured legacy and malformed historical v2 retain result kind without inventing a value', () => {
  const legacy = row(1);
  legacy.document.contract = 'dubsar.operational-context.observation/1';
  delete legacy.document.state_order;
  legacy.document.result = { kind: 'collection_impossible', reason: 'unavailable' };
  const result = view([legacy, row(2)], { binding: { ...binding, legacy_observation_refs: [legacy.local_ref] } });
  assert.doesNotThrow(() => canonicalJson(result));
  assert.equal(result.history[0].result_kind, 'collection_impossible');
  assert.equal(Object.hasOwn(result.history[0], 'value'), false);
  const historical = row(1);
  historical.document.result = { kind: 'collection_impossible', reason: 'unavailable' };
  const blocked = view([historical]);
  assert.equal(blocked.eligible, false);
  assert.doesNotThrow(() => canonicalJson(blocked));
  assert.ok(blocked.limits.some(x => x.code === 'STATE_SNAPSHOT_INVALID'));
});

test('ordered snapshots retain history and are independent of arrival and local_ref order', () => {
  const a = row(1), b = row(2, shaB)
  a.local_ref = 'oco_z'; b.local_ref = 'oco_a'
  assert.deepEqual(view([a,b]), view([b,a]))
  const result = view([b,a])
  assert.doesNotThrow(() => validateClosed('state-projection.schema.json', result))
  assert.equal(result.candidate.value, shaB)
  assert.equal(result.eligible, true)
  assert.equal(result.history[0].classification, 'previous')
  assert.equal(a.document.result.value, shaA)
})
test('late delivery and duplicates cannot refresh the selected source date', () => {
  const a = row(1, shaA, 1000, 8000), b = row(2, shaB, 2000, 2500)
  const copy = structuredClone(b); copy.local_ref = 'oco_dup'; copy.received_at = time(9000)
  const result = view([a,b,copy])
  assert.equal(result.age_ms, 8000)
  assert.equal(result.candidate.value, shaB)
  assert.equal(result.history.filter(v => v.classification === 'same_snapshot').length, 1)
})
test('same sequence divergence stays blocking after a higher sequence', () => {
  const a = row(1), conflict = row(1, shaB), newer = row(2, shaB)
  conflict.local_ref = 'oco_conflict'
  const result = view([a,conflict,newer])
  assert.equal(result.candidate, null)
  assert.equal(result.eligible, false)
  assert.ok(result.limits.some(v => v.code === 'STATE_SEQUENCE_CONFLICT'))
  assert.equal(result.history.length, 3)
  assert.equal(result.history.filter(v => v.classification === 'sequence_conflict').length, 2)
  assert.equal(result.history.find(v => v.observation_ref === newer.local_ref).classification, 'blocked_head')
  assert.equal(view([a, conflict]).history.length, 2)
  const incomplete = view([a], { complete: false })
  assert.equal(incomplete.candidate, null)
  assert.equal(incomplete.history[0].observation_ref, a.local_ref)
})
test('exact TTL boundary; historical staleness does not contaminate the head', () => {
  const a = row(1, shaA, -3600000), b = row(2, shaB, 0, 0)
  for (const [age,expected] of [[0,'current'],[900000,'current'],[900001,'stale']]) {
    const result = view([a,b], { instant: time(age) })
    assert.equal(result.freshness, expected)
    assert.equal(result.candidate.value, shaB)
    assert.equal(result.eligible, expected === 'current')
  }
})
test('binding, rule and mapping are explicit; missing or revoked cannot authorize', () => {
  for (const override of [{binding:null},{rule:null},{mapping:null},
    {rule:{...rule,status:'revoked'}},{mapping:{...mapping,version:2}}]) {
    const result = view([row(1)],override)
    assert.equal(result.eligible,false)
    assert.ok(result.limits.length)
  }
})
test('legacy refs are explicit and unknown v1 after cutover blocks', () => {
  const old = row(1); old.local_ref='oco_old';old.document.contract='dubsar.operational-context.observation/1'
  delete old.document.state_order
  const b={...binding,legacy_observation_refs:['oco_old']}
  assert.equal(view([old,row(2,shaB)],{binding:b}).eligible,true)
  assert.equal(view([old,row(2,shaB)]).eligible,false)
  assert.equal(view([old],{binding:b}).candidate,null)
})
test('future, regressing or unknown source clocks block; equal clocks use sequence', () => {
  const future=row(1,shaA,2000,1000)
  assert.equal(view([future]).eligible,false)
  const unknown=row(1);unknown.document.source_observed_at={absence:'unknown'}
  assert.equal(view([unknown]).freshness,'unknown_source_date')
  assert.equal(view([row(1,shaA,3000),row(2,shaB,1000)]).eligible,false)
  assert.equal(view([row(1,shaA,1000),row(2,shaB,1000)]).candidate.value,shaB)
})
test('other epochs, sources, corrections and incomplete pages never fabricate a head', () => {
  const epoch=row(1);epoch.document.state_order.producer_epoch='epoch:other'
  const producer=row(1);producer.producer_id='producer:other'
  const correction=row(1);correction.document.correction_of='oco_ancestor'
  for(const observations of [[epoch],[producer],[correction]])assert.equal(view(observations).eligible,false)
  assert.equal(view([row(1)],{complete:false}).candidate,null)
})
test('historical views exclude observations received later and future bindings', () => {
  const a=row(1,shaA,1000,1100),b=row(2,shaB,2000,20000)
  assert.equal(view([a,b]).candidate.value,shaA)
  assert.equal(view([a,b],{instant:time(21000)}).candidate.value,shaB)
  assert.equal(view([a],{binding:{...binding,effective_at:time(11000)}}).candidate,null)
})

test('only certified superseded supports stop blocking rule, epoch and producer rotations', () => {
  for (const kind of ['rule', 'epoch', 'producer', 'source']) {
    const old = row(1, shaA), next = row(2, shaB)
    const b = { ...binding, version: 2 }, m = { ...mapping }, r = { ...rule }
    if (kind === 'rule') { b.rule_version = 2; r.version = 2; next.document.rule_version = 2 }
    if (kind === 'epoch') { b.producer_epoch = 'epoch:second'; next.document.state_order.producer_epoch = b.producer_epoch }
    if (kind === 'producer') { b.producer_id = 'producer:next'; m.producer_id = b.producer_id; next.producer_id = b.producer_id; next.document.provenance.producer_id = b.producer_id }
    if (kind === 'source') { b.source_instance_id = 'instance:next'; m.source_instance_id = b.source_instance_id; next.source_instance_id = b.source_instance_id; next.document.subject.source_instance_id = b.source_instance_id }
    const options = { binding: b, mapping: m, rule: r }
    const unknown = view([old, next], options)
    assert.equal(unknown.eligible, false)
    assert.equal(unknown.candidate, null)
    const certified = view([old, next], { ...options, superseded_observation_refs: [old.local_ref] })
    assert.equal(certified.eligible, true)
    assert.equal(certified.candidate.value, shaB)
    assert.equal(certified.history[0].classification, 'previous')
    validateClosed('state-projection.schema.json', certified)
    const rogue = row(3); rogue.document.state_order.producer_epoch = 'epoch:never-admitted'
    const blocked = view([old, next, rogue], { ...options, superseded_observation_refs: [old.local_ref] })
    assert.equal(blocked.eligible, false)
    assert.equal(blocked.candidate, null)
    assert.ok(blocked.limits.some(v => v.code === 'STATE_LINEAGE_UNRECOGNIZED'))
    assert.equal(view([old, next], { ...options, superseded_observation_refs: [old.local_ref], complete: false }).candidate, null)
  }
})
