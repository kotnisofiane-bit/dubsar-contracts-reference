import assert from 'node:assert/strict'
import test from 'node:test'
import { observationFingerprint, qualificationFingerprint, validateObservation } from '../../../src/operational-context/contracts.mjs'
import { OC_BOUNDS } from '../../../src/operational-context/bounds.mjs'
import { aggregateKey, resourceIdentity } from '../../../src/operational-context/identity.mjs'
import { observation, resource, mapping, rule, trust, viewRequest } from '../helpers/fixtures.mjs'
import { setupKernel } from '../helpers/postgres.mjs'

function applied(result) {
  assert.equal(result.outcome, 'applied', JSON.stringify(result))
  return result
}

// Deterministic, validated synthetic journal records model a preexisting window
// without relying on UUID ordering. The production journal remains immutable.
async function insertSupports(ctx, subject, supports, receivedAt = '2026-09-18T09:05:00.000Z') {
  const data = supports.map(({ local_ref, document }) => {
    const doc = validateObservation(document)
    return { local_ref, document: doc, fingerprint: observationFingerprint(doc) }
  })
  await ctx.owner.query(`INSERT INTO dubsar_context.observations
    (local_ref,tenant_id,environment_id,resource_local_ref,property,delivery_id,measurement_absent,
     result_kind,document,fingerprint,source_observed_at,source_date_unknown,received_at,
     mapping_ref,mapping_version,rule_ref,rule_version,producer_id,source_instance_id,correction_of,retraction_of)
    SELECT s.local_ref,$1,$2,$3,s.document->>'property',s.document->>'delivery_id',true,
      s.document->'result'->>'kind',s.document,s.fingerprint,
      (s.document->>'source_observed_at')::timestamptz,false,$5::timestamptz,
      s.document->'provenance'->>'mapping_ref',(s.document->'provenance'->>'mapping_version')::integer,
      s.document->>'rule_ref',(s.document->>'rule_version')::integer,
      s.document->'provenance'->>'producer_id',s.document->'subject'->>'source_instance_id',
      s.document->>'correction_of',s.document->>'retraction_of'
    FROM jsonb_to_recordset($4::jsonb) AS s(local_ref text,document jsonb,fingerprint text)`,
  [subject.tenant_id, subject.environment_id, resourceIdentity(subject).local_ref, JSON.stringify(data), receivedAt])
}

async function published(ctx, subject, property = 'enabled') {
  const key = aggregateKey(resourceIdentity(subject).local_ref, property)
  const rows = (await ctx.owner.query(`SELECT a.status AS aggregate_status,q.status,q.document,q.fingerprint,
      c.status AS cache_status,c.document AS cache_document,c.input_fingerprint AS cache_fingerprint
    FROM dubsar_context.aggregates a JOIN dubsar_context.qualifications q ON q.local_ref=a.current_qualification_ref
    JOIN dubsar_context.derivative_cache c ON c.cache_key=a.aggregate_key
    WHERE a.tenant_id=$1 AND a.environment_id=$2 AND a.aggregate_key=$3`,
  [subject.tenant_id, subject.environment_id, key])).rows
  assert.equal(rows.length, 1)
  const row = rows[0]
  assert.equal(row.status, row.document.status)
  assert.equal(row.aggregate_status, row.document.status)
  assert.equal(row.cache_status, row.document.status === 'pending_recalculation' ? 'stale' : row.document.status)
  assert.deepEqual(row.cache_document, row.document)
  assert.equal(row.fingerprint, qualificationFingerprint(row.document))
  assert.equal(row.cache_fingerprint, row.fingerprint)
  return row
}

test('observe-only cannot persist correction or retraction fields in PostgreSQL', async t => {
  const ctx = await setupKernel(); t.after(() => ctx.close())
  const tr = trust(), subject = resource()
  const base = applied(await ctx.kernel.ingestObservation(tr, observation({ subject, delivery_id: 'mutation:base' })))
  const observer = trust({ principal_id: 'principal:observer-only', principal_kind: 'producer' })
  ctx.authority.grant({ ...observer, action: 'observe' })
  for (const field of ['correction_of', 'retraction_of']) {
    const outcome = await ctx.kernel.ingestObservation(observer, observation({ subject,
      delivery_id: `mutation:${field}`, [field]: base.observation_ref,
      provenance: { ...observation().provenance, producer_id: 'producer:b' } }))
    assert.equal(outcome.outcome, 'rejected'); assert.equal(outcome.code, 'OC_CONTRACT_INVALID')
  }
  const count = (await ctx.owner.query("SELECT count(*)::int AS n FROM dubsar_context.observations WHERE delivery_id LIKE 'mutation:%'")).rows[0].n
  assert.equal(count, 1)
})

test('chains and retracted ancestors agree across qualify, publication, cache and readView', async t => {
  const ctx = await setupKernel(); t.after(() => ctx.close())
  const tr = trust()
  applied(await ctx.kernel.admitMapping(tr, mapping())); applied(await ctx.kernel.admitRule(tr, rule()))
  async function check(subject, supportRef, value) {
    const q = await ctx.kernel.qualify(tr, { resource: subject, property: 'enabled' })
    const view = await ctx.kernel.readView(tr, viewRequest([{ local_ref: resourceIdentity(subject).local_ref }]))
    const stored = await published(ctx, subject)
    assert.deepEqual(q.document, stored.document)
    assert.equal(q.fingerprint, stored.fingerprint)
    assert.deepEqual(view.resources[0].qualifications[0].qualification, q.document)
    assert.deepEqual(q.document.support_refs, supportRef ? [supportRef] : [])
    assert.deepEqual(q.document.values.map(v => v.value), supportRef ? [value] : [])
  }
  for (const chain of [false, true]) {
    const subject = resource({ source_id: `chain:${chain}` })
    const base = applied(await ctx.kernel.ingestObservation(tr, observation({ subject, delivery_id: `chain:${chain}:base` })))
    const first = applied(await ctx.kernel.correctObservation(tr, observation({ subject, delivery_id: `chain:${chain}:c1`,
      correction_of: base.observation_ref, result: { kind: 'measured', value_type: 'boolean', value: false } })))
    let live = first.observation_ref, value = false
    if (chain) {
      live = applied(await ctx.kernel.correctObservation(tr, observation({ subject, delivery_id: 'chain:true:c2', correction_of: first.observation_ref }))).observation_ref
      value = true
    }
    await check(subject, live, value)
    applied(await ctx.kernel.retractObservation(tr, observation({ subject, delivery_id: `chain:${chain}:retract-base`, retraction_of: base.observation_ref })))
    await check(subject, live, value)
    if (chain) {
      applied(await ctx.kernel.retractObservation(tr, observation({ subject, delivery_id: 'chain:true:retract-first', retraction_of: first.observation_ref })))
      await check(subject, live, value)
    }
    applied(await ctx.kernel.retractObservation(tr, observation({ subject, delivery_id: `chain:${chain}:retract-leaf`, retraction_of: live })))
    await check(subject, null)
  }
})

test('local_ref reads disclose no foreign existence, identity, label or observation', async t => {
  const ctx = await setupKernel(); t.after(() => ctx.close())
  const tr = trust(), local = resource()
  applied(await ctx.kernel.ingestObservation(tr, observation({ subject: local })))
  assert.equal((await ctx.kernel.readView(tr, viewRequest([{ local_ref: resourceIdentity(local).local_ref }]))).resources[0].resolution, 'resolved')
  for (const scope of [{ tenant_id: 'tenant:foreign' }, { environment_id: 'env:foreign' }]) {
    const foreignTrust = trust(scope), foreign = resource({ ...scope, label: 'synthetic foreign label' })
    ctx.authority.grant({ ...foreignTrust, action: 'observe' })
    applied(await ctx.kernel.ingestObservation(foreignTrust, observation({ subject: foreign,
      delivery_id: `foreign:${Object.keys(scope)[0]}`, result: { kind: 'measured', value_type: 'string', value: 'synthetic foreign observation' } })))
    const ref = resourceIdentity(foreign).local_ref
    const view = await ctx.kernel.readView(tr, viewRequest([{ local_ref: ref }]))
    assert.deepEqual(view.resources, [{ resolution: 'unknown', requested: ref }])
    assert.equal(view.selection_receipt, 'partial')
    assert.doesNotMatch(JSON.stringify(view), /synthetic foreign|tenant:foreign|env:foreign/)
    const unknown = await ctx.kernel.readView(tr, viewRequest([{ local_ref: 'ocr_never_registered' }]))
    assert.deepEqual(view.reserves, unknown.reserves)
    assert.deepEqual(view.bounds, unknown.bounds)
    assert.deepEqual(view.associations, unknown.associations)
  }
})

function stateBundle(subject, effective_at) {
  const mapping = { contract: 'dubsar.operational-context.mapping/2', mapping_ref: 'map:state', version: 1,
    property: 'state.sha', value_type: 'string', producer_id: 'producer:state',
    source_instance_id: subject.source_instance_id, temporal_mode: 'ordered_snapshot' }
  const fresh = rule({ rule_ref: 'rule:state', freshness_max_age_ms: 900000 })
  const binding = { contract: 'dubsar.operational-context.state-binding/1', binding_ref: 'binding:state', version: 1,
    tenant_id: subject.tenant_id, environment_id: subject.environment_id,
    resource_local_ref: resourceIdentity(subject).local_ref, property: mapping.property,
    producer_id: mapping.producer_id, source_instance_id: mapping.source_instance_id, producer_epoch: 'epoch:one',
    mapping_ref: mapping.mapping_ref, mapping_version: 1, rule_ref: fresh.rule_ref, rule_version: 1,
    effective_at, legacy_observation_refs: [], supersedes: { absence: 'initial' } }
  return { binding, mapping, rule: fresh }
}
function snapshot(subject, binding, time, sequence, value, delivery_id) {
  return { ...observation({ subject, property: binding.property, delivery_id,
    result: { kind: 'measured', value_type: 'string', value }, source_observed_at: time,
    scope: { complete: true, period: { start: time, end: time } }, rule_ref: binding.rule_ref, rule_version: binding.rule_version,
    provenance: { producer_id: binding.producer_id, connector_revision: 'synthetic/1', mapping_ref: binding.mapping_ref, mapping_version: binding.mapping_version } }),
    contract: 'dubsar.operational-context.observation/2', state_order: { producer_epoch: binding.producer_epoch, sequence } }
}
async function stateView(ctx, subject, instant) {
  const view = await ctx.kernel.readView(trust(), { ...viewRequest([{ local_ref: resourceIdentity(subject).local_ref }],
    { properties: ['state.sha'], ...(instant ? { instant } : {}) }), contract: 'dubsar.operational-context.view-request/2' })
  return view.resources[0].qualifications[0].state_projection
}

for (const kind of ['rule', 'epoch', 'producer', 'mapping']) {
  test(`admitted ${kind} rotation recognizes history but rejects old tuples after cutover`, async t => {
    let now = '2026-09-21T11:00:00.000Z'
    const ctx = await setupKernel({ clock: { now: () => now } }); t.after(() => ctx.close())
    const tr = trust(), subject = resource(), bundle = stateBundle(subject, now)
    ctx.authority.grant({ ...tr, action: 'admit_state_policy' })
    applied(await ctx.kernel.admitStatePolicy(tr, bundle))
    now = '2026-09-21T11:00:01.000Z'
    const oldDoc = snapshot(subject, bundle.binding, now, 1, 'a'.repeat(40), 'state:old')
    const old = applied(await ctx.kernel.ingestObservation(tr, oldDoc))
    now = '2026-09-21T11:00:02.000Z'
    const next = structuredClone(bundle)
    next.binding.version = 2; next.binding.effective_at = now
    next.binding.supersedes = { binding_ref: bundle.binding.binding_ref, version: 1 }
    if (kind === 'rule') { next.binding.rule_version = 2; next.rule.version = 2 }
    if (kind === 'epoch') next.binding.producer_epoch = 'epoch:two'
    if (kind === 'producer') { next.binding.producer_id = 'producer:next'; next.mapping.producer_id = next.binding.producer_id }
    if (kind === 'producer' || kind === 'mapping') { next.binding.mapping_version = 2; next.mapping.version = 2 }
    applied(await ctx.kernel.admitStatePolicy(tr, next))
    assert.equal((await stateView(ctx, subject)).candidate, null)
    now = '2026-09-21T11:00:03.000Z'
    const current = applied(await ctx.kernel.ingestObservation(tr, snapshot(subject, next.binding, now, 1, 'b'.repeat(40), 'state:new')))
    const projection = await stateView(ctx, subject)
    assert.equal(projection.eligible, true); assert.equal(projection.candidate.observation_ref, current.observation_ref)
    assert.equal(projection.history.find(x => x.observation_ref === old.observation_ref).classification, 'previous')
    assert.deepEqual(projection.limits, [])
    assert.equal((await stateView(ctx, subject, '2026-09-21T11:00:01.000Z')).candidate.observation_ref, old.observation_ref)
    assert.equal((await ctx.kernel.ingestObservation(tr, { ...oldDoc, delivery_id: 'state:old-after-cutover' })).outcome, 'rejected')
    // Even a valid old tuple in legacy/corrupt storage cannot be classified as
    // admitted history when it arrived after its generation was superseded.
    await insertSupports(ctx, subject, [{ local_ref: 'oco_unadmitted_after_cutover', document: { ...oldDoc, delivery_id: 'state:unadmitted' } }], now)
    const blocked = await stateView(ctx, subject)
    assert.equal(blocked.eligible, false); assert.equal(blocked.candidate, null)
    assert.ok(blocked.limits.some(x => ['STATE_LINEAGE_UNRECOGNIZED', 'STATE_POLICY_MISMATCH'].includes(x.code)))
  })
}

for (const kind of ['binding', 'mapping', 'rule']) {
  test(`supports received while ${kind} was revoked stay blocking after rotation`, async t => {
    let now = '2026-09-21T11:00:00.000Z'
    const ctx = await setupKernel({ clock: { now: () => now } }); t.after(() => ctx.close())
    const tr = trust(), subject = resource(), bundle = stateBundle(subject, now)
    for (const action of ['admit_state_policy', 'revoke_state_policy']) ctx.authority.grant({ ...tr, action })
    applied(await ctx.kernel.admitStatePolicy(tr, bundle))
    now = '2026-09-21T11:00:01.000Z'
    const oldDoc = snapshot(subject, bundle.binding, now, 1, 'a'.repeat(40), 'state:valid')
    applied(await ctx.kernel.ingestObservation(tr, oldDoc))
    now = '2026-09-21T11:00:02.000Z'
    const revoke = { binding: 'revokeStatePolicy', mapping: 'revokeMapping', rule: 'revokeRule' }[kind]
    applied(await ctx.kernel[revoke](tr, bundle[kind]))
    now = '2026-09-21T11:00:02.500Z'
    assert.equal((await ctx.kernel.ingestObservation(tr, { ...oldDoc, delivery_id: 'state:revoked-at-receipt' })).outcome, 'rejected')
    await insertSupports(ctx, subject, [{ local_ref: 'oco_revoked_at_receipt', document: { ...oldDoc, delivery_id: 'state:synthetic-revoked' } }], now)
    now = '2026-09-21T11:00:03.000Z'
    const next = { ...bundle, rule: { ...bundle.rule, version: 2 }, binding: { ...bundle.binding,
      version: 2, rule_version: 2, effective_at: now, supersedes: { binding_ref: bundle.binding.binding_ref, version: 1 } } }
    applied(await ctx.kernel.admitStatePolicy(tr, next))
    now = '2026-09-21T11:00:04.000Z'
    applied(await ctx.kernel.ingestObservation(tr, snapshot(subject, next.binding, now, 1, 'b'.repeat(40), 'state:current')))
    const blocked = await stateView(ctx, subject)
    assert.equal(blocked.eligible, false); assert.equal(blocked.candidate, null)
    assert.ok(blocked.limits.some(x => x.code === 'STATE_POLICY_MISMATCH'))
  })
}

test('source identity rotation needs a new local_ref and its own admitted binding', async t => {
  let now = '2026-09-21T11:00:00.000Z'
  const ctx = await setupKernel({ clock: { now: () => now } }); t.after(() => ctx.close())
  const tr = trust(), original = resource(), next = resource({ source_instance_id: 'src:next' })
  ctx.authority.grant({ ...tr, action: 'admit_state_policy' })
  const originalBundle = stateBundle(original, now)
  applied(await ctx.kernel.admitStatePolicy(tr, originalBundle))
  now = '2026-09-21T11:00:01.000Z'
  applied(await ctx.kernel.ingestObservation(tr, snapshot(original, originalBundle.binding, now, 1, 'a'.repeat(40), 'source:old')))
  assert.notEqual(resourceIdentity(original).local_ref, resourceIdentity(next).local_ref)
  const nextBundle = stateBundle(next, now)
  nextBundle.mapping = { ...nextBundle.mapping, mapping_ref: 'map:next-source' }
  nextBundle.binding = { ...nextBundle.binding, binding_ref: 'binding:next-source', mapping_ref: nextBundle.mapping.mapping_ref }
  const doc = snapshot(next, nextBundle.binding, now, 1, 'b'.repeat(40), 'source:new')
  assert.equal((await ctx.kernel.ingestObservation(tr, doc)).outcome, 'rejected')
  applied(await ctx.kernel.admitStatePolicy(tr, nextBundle))
  applied(await ctx.kernel.ingestObservation(tr, doc))
  assert.equal((await stateView(ctx, original)).candidate.value, 'a'.repeat(40))
  assert.equal((await stateView(ctx, next)).candidate.value, 'b'.repeat(40))
})

test('future cutover uses admission at receipt and leaves unknown post-cutover v1 blocking', async t => {
  let now = '2026-09-21T11:00:00.000Z'
  const ctx = await setupKernel({ clock: { now: () => now } }); t.after(() => ctx.close())
  const tr = trust(), subject = resource(), bundle = stateBundle(subject, now)
  ctx.authority.grant({ ...tr, action: 'admit_state_policy' })
  applied(await ctx.kernel.admitStatePolicy(tr, bundle))
  now = '2026-09-21T11:00:01.000Z'
  applied(await ctx.kernel.ingestObservation(tr, snapshot(subject, bundle.binding, now, 1, 'a'.repeat(40), 'future:old')))
  now = '2026-09-21T11:00:02.000Z'
  const next = { ...bundle, binding: { ...bundle.binding, version: 2, producer_epoch: 'epoch:two',
    effective_at: '2026-09-21T11:00:05.000Z', supersedes: { binding_ref: bundle.binding.binding_ref, version: 1 } } }
  applied(await ctx.kernel.admitStatePolicy(tr, next))
  now = '2026-09-21T11:00:03.000Z'
  applied(await ctx.kernel.ingestObservation(tr, snapshot(subject, bundle.binding, now, 2, 'a'.repeat(40), 'future:still-old')))
  assert.equal((await ctx.kernel.ingestObservation(tr, snapshot(subject, next.binding, now, 1, 'b'.repeat(40), 'future:too-early'))).outcome, 'rejected')
  assert.equal((await stateView(ctx, subject)).eligible, true)
  now = '2026-09-21T11:00:06.000Z'
  applied(await ctx.kernel.ingestObservation(tr, snapshot(subject, next.binding, now, 1, 'b'.repeat(40), 'future:current')))
  assert.equal((await stateView(ctx, subject)).eligible, true)
  assert.equal((await stateView(ctx, subject, '2026-09-21T11:00:03.000Z')).binding_version, 1)
  const v1 = snapshot(subject, next.binding, now, 2, 'c'.repeat(40), 'future:unlisted-v1')
  v1.contract = 'dubsar.operational-context.observation/1'; delete v1.state_order
  applied(await ctx.kernel.ingestObservation(tr, v1))
  const blocked = await stateView(ctx, subject)
  assert.equal(blocked.eligible, false); assert.equal(blocked.candidate, null)
  assert.ok(blocked.limits.some(x => x.code === 'STATE_LINEAGE_UNRECOGNIZED'))
})

for (const baseInside of [true, false]) {
  test(`correction beyond a full support window fails closed with base ${baseInside ? 'at the boundary' : 'outside'}`, async t => {
    const ctx = await setupKernel(); t.after(() => ctx.close())
    const tr = trust(), subject = resource(), ref = resourceIdentity(subject).local_ref
    await ctx.kernel.registerResource(tr, subject)
    applied(await ctx.kernel.admitMapping(tr, mapping())); applied(await ctx.kernel.admitRule(tr, rule()))
    const size = OC_BOUNDS.max_observations_examined
    const baseRef = baseInside ? `aaa_${String(size - 1).padStart(32, '0')}` : 'oco_base_outside'
    const fillers = Array.from({ length: baseInside ? size - 1 : size }, (_, i) => ({
      local_ref: `aaa_${String(i).padStart(32, '0')}`, document: observation({ subject, delivery_id: `window:filler:${i}` }) }))
    await insertSupports(ctx, subject, [...fillers, { local_ref: baseRef, document: observation({ subject, delivery_id: 'window:base' }) }])
    const before = await ctx.kernel.qualify(tr, { resource: subject, property: 'enabled' })
    const requestedLimits = []
    const list = ctx.kernel.store.listObservationsPage.bind(ctx.kernel.store)
    ctx.kernel.store.listObservationsPage = (...args) => { requestedLimits.push(args.at(-1).limit); return list(...args) }
    const correction = applied(await ctx.kernel.correctObservation(tr, observation({ subject, delivery_id: 'window:correction',
      correction_of: baseRef, result: { kind: 'measured', value_type: 'boolean', value: false } })))
    const lexical = (await ctx.owner.query('SELECT local_ref FROM dubsar_context.observations WHERE resource_local_ref=$1 ORDER BY local_ref LIMIT $2', [ref, size])).rows
    assert.equal(lexical.length, size)
    assert.equal(lexical.some(x => x.local_ref === baseRef), baseInside)
    assert.equal(lexical.some(x => x.local_ref === correction.observation_ref), false)
    const stored = await published(ctx, subject)
    const q = await ctx.kernel.qualify(tr, { resource: subject, property: 'enabled' })
    assert.equal(ctx.kernel.faults.rawSupportsExamined, size)
    const view = await ctx.kernel.readView(tr, viewRequest([{ local_ref: ref }]))
    assert.equal(ctx.kernel.faults.rawSupportsExamined, size)
    assert.equal(view.selection_receipt, 'partial'); assert.equal(view.bounds.truncated, true)
    for (const doc of [stored.document, q.document, view.resources[0].qualifications[0].qualification]) {
      assert.equal(doc.status, 'pending_recalculation'); assert.equal(doc.admissibility, 'limited')
      assert.ok(doc.limits.some(x => x.code === 'SUPPORT_WINDOW_TRUNCATED'))
      assert.deepEqual(doc.values, []); assert.deepEqual(doc.support_refs, [])
    }
    assert.deepEqual(q.document, stored.document); assert.equal(q.fingerprint, stored.fingerprint)
    if (baseInside) assert.notEqual(before.fingerprint, q.fingerprint)
    assert.ok(requestedLimits.every(limit => limit <= size + 1))
    assert.ok(requestedLimits.length >= 3)
    // More out-of-window mutations and a rebuild cannot restore an old head.
    applied(await ctx.kernel.correctObservation(tr, observation({ subject, delivery_id: 'window:chain', correction_of: correction.observation_ref })))
    applied(await ctx.kernel.retractObservation(tr, observation({ subject, delivery_id: 'window:retract-base', retraction_of: baseRef })))
    await ctx.kernel.rebuildDerivatives(tr)
    assert.equal((await published(ctx, subject)).document.status, 'pending_recalculation')
  })
}
