import test from 'node:test'
import assert from 'node:assert/strict'
import { setupKernel } from '../helpers/postgres.mjs'
import { observation, resource, trust } from '../helpers/fixtures.mjs'
import { resourceIdentity } from '../../../src/operational-context/identity.mjs'

test('state policy is explicit, authorized, immutable, historical and fail-closed', async t => {
  let now = '2026-09-21T10:00:00.000Z'
  const ctx = await setupKernel({ clock: { now: () => now } })
  t.after(() => ctx.close())
  const tr = trust(), subject = resource(), ref = resourceIdentity(subject).local_ref
  const mapping = { contract: 'dubsar.operational-context.mapping/2', mapping_ref: 'mapping:state', version: 1,
    property: 'mywork.release.current_sha', value_type: 'string', producer_id: 'producer:mywork-release',
    source_instance_id: subject.source_instance_id, temporal_mode: 'ordered_snapshot' }
  const rule = { contract: 'dubsar.operational-context.rule/1', rule_ref: 'rule:state', version: 1, freshness_max_age_ms: 900000 }
  const binding = { contract: 'dubsar.operational-context.state-binding/1', binding_ref: 'binding:state', version: 1,
    tenant_id: tr.tenant_id, environment_id: tr.environment_id, resource_local_ref: ref, property: mapping.property,
    producer_id: mapping.producer_id, source_instance_id: subject.source_instance_id, producer_epoch: 'epoch:first',
    mapping_ref: mapping.mapping_ref, mapping_version: 1, rule_ref: rule.rule_ref, rule_version: 1,
    effective_at: now, legacy_observation_refs: [], supersedes: { absence: 'initial' } }
  const bundle = { binding, mapping, rule }
  await assert.rejects(ctx.kernel.admitStatePolicy(tr, bundle), { code: 'OC_UNAUTHORIZED' })
  for (const action of ['admit_state_policy', 'revoke_state_policy']) ctx.authority.grant({
    tenant_id: tr.tenant_id, environment_id: tr.environment_id, principal_id: tr.principal_id,
    action, resource_local_ref: ref, property: mapping.property, producer_id: mapping.producer_id,
  })
  assert.equal((await ctx.kernel.admitStatePolicy(tr, bundle)).outcome, 'applied')
  const make = (sequence, value, source = now) => {
    const doc = observation({ subject, property: mapping.property,
      result: { kind: 'measured', value_type: 'string', value },
      provenance: { producer_id: mapping.producer_id, connector_revision: 'producer/2', mapping_ref: mapping.mapping_ref, mapping_version: 1 },
      rule_ref: rule.rule_ref, rule_version: 1, source_observed_at: source,
      scope: { complete: true, period: { start: source, end: source } } })
    return { ...doc, contract: 'dubsar.operational-context.observation/2',
      state_order: { producer_epoch: binding.producer_epoch, sequence }, delivery_id: `delivery:${sequence}:${value.slice(0,1)}` }
  }
  now = '2026-09-21T10:00:01.000Z'
  const a = make(1, 'a'.repeat(40))
  assert.equal((await ctx.kernel.ingestObservation(tr, { ...a, state_order: { ...a.state_order, producer_epoch: 'epoch:unknown' } })).outcome, 'rejected')
  assert.equal((await ctx.kernel.ingestObservation(tr, a)).outcome, 'applied')
  now = '2026-09-21T10:00:02.000Z'
  const b = make(2, 'b'.repeat(40))
  assert.equal((await ctx.kernel.ingestObservation(tr, b)).outcome, 'applied')
  const req = { contract: 'dubsar.operational-context.view-request/2', resources: [{ local_ref: ref }], properties: [mapping.property], relation_depth: 0 }
  const project = view => view.resources[0].qualifications[0].state_projection
  let view = await ctx.kernel.readView(tr, req)
  assert.equal(view.contract, 'dubsar.operational-context.view/2')
  assert.equal(project(view).eligible, true)
  assert.equal(project(view).candidate.value, b.result.value)
  assert.equal(project(view).history.length, 1)
  const v1 = await ctx.kernel.readView(tr, { ...req, contract: 'dubsar.operational-context.view-request/1' })
  assert.equal(v1.resources[0].qualifications[0].state_projection, undefined)
  assert.equal((await ctx.kernel.admitStatePolicy(tr, { ...bundle, binding: { ...binding, effective_at: now }, rule: { ...rule, freshness_max_age_ms: 1 } })).outcome, 'integrity_conflict')
  now = '2026-09-21T10:00:03.000Z'
  await ctx.kernel.revokeRule(tr, rule)
  view = await ctx.kernel.readView(tr, req)
  assert.equal(project(view).eligible, false)
  assert.ok(project(view).limits.some(x => x.code === 'RULE_UNAVAILABLE'))
  const historical = await ctx.kernel.readView(tr, { ...req, instant: '2026-09-21T10:00:02.000Z' })
  assert.equal(project(historical).eligible, true)
  assert.equal(project(historical).candidate.value, b.result.value)
  now = '2026-09-21T10:00:04.000Z'
  const nextBinding = { ...binding, version: 2, effective_at: now, supersedes: { binding_ref: binding.binding_ref, version: 1 } }
  assert.equal((await ctx.kernel.admitStatePolicy(tr, { ...bundle, binding: nextBinding })).outcome, 'applied')
  now = '2026-09-21T10:00:05.000Z'
  await ctx.kernel.revokeStatePolicy(tr, binding)
  const afterOldRevoke = project(await ctx.kernel.readView(tr, req))
  assert.equal(afterOldRevoke.binding_version, 2)
  assert.equal(afterOldRevoke.eligible, true)
  for (let sequence = 3; sequence <= 202; sequence++) {
    assert.equal((await ctx.kernel.ingestObservation(tr, make(sequence, 'c'.repeat(40)))).outcome, 'applied')
  }
  const bounded = await ctx.kernel.readView(tr, req)
  assert.equal(bounded.bounds.truncated, true)
  assert.equal(project(bounded).eligible, false)
  assert.equal(project(bounded).candidate, null)
  assert.equal(project(bounded).history.length, 200)
  assert.ok(project(bounded).limits.some(x => x.code === 'STATE_SUPPORTS_INCOMPLETE'))
  await assert.rejects(ctx.owner.query("DELETE FROM dubsar_context.state_policy_events"), { code: '23514' })
})
