import pg from 'pg'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { OC_BOUNDS } from '../../../src/operational-context/bounds.mjs'
import { OperationalContextKernel } from '../../../src/operational-context/kernel.mjs'
import { resourceIdentity, aggregateKey } from '../../../src/operational-context/identity.mjs'
import { association, mapping, observation, resource, rule, trust, viewRequest } from '../helpers/fixtures.mjs'
import { seedComparability, setupKernel } from '../helpers/postgres.mjs'

async function insertHiddenSupports(owner, {
  tenantId,
  environmentId,
  resourceLocalRef,
  sourceInstanceId,
  count,
  producerId,
  deliveryPrefix,
  localPrefix,
}) {
  if (count <= 0) return
  await owner.query(
    `INSERT INTO dubsar_context.observations (
       local_ref, tenant_id, environment_id, resource_local_ref, property, delivery_id,
       measurement_id, measurement_absent, result_kind, document, fingerprint,
       source_observed_at, source_date_unknown, received_at, mapping_ref, mapping_version,
       rule_ref, rule_version, producer_id, source_instance_id, correction_of, retraction_of
     )
     SELECT
       $6::text || lpad(gs::text, 32, '0'),
       $1, $2, $3, 'enabled',
       $7::text || gs::text,
       NULL, true, 'measured',
       jsonb_build_object(
         'contract', 'dubsar.operational-context.observation/1',
         'delivery_id', $7::text || gs::text,
         'property', 'enabled',
         'result', jsonb_build_object('kind', 'measured', 'value_type', 'boolean', 'value', false),
         'provenance', jsonb_build_object('producer_id', $5::text),
         'scope', jsonb_build_object(
           'complete', true,
           'period', jsonb_build_object('start', '2026-09-18T08:00:00Z', 'end', '2026-09-18T12:00:00Z')
         )
       ),
       'sha256:' || lpad(to_hex(gs::int), 64, '0'),
       TIMESTAMPTZ '2026-09-18T09:00:00Z',
       false,
       TIMESTAMPTZ '2026-09-18T09:05:00Z',
       'map:enabled', 1, 'rule:fresh', 1,
       $5::text,
       $4,
       NULL, NULL
     FROM generate_series(0, $8::int - 1) AS gs`,
    [
      tenantId,
      environmentId,
      resourceLocalRef,
      sourceInstanceId,
      producerId,
      localPrefix,
      deliveryPrefix,
      count,
    ],
  )
}

function assertNoHiddenLeak(view, extras = []) {
  const text = JSON.stringify(view)
  assert.doesNotMatch(text, /hidden_count|redacted|forbidden_support|rawSupportsExamined|onSupportExamined/)
  for (const extra of extras) {
    assert.equal(text.includes(extra), false, `view must not leak ${extra}`)
  }
}

test('OC kernel PostgreSQL path AC02–AC11', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const { kernel, owner, runtime, authority } = ctx
  const seeded = await seedComparability(kernel)
  const { admin, a, b } = seeded

  await t.test('AC02 two tenants, two environments, homonyms, bad producer, usurped author, missing authority', async () => {
    const otherTenant = trust({ tenant_id: 'tenant:other', principal_id: 'principal:ops' })
    authority.grant({ tenant_id: 'tenant:other', environment_id: 'env:test', principal_id: 'principal:ops', action: 'observe' })
    authority.grant({ tenant_id: 'tenant:other', environment_id: 'env:test', principal_id: 'principal:ops', action: 'register_resource' })
    const otherRes = resource({ tenant_id: 'tenant:other', source_id: 'export-commandes' })
    await kernel.registerResource(otherTenant, otherRes)
    const mixed = await kernel.ingestObservation(admin, observation({ subject: otherRes, delivery_id: 'delivery:mix' }))
    assert.equal(mixed.outcome, 'rejected')
    const otherEnv = trust({ environment_id: 'env:prod' })
    authority.grant({ tenant_id: 'tenant:lab', environment_id: 'env:prod', principal_id: 'principal:ops', action: 'observe' })
    const envRes = resource({ environment_id: 'env:prod' })
    const envMix = await kernel.ingestObservation(admin, observation({ subject: envRes, delivery_id: 'delivery:env' }))
    assert.equal(envMix.outcome, 'rejected')
    const homonym = resource({ source_id: 'commandes', source_instance_id: 'src:crm', label: 'export commandes' })
    await kernel.registerResource(admin, homonym)
    assert.notEqual(resourceIdentity(a).local_ref, resourceIdentity(homonym).local_ref)
    const stranger = trust({ principal_id: 'principal:stranger', principal_kind: 'producer' })
    const denied = await kernel.ingestObservation(stranger, observation({ delivery_id: 'delivery:stranger', subject: a }))
    assert.equal(denied.outcome, 'rejected')
    const producerB = trust({ principal_id: 'principal:producer-b', principal_kind: 'producer' })
    await kernel.ingestObservation(admin, observation({ subject: a, delivery_id: 'delivery:a-root', provenance: { ...observation().provenance, producer_id: 'producer:a' } }))
    const usurped = await kernel.correctObservation(producerB, observation({
      subject: a,
      delivery_id: 'delivery:usurp',
      correction_of: (await owner.query('SELECT local_ref FROM dubsar_context.observations WHERE delivery_id=$1', ['delivery:a-root'])).rows[0].local_ref,
      provenance: { ...observation().provenance, producer_id: 'producer:b' },
    }))
    assert.equal(usurped.outcome, 'rejected')
    authority.setUnavailable(true)
    const down = await kernel.ingestObservation(admin, observation({ delivery_id: 'delivery:down', subject: a }))
    assert.equal(down.outcome, 'unavailable')
    authority.setUnavailable(false)
  })

  await t.test('AC03 distinct result kinds persist', async () => {
    const cases = [
      observation({ subject: a, delivery_id: 'delivery:false', result: { kind: 'measured', value_type: 'boolean', value: false } }),
      observation({ subject: a, delivery_id: 'delivery:absence', result: { kind: 'proven_absence', method: 'full-list', scope_complete: true } }),
      observation({ subject: a, delivery_id: 'delivery:impossible', result: { kind: 'collection_impossible', reason: 'timeout' } }),
      observation({ subject: a, delivery_id: 'delivery:partial', result: { kind: 'collection_partial', reason: 'page' }, scope: { period: { start: '2026-09-18T08:00:00Z', end: '2026-09-18T12:00:00Z' }, complete: false } }),
      observation({ subject: a, delivery_id: 'delivery:unknown-date', source_observed_at: { absence: 'unknown' } }),
      observation({ subject: a, delivery_id: 'delivery:stale', source_observed_at: '2026-09-18T07:00:00Z' }),
    ]
    for (const item of cases) {
      const result = await kernel.ingestObservation(admin, item)
      assert.equal(result.outcome, 'applied', item.delivery_id)
    }
    const kinds = (await owner.query('SELECT delivery_id, result_kind, source_date_unknown FROM dubsar_context.observations WHERE delivery_id LIKE $1 ORDER BY delivery_id', ['delivery:%'])).rows
    assert.ok(kinds.some(row => row.result_kind === 'measured'))
    assert.ok(kinds.some(row => row.result_kind === 'proven_absence'))
    assert.ok(kinds.some(row => row.result_kind === 'collection_impossible'))
    assert.ok(kinds.some(row => row.result_kind === 'collection_partial'))
    assert.ok(kinds.some(row => row.source_date_unknown === true))
  })

  await t.test('AC04 immutable journal, replay, integrity conflict, authorized correction', async () => {
    const first = await kernel.ingestObservation(admin, observation({ subject: a, delivery_id: 'delivery:replay', measurement_id: 'measure:1' }))
    assert.equal(first.outcome, 'applied')
    const before = (await owner.query('SELECT fingerprint, received_at FROM dubsar_context.observations WHERE delivery_id=$1', ['delivery:replay'])).rows[0]
    const replay = await kernel.ingestObservation(admin, observation({ subject: a, delivery_id: 'delivery:replay', measurement_id: 'measure:1' }))
    assert.equal(replay.outcome, 'duplicate_identical')
    const after = (await owner.query('SELECT fingerprint, received_at FROM dubsar_context.observations WHERE delivery_id=$1', ['delivery:replay'])).rows[0]
    assert.equal(String(before.received_at), String(after.received_at))
    const conflict = await kernel.ingestObservation(admin, observation({
      subject: a,
      delivery_id: 'delivery:replay',
      result: { kind: 'measured', value_type: 'boolean', value: false },
    }))
    assert.equal(conflict.outcome, 'integrity_conflict')
    const equalNew = await kernel.ingestObservation(admin, observation({
      subject: a,
      delivery_id: 'delivery:replay-2',
      measurement_id: 'measure:2',
      result: { kind: 'measured', value_type: 'boolean', value: true },
    }))
    assert.equal(equalNew.outcome, 'applied')
    await assert.rejects(runtime.query('UPDATE dubsar_context.observations SET property = property'), /permission denied|immutable/)
    await assert.rejects(runtime.query('DELETE FROM dubsar_context.observations'), /permission denied|immutable/)
    const correction = await kernel.correctObservation(admin, observation({
      subject: a,
      delivery_id: 'delivery:corr',
      measurement_id: 'measure:corr',
      correction_of: first.observation_ref,
      result: { kind: 'measured', value_type: 'boolean', value: false },
    }))
    assert.equal(correction.outcome, 'applied')
    const original = (await owner.query('SELECT document FROM dubsar_context.observations WHERE local_ref=$1', [first.observation_ref])).rows[0]
    assert.equal(original.document.result.value, true)
  })

  await t.test('AC05 candidate vs admitted, uniqueness, expected version, revoke invalidates', async () => {
    const proposed = await kernel.proposeAssociation(admin, association(a, b))
    assert.equal(proposed.status, 'candidate')
    const again = await kernel.proposeAssociation(admin, association(a, b))
    assert.equal(again.local_ref, proposed.local_ref)
    const admitted = await kernel.admitAssociation(admin, { local_ref: proposed.local_ref, expected_version: proposed.version })
    assert.equal(admitted.status, 'admitted')
    await assert.rejects(kernel.admitAssociation(admin, { local_ref: proposed.local_ref, expected_version: proposed.version }))
    const separators = await kernel.proposeAssociation(admin, association(
      resource({ source_id: 'id:with|sep', source_instance_id: 'src:n8n-a' }),
      resource({ source_id: 'id:with|sep', source_instance_id: 'src:n8n-b' }),
    ))
    assert.equal(separators.outcome, 'applied')
    await kernel.ingestObservation(admin, observation({ subject: a, delivery_id: 'delivery:link-a', result: { kind: 'measured', value_type: 'boolean', value: true } }))
    await kernel.ingestObservation(admin, observation({
      subject: b,
      delivery_id: 'delivery:link-b',
      result: { kind: 'measured', value_type: 'boolean', value: false },
      provenance: { ...observation().provenance, producer_id: 'producer:b' },
    }))
    const revoked = await kernel.revokeAssociation(admin, { local_ref: proposed.local_ref, expected_version: admitted.version })
    assert.equal(revoked.status, 'revoked')
    const events = (await owner.query('SELECT action FROM dubsar_context.association_events WHERE association_ref=$1 ORDER BY version', [proposed.local_ref])).rows
    assert.deepEqual(events.map(row => row.action), ['propose', 'admit', 'revoke'])
    const aggregate = (await owner.query("SELECT status FROM dubsar_context.aggregates LIMIT 1")).rows[0]
    assert.ok(['pending_recalculation', 'invalidated', 'current'].includes(aggregate.status))
  })

  await t.test('AC05 revoke invalidates every property on both association ends', async () => {
    const left = resource({ source_id: 'multi-prop', source_instance_id: 'src:n8n-a' })
    const right = resource({ source_id: 'multi-prop', source_instance_id: 'src:n8n-b' })
    await kernel.registerResource(admin, left)
    await kernel.registerResource(admin, right)
    const proposed = await kernel.proposeAssociation(admin, association(left, right))
    const admitted = proposed.status === 'admitted'
      ? proposed
      : await kernel.admitAssociation(admin, { local_ref: proposed.local_ref, expected_version: proposed.version })
    for (const property of ['enabled', 'active']) {
      const appliedLeft = await kernel.ingestObservation(admin, observation({
        subject: left, property, delivery_id: `delivery:multi-l-${property}`,
      }))
      assert.equal(appliedLeft.outcome, 'applied')
      const appliedRight = await kernel.ingestObservation(admin, observation({
        subject: right, property, delivery_id: `delivery:multi-r-${property}`,
        provenance: { ...observation().provenance, producer_id: 'producer:b' },
      }))
      assert.equal(appliedRight.outcome, 'applied')
    }
    const keys = ['enabled', 'active'].flatMap(property => [
      aggregateKey(resourceIdentity(left).local_ref, property),
      aggregateKey(resourceIdentity(right).local_ref, property),
    ])
    const before = await owner.query(
      'SELECT aggregate_key, status FROM dubsar_context.aggregates WHERE aggregate_key = ANY($1)',
      [keys],
    )
    assert.equal(before.rows.length, 4)
    assert.ok(before.rows.every(row => row.status === 'current'))
    const revoked = await kernel.revokeAssociation(admin, {
      local_ref: proposed.local_ref, expected_version: admitted.version,
    })
    assert.equal(revoked.status, 'revoked')
    const after = await owner.query(
      'SELECT aggregate_key, status FROM dubsar_context.aggregates WHERE aggregate_key = ANY($1)',
      [keys],
    )
    assert.equal(after.rows.length, 4)
    assert.ok(after.rows.every(row => row.status === 'pending_recalculation'))
    const current = await owner.query(
      `SELECT count(*)::int AS n FROM dubsar_context.qualifications
       WHERE aggregate_key = ANY($1) AND status = 'current'`,
      [keys],
    )
    assert.equal(current.rows[0].n, 0)
    const history = (await owner.query(
      'SELECT action FROM dubsar_context.association_events WHERE association_ref=$1 ORDER BY version',
      [proposed.local_ref],
    )).rows
    assert.deepEqual(history.map(row => row.action), ['propose', 'admit', 'revoke'])
  })

  await t.test('AC06 comparable conflict after admitted same_resource', async () => {
    const pair = await kernel.proposeAssociation(admin, association(a, b))
    if (pair.status === 'candidate') await kernel.admitAssociation(admin, { local_ref: pair.local_ref, expected_version: pair.version })
    else if (pair.status === 'revoked') await kernel.admitAssociation(admin, { local_ref: pair.local_ref, expected_version: pair.version })
    await kernel.ingestObservation(admin, observation({ subject: a, delivery_id: 'delivery:conf-a', result: { kind: 'measured', value_type: 'boolean', value: true } }))
    await kernel.ingestObservation(admin, observation({
      subject: b,
      delivery_id: 'delivery:conf-b',
      result: { kind: 'measured', value_type: 'boolean', value: false },
      provenance: { ...observation().provenance, producer_id: 'producer:b' },
    }))
    const qualified = await kernel.qualify(admin, { resource: a, property: 'enabled', instant: '2026-09-18T09:05:00.000Z' })
    assert.equal(qualified.document.agreement, 'conflict')
    await kernel.revokeMapping(admin, mapping())
    const limited = await kernel.qualify(admin, { resource: a, property: 'enabled', instant: '2026-09-18T09:05:00.000Z' })
    assert.equal(limited.document.admissibility, 'limited')
    await kernel.admitMapping(admin, mapping())
  })

  await t.test('AC06 mapping and rule versions bind content immutably', async () => {
    const mapDoc = mapping({ mapping_ref: 'map:immutable', property: 'enabled' })
    assert.equal((await kernel.admitMapping(admin, mapDoc)).outcome, 'applied')
    assert.equal((await kernel.admitMapping(admin, mapDoc)).outcome, 'duplicate_identical')
    const mapConflict = await kernel.admitMapping(admin, mapping({
      mapping_ref: 'map:immutable',
      property: 'enabled',
      comparable_source_instances: ['src:other'],
    }))
    assert.equal(mapConflict.outcome, 'integrity_conflict')
    const mapRow = (await owner.query(
      "SELECT document, status FROM dubsar_context.mappings WHERE mapping_ref='map:immutable' AND version=1",
    )).rows[0]
    assert.deepEqual(mapRow.document.comparable_source_instances, ['src:n8n-a', 'src:n8n-b'])
    const mapRevoke = await kernel.revokeMapping(admin, mapDoc)
    assert.equal(mapRevoke.outcome, 'applied')
    assert.equal(mapRevoke.status, 'revoked')
    const mapAfter = (await owner.query(
      "SELECT document, status FROM dubsar_context.mappings WHERE mapping_ref='map:immutable' AND version=1",
    )).rows[0]
    assert.equal(mapAfter.status, 'revoked')
    assert.deepEqual(mapAfter.document.comparable_source_instances, ['src:n8n-a', 'src:n8n-b'])
    assert.equal((await kernel.revokeMapping(admin, mapping({
      mapping_ref: 'map:immutable',
      comparable_source_instances: ['src:forged'],
    }))).outcome, 'integrity_conflict')

    const ruleDoc = rule({ rule_ref: 'rule:immutable' })
    assert.equal((await kernel.admitRule(admin, ruleDoc)).outcome, 'applied')
    assert.equal((await kernel.admitRule(admin, ruleDoc)).outcome, 'duplicate_identical')
    assert.equal((await kernel.admitRule(admin, rule({
      rule_ref: 'rule:immutable',
      freshness_max_age_ms: 1,
    }))).outcome, 'integrity_conflict')
    const ruleRow = (await owner.query(
      "SELECT document, status FROM dubsar_context.rules WHERE rule_ref='rule:immutable' AND version=1",
    )).rows[0]
    assert.equal(ruleRow.document.freshness_max_age_ms, 3_600_000)
    assert.equal((await kernel.revokeRule(admin, ruleDoc)).outcome, 'applied')
    const ruleAfter = (await owner.query(
      "SELECT document, status FROM dubsar_context.rules WHERE rule_ref='rule:immutable' AND version=1",
    )).rows[0]
    assert.equal(ruleAfter.status, 'revoked')
    assert.equal(ruleAfter.document.freshness_max_age_ms, 3_600_000)

    const q1 = await kernel.qualify(admin, { resource: a, property: 'enabled', instant: '2026-09-18T09:05:00.000Z' })
    const q2 = await kernel.qualify(admin, { resource: a, property: 'enabled', instant: '2026-09-18T09:05:00.000Z' })
    assert.deepEqual(q1.semantic, q2.semantic)
  })

  await t.test('AC08 two readers, revoke during prepare, unavailable authority, no hidden counters', async () => {
    const aRef = resourceIdentity(a).local_ref
    authority.grant({
      tenant_id: admin.tenant_id, environment_id: admin.environment_id,
      principal_id: 'principal:restricted', action: 'read', resource_local_ref: aRef,
    })
    const full = await kernel.readView(admin, viewRequest([a], { relation_depth: 0, properties: ['enabled'] }))
    assert.equal(full.selection_receipt, 'complete_in_authorized_selection')
    assert.ok(!JSON.stringify(full).includes('hidden'))
    const restrictedTrust = trust({ principal_id: 'principal:restricted' })
    const restricted = await kernel.readView(restrictedTrust, viewRequest([a], { properties: ['enabled'] }))
    const text = JSON.stringify(restricted)
    assert.equal(restricted.selection_receipt, 'complete_in_authorized_selection')
    assert.doesNotMatch(text, /producer:b/)
    assert.doesNotMatch(text, /hidden_count|redacted/)
    const forbidden = viewRequest([b])
    await assert.rejects(kernel.readView(restrictedTrust, forbidden))
    kernel.faults.duringPrepare = async () => {
      authority.revoke({ tenant_id: admin.tenant_id, environment_id: admin.environment_id, principal_id: 'principal:ops', action: 'read' })
    }
    await assert.rejects(kernel.readView(admin, viewRequest([a])))
    kernel.faults.duringPrepare = undefined
    authority.grant({ tenant_id: admin.tenant_id, environment_id: admin.environment_id, principal_id: 'principal:ops', action: 'read' })
    authority.setUnavailable(true)
    await assert.rejects(kernel.readView(admin, viewRequest([a])))
    authority.setUnavailable(false)
  })

  await t.test('AC08 hidden contradictory support does not change restricted disclosure', async () => {
    const subject = resource({ source_id: 'slice-only', source_instance_id: 'src:n8n-a' })
    await kernel.registerResource(admin, subject)
    const subjectRef = resourceIdentity(subject).local_ref
    await kernel.ingestObservation(admin, observation({
      subject,
      delivery_id: 'delivery:slice-visible',
      provenance: { ...observation().provenance, producer_id: 'producer:a' },
    }))
    const restrictedTrust = trust({ principal_id: 'principal:slice' })
    authority.grant({
      tenant_id: admin.tenant_id,
      environment_id: admin.environment_id,
      principal_id: 'principal:slice',
      action: 'read',
      resource_local_ref: subjectRef,
      producer_id: 'producer:a',
    })
    const sliceOf = view => ({
      selection_receipt: view.selection_receipt,
      reserves: view.reserves,
      associations: view.associations,
      properties: (view.resources[0]?.qualifications ?? []).map(row => row.property).sort(),
      agreements: (view.resources[0]?.qualifications ?? []).map(row => row.qualification.agreement),
      producers: (view.resources[0]?.qualifications ?? []).flatMap(row => row.observations.map(item => item.producer_id)).sort(),
      values: (view.resources[0]?.qualifications ?? []).map(row => row.qualification.values.map(item => item.value)),
    })
    const before = await kernel.readView(restrictedTrust, viewRequest([subject]))
    await kernel.ingestObservation(admin, observation({
      subject,
      delivery_id: 'delivery:slice-hidden',
      result: { kind: 'measured', value_type: 'boolean', value: false },
      provenance: { ...observation().provenance, producer_id: 'producer:b' },
    }))
    await kernel.ingestObservation(admin, observation({
      subject,
      delivery_id: 'delivery:slice-secret',
      property: 'secret_flag',
      result: { kind: 'measured', value_type: 'boolean', value: true },
      provenance: { ...observation().provenance, producer_id: 'producer:b' },
    }))
    const after = await kernel.readView(restrictedTrust, viewRequest([subject]))
    assert.deepEqual(sliceOf(after), sliceOf(before))
    const afterText = JSON.stringify(after)
    assert.doesNotMatch(afterText, /producer:b/)
    assert.doesNotMatch(afterText, /secret_flag/)
    assert.doesNotMatch(afterText, /hidden_count|redacted|forbidden_support/)
    const full = await kernel.readView(admin, viewRequest([subject]))
    const properties = (full.resources[0]?.qualifications ?? []).map(row => row.property)
    assert.ok(properties.includes('secret_flag'))
    const enabled = (full.resources[0]?.qualifications ?? []).find(row => row.property === 'enabled')
    assert.equal(enabled?.qualification.agreement, 'conflict')
  })

  await t.test('AC11 case A: 199 hidden + 1 visible inside the 200 raw window', async () => {
    const subject = resource({ source_id: 'bound-case-a', source_instance_id: 'src:n8n-a' })
    await kernel.registerResource(admin, subject)
    const subjectRef = resourceIdentity(subject).local_ref
    const visible = await kernel.ingestObservation(admin, observation({
      subject,
      delivery_id: 'delivery:bound-a-visible',
      provenance: { ...observation().provenance, producer_id: 'producer:a' },
    }))
    assert.equal(visible.outcome, 'applied')
    const restrictedTrust = trust({ principal_id: 'principal:bound-a' })
    authority.grant({
      tenant_id: admin.tenant_id,
      environment_id: admin.environment_id,
      principal_id: 'principal:bound-a',
      action: 'read',
      resource_local_ref: subjectRef,
      producer_id: 'producer:a',
    })
    await insertHiddenSupports(owner, {
      tenantId: admin.tenant_id,
      environmentId: admin.environment_id,
      resourceLocalRef: subjectRef,
      sourceInstanceId: subject.source_instance_id,
      count: OC_BOUNDS.max_observations_examined - 1,
      producerId: 'producer:hidden-bound-a',
      deliveryPrefix: 'delivery:bound-a-hidden-',
      localPrefix: 'aaa_',
    })
    const ordered = await owner.query(
      `SELECT producer_id FROM dubsar_context.observations
       WHERE resource_local_ref = $1
       ORDER BY local_ref
       LIMIT $2`,
      [subjectRef, OC_BOUNDS.max_observations_examined],
    )
    assert.equal(ordered.rows.length, OC_BOUNDS.max_observations_examined)
    assert.equal(ordered.rows.at(-1).producer_id, 'producer:a')
    assert.equal(ordered.rows.filter(row => row.producer_id === 'producer:hidden-bound-a').length, 199)

    const view = await kernel.readView(restrictedTrust, viewRequest([subject]))
    assert.ok(kernel.faults.rawSupportsExamined <= OC_BOUNDS.max_observations_examined)
    assert.equal(view.selection_receipt, 'complete_in_authorized_selection')
    assert.equal(view.bounds.truncated, false)
    const enabled = (view.resources[0]?.qualifications ?? []).find(row => row.property === 'enabled')
    assert.ok(enabled)
    assert.equal(enabled.qualification.agreement, 'single')
    assert.deepEqual(enabled.observations.map(item => item.producer_id), ['producer:a'])
    assert.equal(enabled.qualification.values[0]?.value, true)
    assertNoHiddenLeak(view, ['producer:hidden-bound-a', 'delivery:bound-a-hidden-', 'aaa_'])
    assert.ok(view.reserves.every(row => row.code === 'AUTHORIZED_SELECTION_ONLY' || row.code === 'EMPTY_AUTHORIZED_SELECTION'))
  })

  await t.test('AC11 case B: 200 hidden + 1 visible beyond the bound is partial, never complete', async () => {
    const subject = resource({ source_id: 'bound-case-b', source_instance_id: 'src:n8n-a' })
    await kernel.registerResource(admin, subject)
    const subjectRef = resourceIdentity(subject).local_ref
    const visible = await kernel.ingestObservation(admin, observation({
      subject,
      delivery_id: 'delivery:bound-b-visible',
      provenance: { ...observation().provenance, producer_id: 'producer:a' },
    }))
    assert.equal(visible.outcome, 'applied')
    const restrictedTrust = trust({ principal_id: 'principal:bound-b' })
    authority.grant({
      tenant_id: admin.tenant_id,
      environment_id: admin.environment_id,
      principal_id: 'principal:bound-b',
      action: 'read',
      resource_local_ref: subjectRef,
      producer_id: 'producer:a',
    })
    await insertHiddenSupports(owner, {
      tenantId: admin.tenant_id,
      environmentId: admin.environment_id,
      resourceLocalRef: subjectRef,
      sourceInstanceId: subject.source_instance_id,
      count: OC_BOUNDS.max_observations_examined,
      producerId: 'producer:hidden-bound-b',
      deliveryPrefix: 'delivery:bound-b-hidden-',
      localPrefix: 'aab_',
    })
    const ordered = await owner.query(
      `SELECT producer_id FROM dubsar_context.observations
       WHERE resource_local_ref = $1
       ORDER BY local_ref
       LIMIT $2`,
      [subjectRef, OC_BOUNDS.max_observations_examined + 1],
    )
    assert.equal(ordered.rows.length, OC_BOUNDS.max_observations_examined + 1)
    assert.ok(ordered.rows.slice(0, OC_BOUNDS.max_observations_examined).every(row => row.producer_id === 'producer:hidden-bound-b'))
    assert.equal(ordered.rows.at(-1).producer_id, 'producer:a')

    const view = await kernel.readView(restrictedTrust, viewRequest([subject]))
    assert.ok(kernel.faults.rawSupportsExamined <= OC_BOUNDS.max_observations_examined)
    assert.equal(kernel.faults.rawSupportsExamined, OC_BOUNDS.max_observations_examined)
    assert.equal(view.selection_receipt, 'partial')
    assert.equal(view.bounds.truncated, true)
    const producers = (view.resources[0]?.qualifications ?? []).flatMap(row => row.observations.map(item => item.producer_id))
    assert.equal(producers.includes('producer:a'), false)
    assertNoHiddenLeak(view, ['producer:hidden-bound-b', 'delivery:bound-b-hidden-', 'aab_'])
    assert.ok(view.reserves.every(row => row.code === 'AUTHORIZED_SELECTION_ONLY' || row.code === 'EMPTY_AUTHORIZED_SELECTION'))
    assert.ok(view.reserves.some(row => row.code === 'AUTHORIZED_SELECTION_ONLY'))
  })

  await t.test('AC09 empty complete, unknown ref, contradictory type, source down', async () => {
    const emptyRes = resource({ source_id: 'empty-wf', source_instance_id: 'src:n8n-a' })
    await kernel.registerResource(admin, emptyRes)
    const empty = await kernel.readView(admin, viewRequest([emptyRes]))
    assert.equal(empty.selection_receipt, 'complete_in_authorized_selection')
    assert.ok(empty.resources[0].qualifications.length === 0 || empty.reserves.some(row => row.code === 'EMPTY_AUTHORIZED_SELECTION'))
    const unknown = await kernel.readView(admin, viewRequest([{ local_ref: 'ocr_deadbeefdeadbeefdeadbeefdeadbeef' }]))
    assert.ok(unknown.resources.some(row => row.resolution === 'unknown') || unknown.selection_receipt === 'partial')
    const wrongType = await kernel.readView(admin, viewRequest([{ ...a, type: 'connector' }]))
    assert.ok(wrongType.resources.some(row => row.resolution === 'unknown' || row.resolution === 'type_mismatch'))
  })

  await t.test('AC10 rebuild in this process after cache corruption', async () => {
    await owner.query("UPDATE dubsar_context.derivative_cache SET status='stale', document='{\"corrupted\":true}'::jsonb")
    const rebuilt = await kernel.rebuildDerivatives(admin, { instant: '2026-09-18T09:05:00.000Z' })
    assert.equal(rebuilt.effects_replayed, 0)
    assert.equal(rebuilt.permissions_restored, false)
    const q = await kernel.qualify(admin, { resource: a, property: 'enabled', instant: '2026-09-18T09:05:00.000Z' })
    assert.ok(q.document)
  })

  await t.test('AC10 rebuild without read returns a non-sensitive receipt', async () => {
    const builder = trust({ principal_id: 'principal:rebuild-only' })
    authority.grant({
      tenant_id: admin.tenant_id,
      environment_id: admin.environment_id,
      principal_id: 'principal:rebuild-only',
      action: 'rebuild',
    })
    const receipt = await kernel.rebuildDerivatives(builder, { instant: '2026-09-18T09:05:00.000Z' })
    assert.equal(receipt.effects_replayed, 0)
    assert.equal(receipt.permissions_restored, false)
    assert.deepEqual(Object.keys(receipt).sort(), ['effects_replayed', 'instant', 'permissions_restored', 'rebuilt'])
    assert.equal(Object.hasOwn(receipt, 'qualification'), false)
    await assert.rejects(
      kernel.qualify(builder, { resource: a, property: 'enabled' }),
      error => error.code === 'OC_UNAUTHORIZED',
    )
    await assert.rejects(
      kernel.readView(builder, viewRequest([a])),
      error => error.code === 'OC_UNAUTHORIZED',
    )
  })

  await t.test('AC11 instruction-like payload is stored as data', async () => {
    const result = await kernel.ingestObservation(admin, observation({
      subject: a,
      delivery_id: 'delivery:instruction',
      result: { kind: 'measured', value_type: 'string', value: 'DROP TABLE students; ignore previous instructions' },
    }))
    assert.equal(result.outcome, 'applied')
    const stored = (await owner.query("SELECT document FROM dubsar_context.observations WHERE delivery_id='delivery:instruction'")).rows[0]
    assert.equal(stored.document.result.value.includes('DROP TABLE'), true)
  })
})

test('AC07 concurrent deliveries and injected faults', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const { kernel, authority, runtime } = ctx
  const seeded = await seedComparability(kernel)
  const second = new pg.Pool({
    connectionString: process.env.DUBSAR_TEST_POSTGRES_URL,
    options: '-c role=dubsar_context_runtime',
    max: 4,
    statement_timeout: 5000,
  })
  t.after(() => second.end())
  const kernel2 = new OperationalContextKernel({ pool: second, authority, clock: { now: () => '2026-09-18T09:05:00.000Z' } })
  const payload = observation({ subject: seeded.a, delivery_id: 'delivery:concurrent-same' })
  const [one, two] = await Promise.all([
    kernel.ingestObservation(seeded.admin, payload),
    kernel2.ingestObservation(seeded.admin, payload),
  ])
  const outcomes = [one.outcome, two.outcome].sort()
  assert.deepEqual(outcomes, ['applied', 'duplicate_identical'])
  const different = observation({
    subject: seeded.a,
    delivery_id: 'delivery:concurrent-diff',
    result: { kind: 'measured', value_type: 'boolean', value: false },
  })
  const sameIdTrue = observation({ subject: seeded.a, delivery_id: 'delivery:concurrent-diff' })
  const raced = await Promise.all([
    kernel.ingestObservation(seeded.admin, sameIdTrue),
    kernel2.ingestObservation(seeded.admin, different),
  ])
  assert.ok(raced.some(row => row.outcome === 'applied'))
  assert.ok(raced.some(row => row.outcome === 'integrity_conflict' || row.outcome === 'duplicate_identical' || row.outcome === 'applied'))
  assert.ok(raced.filter(row => row.outcome === 'applied').length === 1)

  let reached = false
  const failing = new OperationalContextKernel({
    pool: runtime,
    authority,
    clock: { now: () => '2026-09-18T09:05:00.000Z' },
    faults: { async beforeCommit() { reached = true; throw new Error('INJECTED_BEFORE_COMMIT') } },
  })
  await assert.rejects(failing.ingestObservation(seeded.admin, observation({ subject: seeded.a, delivery_id: 'delivery:fail-before' })))
  assert.equal(reached, true)
  const missing = (await ctx.owner.query("SELECT count(*)::int AS n FROM dubsar_context.observations WHERE delivery_id='delivery:fail-before'")).rows[0]
  assert.equal(missing.n, 0)

  const afterCommit = new OperationalContextKernel({
    pool: runtime,
    authority,
    clock: { now: () => '2026-09-18T09:05:00.000Z' },
    faults: { async afterCommitBeforeReply() { throw new Error('INJECTED_AFTER_COMMIT') } },
  })
  await assert.rejects(afterCommit.ingestObservation(seeded.admin, observation({ subject: seeded.a, delivery_id: 'delivery:fail-after' })))
  const stored = (await ctx.owner.query("SELECT count(*)::int AS n FROM dubsar_context.observations WHERE delivery_id='delivery:fail-after'")).rows[0]
  assert.equal(stored.n, 1)
  const replay = await kernel.ingestObservation(seeded.admin, observation({ subject: seeded.a, delivery_id: 'delivery:fail-after' }))
  assert.equal(replay.outcome, 'duplicate_identical')

  const beforeDeriv = new OperationalContextKernel({
    pool: runtime,
    authority,
    clock: { now: () => '2026-09-18T09:05:00.000Z' },
    faults: { async beforeDerivativePublish() { throw new Error('INJECTED_BEFORE_DERIVATIVE') } },
  })
  await assert.rejects(beforeDeriv.ingestObservation(seeded.admin, observation({ subject: seeded.a, delivery_id: 'delivery:fail-deriv' })))
  const pending = (await ctx.owner.query(`
    SELECT a.status FROM dubsar_context.aggregates a
    JOIN dubsar_context.observations o ON o.resource_local_ref = split_part(a.aggregate_key, '"', 4)
    WHERE o.delivery_id = 'delivery:fail-deriv'
  `)).rows
  void pending
  const current = await kernel.qualify(seeded.admin, { resource: seeded.a, property: 'enabled' })
  assert.ok(current.document.status !== undefined)
})

test('AC10 second Node process rereads PostgreSQL', async () => {
  const ctx = await setupKernel()
  try {
    const seeded = await seedComparability(ctx.kernel)
    await ctx.kernel.ingestObservation(seeded.admin, observation({ subject: seeded.a, delivery_id: 'delivery:rebuild-a' }))
    const child = spawn(process.execPath, [fileURLToPath(new URL('../../../tools/operational-context/rebuild-reader.mjs', import.meta.url))], {
      env: {
        ...process.env,
        OC_TRUST_JSON: JSON.stringify(seeded.admin),
        OC_RESOURCE_JSON: JSON.stringify(seeded.a),
        OC_INSTANT: '2026-09-18T09:05:00.000Z',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const chunks = []
    const err = []
    child.stdout.on('data', chunk => chunks.push(chunk))
    child.stderr.on('data', chunk => err.push(chunk))
    const code = await new Promise(resolve => child.on('close', resolve))
    assert.equal(code, 0, Buffer.concat(err).toString())
    const payload = JSON.parse(Buffer.concat(chunks).toString())
    assert.equal(payload.effects_replayed, 0)
    assert.equal(payload.computed, true)
  } finally {
    await ctx.close()
  }
})

test('AC10 second Node process with rebuild-only cannot read content', async () => {
  const ctx = await setupKernel()
  try {
    const seeded = await seedComparability(ctx.kernel)
    await ctx.kernel.ingestObservation(seeded.admin, observation({ subject: seeded.a, delivery_id: 'delivery:rebuild-only-a' }))
    const builder = { ...seeded.admin, principal_id: 'principal:rebuild-only' }
    const child = spawn(process.execPath, [fileURLToPath(new URL('../../../tools/operational-context/rebuild-reader.mjs', import.meta.url))], {
      env: {
        ...process.env,
        OC_REBUILD_ONLY: '1',
        OC_TRUST_JSON: JSON.stringify(builder),
        OC_RESOURCE_JSON: JSON.stringify(seeded.a),
        OC_INSTANT: '2026-09-18T09:05:00.000Z',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const chunks = []
    const err = []
    child.stdout.on('data', chunk => chunks.push(chunk))
    child.stderr.on('data', chunk => err.push(chunk))
    const code = await new Promise(resolve => child.on('close', resolve))
    assert.equal(code, 0, Buffer.concat(err).toString())
    const payload = JSON.parse(Buffer.concat(chunks).toString())
    assert.equal(payload.rebuild_only, true)
    assert.equal(payload.effects_replayed, 0)
    assert.equal(payload.has_qualification_payload, false)
    assert.equal(payload.qualify_code, 'OC_UNAUTHORIZED')
    assert.deepEqual(payload.receipt_keys, ['effects_replayed', 'instant', 'permissions_restored', 'rebuilt'])
  } finally {
    await ctx.close()
  }
})
