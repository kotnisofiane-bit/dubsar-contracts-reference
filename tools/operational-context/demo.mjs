import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { applyOperationalContextMigration } from '../../src/operational-context/migrate.mjs'
import { createOperationalContextKernel } from '../../src/operational-context/kernel.mjs'
import { SimulatedAuthority } from '../../src/operational-context/authority.mjs'
import { resourceIdentity } from '../../src/operational-context/identity.mjs'

const url = process.env.DUBSAR_TEST_POSTGRES_URL
if (!url) {
  process.stderr.write('disposable PostgreSQL required (DUBSAR_TEST_POSTGRES_URL)\n')
  process.exit(1)
}

const clock = { now: () => '2026-09-18T09:05:00.000Z' }
const owner = new pg.Pool({ connectionString: url, max: 4 })
const runtime = new pg.Pool({
  connectionString: url,
  options: '-c role=dubsar_context_runtime',
  max: 8,
  statement_timeout: 5000,
})

const resourceA = {
  contract: 'dubsar.operational-context.resource/1',
  tenant_id: 'tenant:lab',
  environment_id: 'env:test',
  source_instance_id: 'src:n8n-a',
  namespace: 'workflow',
  type: 'workflow',
  source_id: 'export-commandes',
  incarnation: { absence: 'not_available' },
  label: 'export commandes',
}
const resourceB = { ...resourceA, source_instance_id: 'src:n8n-b' }
const homonym = { ...resourceA, source_instance_id: 'src:crm', source_id: 'commandes' }
const admin = {
  contract: 'dubsar.operational-context.trust/1',
  tenant_id: 'tenant:lab',
  environment_id: 'env:test',
  principal_id: 'principal:ops',
  principal_kind: 'human',
}
const restricted = { ...admin, principal_id: 'principal:restricted' }
const mapping = {
  contract: 'dubsar.operational-context.mapping/1',
  mapping_ref: 'map:enabled',
  version: 1,
  property: 'enabled',
  value_type: 'boolean',
  comparable_source_instances: ['src:n8n-a', 'src:n8n-b'],
}
const rule = {
  contract: 'dubsar.operational-context.rule/1',
  rule_ref: 'rule:fresh',
  version: 1,
  freshness_max_age_ms: 3_600_000,
}

function observation(subject, deliveryId, value, producer, extra = {}) {
  return {
    contract: 'dubsar.operational-context.observation/1',
    delivery_id: deliveryId,
    measurement_id: { absence: 'not_provided' },
    subject,
    property: 'enabled',
    result: { kind: 'measured', value_type: 'boolean', value },
    provenance: {
      producer_id: producer,
      connector_revision: 'connector:1',
      mapping_ref: 'map:enabled',
      mapping_version: 1,
    },
    source_observed_at: extra.source_observed_at ?? '2026-09-18T09:00:00Z',
    scope: { period: { start: '2026-09-18T08:00:00Z', end: '2026-09-18T12:00:00Z' }, complete: true },
    rule_ref: 'rule:fresh',
    rule_version: 1,
    ...extra,
  }
}

const authority = new SimulatedAuthority()
for (const action of [
  'observe', 'correct', 'retract', 'register_resource', 'propose_association', 'admit_association',
  'revoke_association', 'admit_mapping', 'revoke_mapping', 'admit_rule', 'revoke_rule', 'read', 'rebuild',
]) {
  authority.grant({ tenant_id: admin.tenant_id, environment_id: admin.environment_id, principal_id: admin.principal_id, action })
}
authority.grant({
  tenant_id: admin.tenant_id,
  environment_id: admin.environment_id,
  principal_id: restricted.principal_id,
  action: 'read',
  resource_local_ref: resourceIdentity(resourceA).local_ref,
})

try {
  await applyOperationalContextMigration(owner)
  await owner.query(`
    TRUNCATE
      dubsar_context.view_receipts, dubsar_context.derivative_cache, dubsar_context.qualifications,
      dubsar_context.association_events, dubsar_context.associations, dubsar_context.observations,
      dubsar_context.aggregates, dubsar_context.mappings, dubsar_context.rules, dubsar_context.resources
    CASCADE
  `)
  const kernel = createOperationalContextKernel({ pool: runtime, authority, clock })
  await kernel.admitMapping(admin, mapping)
  await kernel.admitRule(admin, rule)
  await kernel.registerResource(admin, resourceA)
  await kernel.registerResource(admin, resourceB)
  await kernel.registerResource(admin, homonym)
  const proposed = await kernel.proposeAssociation(admin, {
    contract: 'dubsar.operational-context.association/1',
    association_type: 'same_resource',
    left: resourceA,
    right: resourceB,
  })
  await kernel.admitAssociation(admin, { local_ref: proposed.local_ref, expected_version: proposed.version })
  const aTrue = await kernel.ingestObservation(admin, observation(resourceA, 'delivery:demo-a', true, 'producer:a'))
  const bFalse = await kernel.ingestObservation(admin, observation(resourceB, 'delivery:demo-b', false, 'producer:b'))
  const homonymObs = await kernel.ingestObservation(admin, observation(homonym, 'delivery:demo-homonym', true, 'producer:a'))
  const impossible = await kernel.ingestObservation(admin, observation(resourceA, 'delivery:demo-impossible', true, 'producer:a', {
    result: { kind: 'collection_impossible', reason: 'source-timeout' },
  }))
  clock.now = () => '2026-09-18T11:00:00.000Z'
  const stale = await kernel.ingestObservation(admin, observation(resourceA, 'delivery:demo-stale', true, 'producer:a', {
    source_observed_at: '2026-09-18T08:00:00Z',
    delivery_id: 'delivery:demo-stale',
    result: { kind: 'measured', value_type: 'boolean', value: true },
  }))
  clock.now = () => '2026-09-18T09:05:00.000Z'
  const correction = await kernel.correctObservation(admin, observation(resourceA, 'delivery:demo-corr', true, 'producer:a', {
    correction_of: aTrue.observation_ref,
    result: { kind: 'measured', value_type: 'boolean', value: true },
  }))
  const replay = await kernel.ingestObservation(admin, observation(resourceA, 'delivery:demo-a', true, 'producer:a'))
  const full = await kernel.readView(admin, {
    contract: 'dubsar.operational-context.view-request/1',
    resources: [resourceA],
    properties: ['enabled'],
    relation_depth: 1,
    instant: '2026-09-18T09:05:00.000Z',
  })
  const restrictedView = await kernel.readView(restricted, {
    contract: 'dubsar.operational-context.view-request/1',
    resources: [resourceA],
    properties: ['enabled'],
    relation_depth: 1,
    instant: '2026-09-18T09:05:00.000Z',
  })
  const conflict = full.resources[0]?.qualifications?.find(row => row.property === 'enabled')?.qualification?.agreement
  const verdict = conflict === 'conflict' ? 'CONFLICT' : conflict
  authority.revoke({
    tenant_id: admin.tenant_id,
    environment_id: admin.environment_id,
    principal_id: restricted.principal_id,
    action: 'read',
    resource_local_ref: resourceIdentity(resourceA).local_ref,
  })
  let revokedRead = 'ok'
  try {
    await kernel.readView(restricted, {
      contract: 'dubsar.operational-context.view-request/1',
      resources: [resourceA],
      relation_depth: 0,
    })
  } catch {
    revokedRead = 'refused'
  }

  const child = spawn(process.execPath, [fileURLToPath(new URL('./rebuild-reader.mjs', import.meta.url))], {
    env: {
      ...process.env,
      OC_TRUST_JSON: JSON.stringify(admin),
      OC_RESOURCE_JSON: JSON.stringify(resourceA),
      OC_INSTANT: '2026-09-18T09:05:00.000Z',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const out = []
  const err = []
  child.stdout.on('data', chunk => out.push(chunk))
  child.stderr.on('data', chunk => err.push(chunk))
  const code = await new Promise(resolve => child.on('close', resolve))
  if (code !== 0) throw new Error(`rebuild process failed: ${Buffer.concat(err).toString()}`)
  const rebuilt = JSON.parse(Buffer.concat(out).toString())

  const report = {
    demo: 'oc-kernel-01',
    computed: true,
    synthetic: true,
    conflict: verdict,
    ingest: {
      aTrue: aTrue.outcome,
      bFalse: bFalse.outcome,
      homonym: homonymObs.outcome,
      impossible: impossible.outcome,
      stale: stale.outcome,
      correction: correction.outcome,
      replay: replay.outcome,
    },
    full_reader_agreement: verdict,
    restricted_reader_receipt: restrictedView.selection_receipt,
    restricted_has_producer_b: JSON.stringify(restrictedView).includes('producer:b'),
    restricted_has_hidden_counter: JSON.stringify(restrictedView).includes('hidden'),
    access_revocation: revokedRead,
    second_process: { pid: rebuilt.pid, effects_replayed: rebuilt.effects_replayed, agreement: rebuilt.qualification?.agreement },
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  if (conflict !== 'conflict') throw new Error('demo expected CONFLICT for comparable A/B boolean')
  if (replay.outcome !== 'duplicate_identical') throw new Error('demo expected identical replay')
  if (revokedRead !== 'refused') throw new Error('demo expected revocation to refuse')
  if (report.restricted_has_producer_b) throw new Error('restricted reader leaked producer B')
} finally {
  await Promise.all([runtime.end(), owner.end()])
}
