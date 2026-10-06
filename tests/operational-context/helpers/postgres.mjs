import pg from 'pg'
import { applyOperationalContextMigration } from '../../../src/operational-context/migrate.mjs'
import { OperationalContextKernel } from '../../../src/operational-context/kernel.mjs'
import { SimulatedAuthority } from '../../../src/operational-context/authority.mjs'
import { resourceIdentity } from '../../../src/operational-context/identity.mjs'
import { mapping, resource, rule, trust } from './fixtures.mjs'

const { Pool } = pg

export function postgresUrl() {
  const url = process.env.DUBSAR_TEST_POSTGRES_URL
  if (!url) throw new Error('disposable PostgreSQL required')
  return url
}

export async function setupKernel({ clock, faults, grants } = {}) {
  const url = postgresUrl()
  const owner = new Pool({ connectionString: url, max: 4, connectionTimeoutMillis: 3000, statement_timeout: 5000 })
  await applyOperationalContextMigration(owner)
  await owner.query(`
    TRUNCATE
      dubsar_context.view_receipts,
      dubsar_context.state_policy_events,
      dubsar_context.derivative_cache,
      dubsar_context.qualifications,
      dubsar_context.association_events,
      dubsar_context.associations,
      dubsar_context.observations,
      dubsar_context.aggregates,
      dubsar_context.mappings,
      dubsar_context.rules,
      dubsar_context.resources
    CASCADE
  `)
  const runtime = new Pool({
    connectionString: url,
    options: '-c role=dubsar_context_runtime',
    max: 8,
    connectionTimeoutMillis: 3000,
    statement_timeout: 5000,
    query_timeout: 5000,
  })
  const authority = new SimulatedAuthority()
  const defaults = grants ?? defaultGrants()
  for (const grant of defaults) authority.grant(grant)
  const kernel = new OperationalContextKernel({
    pool: runtime,
    authority,
    clock: clock ?? { now: () => '2026-09-18T09:05:00.000Z' },
    faults,
  })
  return {
    owner,
    runtime,
    authority,
    kernel,
    async close() { await Promise.all([runtime.end(), owner.end()]) },
  }
}

export function defaultGrants() {
  const t = trust()
  const admin = { tenant_id: t.tenant_id, environment_id: t.environment_id }
  const principals = [
    ['principal:ops', 'read'],
    ['principal:ops', 'register_resource'],
    ['principal:ops', 'observe'],
    ['principal:ops', 'correct'],
    ['principal:ops', 'retract'],
    ['principal:ops', 'propose_association'],
    ['principal:ops', 'admit_association'],
    ['principal:ops', 'revoke_association'],
    ['principal:ops', 'admit_mapping'],
    ['principal:ops', 'revoke_mapping'],
    ['principal:ops', 'admit_rule'],
    ['principal:ops', 'revoke_rule'],
    ['principal:ops', 'rebuild'],
    ['principal:producer-a', 'observe'],
    ['principal:producer-a', 'correct'],
    ['principal:producer-a', 'retract'],
    ['principal:producer-a', 'register_resource'],
    ['principal:producer-b', 'observe'],
    ['principal:producer-b', 'correct'],
    ['principal:producer-b', 'retract'],
    ['principal:producer-b', 'register_resource'],
  ]
  return principals.map(([principal_id, action]) => ({
    ...admin,
    principal_id,
    action,
  }))
}

export async function seedComparability(kernel) {
  const admin = trust()
  await kernel.admitMapping(admin, mapping())
  await kernel.admitRule(admin, rule())
  const a = resource({ source_instance_id: 'src:n8n-a' })
  const b = resource({ source_instance_id: 'src:n8n-b' })
  await kernel.registerResource(admin, a)
  await kernel.registerResource(admin, b)
  return { admin, a, b, aRef: resourceIdentity(a).local_ref, bRef: resourceIdentity(b).local_ref }
}
