import pg from 'pg'
import { applyOperationalContextMigration } from '../../src/operational-context/migrate.mjs'
import { createOperationalContextKernel } from '../../src/operational-context/kernel.mjs'
import { SimulatedAuthority } from '../../src/operational-context/authority.mjs'
import { resourceIdentity } from '../../src/operational-context/identity.mjs'
import { qualifyAt } from '../../src/operational-context/qualify.mjs'

const url = process.env.DUBSAR_TEST_POSTGRES_URL
if (!url) {
  process.stderr.write('disposable PostgreSQL required (DUBSAR_TEST_POSTGRES_URL)\n')
  process.exit(1)
}

const trust = JSON.parse(process.env.OC_TRUST_JSON)
const resource = JSON.parse(process.env.OC_RESOURCE_JSON)
const instant = process.env.OC_INSTANT ?? new Date().toISOString()
const rebuildOnly = process.env.OC_REBUILD_ONLY === '1'

const owner = new pg.Pool({ connectionString: url, max: 2 })
const runtime = new pg.Pool({
  connectionString: url,
  options: '-c role=dubsar_context_runtime',
  max: 2,
  statement_timeout: 5000,
})
const authority = new SimulatedAuthority()
authority.grant({
  tenant_id: trust.tenant_id,
  environment_id: trust.environment_id,
  principal_id: trust.principal_id,
  action: 'rebuild',
})
if (!rebuildOnly) {
  authority.grant({
    tenant_id: trust.tenant_id,
    environment_id: trust.environment_id,
    principal_id: trust.principal_id,
    action: 'read',
  })
}
try {
  await applyOperationalContextMigration(owner)
  const kernel = createOperationalContextKernel({
    pool: runtime,
    authority,
    clock: { now: () => instant },
  })
  const rebuilt = await kernel.rebuildDerivatives(trust, { instant })
  if (rebuildOnly) {
    let qualify_code = null
    try {
      await kernel.qualify(trust, { resource, property: 'enabled', instant })
    } catch (error) {
      qualify_code = error?.code ?? 'unknown'
    }
    process.stdout.write(`${JSON.stringify({
      computed: true,
      process: 'rebuild-reader',
      rebuild_only: true,
      pid: process.pid,
      effects_replayed: rebuilt.effects_replayed,
      permissions_restored: rebuilt.permissions_restored,
      rebuilt: rebuilt.rebuilt,
      receipt_keys: Object.keys(rebuilt).sort(),
      has_qualification_payload: Object.hasOwn(rebuilt, 'qualification') || Object.hasOwn(rebuilt, 'qualifications'),
      qualify_code,
      qualify_fn: typeof qualifyAt,
    }, null, 2)}\n`)
  } else {
    const qualified = await kernel.qualify(trust, { resource, property: 'enabled', instant })
    process.stdout.write(`${JSON.stringify({
      computed: true,
      process: 'rebuild-reader',
      pid: process.pid,
      effects_replayed: rebuilt.effects_replayed,
      permissions_restored: rebuilt.permissions_restored,
      rebuilt: rebuilt.rebuilt,
      qualification: qualified.semantic,
      resource_ref: resourceIdentity(resource).local_ref,
      qualify_fn: typeof qualifyAt,
    }, null, 2)}\n`)
  }
} finally {
  await Promise.all([runtime.end(), owner.end()])
}
