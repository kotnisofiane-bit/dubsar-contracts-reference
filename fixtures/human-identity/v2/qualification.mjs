// Test-only process composition. Public keys and synthetic identifiers in env;
// private Core lifecycle key generated in this process, never exported.
import pg from 'pg'
import { generateKeyPairSync } from 'node:crypto'
import { qualification } from '../v1/qualification.mjs'
import { applyBrokerMigrations } from '../../../src/broker/postgres-migrations.mjs'
import { PortalSessionLifecycle } from '../../../src/human-identity/lifecycle.mjs'
import { createSourceVerifier } from '../../../src/human-identity/lifecycle-wire.mjs'
export async function createAuthority() {
  const ownerPool = new pg.Pool({ connectionString: process.env.DUBSAR_TEST_POSTGRES_URL, connectionTimeoutMillis: 1000 })
  for (const role of ['dubsar_broker_runtime', 'dubsar_exact_records_runtime', 'dubsar_artifact_runtime'])
    await ownerPool.query(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`)
  await applyBrokerMigrations(ownerPool)
  const rolePool = role => { const u = new URL(process.env.DUBSAR_TEST_POSTGRES_URL); u.username = role; u.password = ''; return new pg.Pool({ connectionString: u.toString(), connectionTimeoutMillis: 1000 }) }
  await ownerPool.query('ALTER ROLE dubsar_human_lifecycle_runtime LOGIN')
  const brokerPool = rolePool('dubsar_broker_runtime'), recordsPool = rolePool('dubsar_exact_records_runtime'), artifactPool = rolePool('dubsar_artifact_runtime'), lifecyclePool = rolePool('dubsar_human_lifecycle_runtime')
  const keys = generateKeyPairSync('ed25519')
  const peer = process.env.DUBSAR_TEST_PORTAL_PUBLIC_KEY
  const corePublicKey = keys.publicKey.export({ type: 'spki', format: 'pem' })
  const q = await qualification({ ownerPool, brokerPool, recordsPool, artifactPool, portalOptions: {
    issuer: 'portal:human', subject: process.env.DUBSAR_TEST_SUBJECT, publicKey: process.env.DUBSAR_TEST_HUMAN_PUBLIC_KEY,
    createLifecycle: ({ context, clock }) => new PortalSessionLifecycle({ pool: lifecyclePool, context, humanIssuer: 'portal:human', clock,
      commandVerifier: { issuer: 'portal:workload', audience: 'core:workload', publicKey: peer },
      replySigner: { issuer: 'core:workload', audience: 'portal:workload', privateKey: keys.privateKey },
      verifySource: createSourceVerifier({ issuer: 'core:workload', audience: 'portal:workload', privateKey: keys.privateKey, publicKey: peer, clock,
        exchange: async (request, signal) => {
          const response = await fetch(process.env.DUBSAR_TEST_BACKEND_CALLBACK, { method: 'POST', redirect: 'error', signal,
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request) })
          if (!response.ok) throw new Error('callback unavailable')
          return response.json()
        } }) }) } })
  let capability
  const service = { async handle(operation, params) {
    if (operation === 'lifecycle') return q.portalLifecycle.handle(params)
    if (operation === 'view' && params.fixture === 'bootstrap') return { context: q.context, now: q.f.clock.now(), corePublicKey }
    if (operation === 'view' && params.fixture === 'eligibility') {
      await ownerPool.query('UPDATE dubsar_human.memberships SET enabled=$1 WHERE context_key=$2', [params.enabled, q.scope])
      return { updated: true }
    }
    if (operation === 'view' && params.fixture === 'issue') { capability = await q.issue(params.decision_ref); return { issued: true } }
    if (operation === 'view' && params.fixture === 'submit') return q.submit(capability)
    if (operation === 'view' && params.fixture === 'observe') return q.observe(params.presentation_id)
    return q.service.handle(operation, params)
  } }
  return { service, protocol: 'dubsar.exact-ipc/2', async close() { await q.close(); await Promise.all([ownerPool, brokerPool, recordsPool, artifactPool, lifecyclePool].map(p => p.end())) } }
}
