// Test composition ONLY. Administrative SQL and fixture controls are never product ports.
import pg from 'pg'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto'
import { setupExact } from '../../../tests/helpers/exact-action-fixture.mjs'
import { canonicalJson, canonicalBytes } from '../../../src/canonical-json.mjs'
import { HumanProofVerifier } from '../../../src/human-identity/proof.mjs'
import { HumanRegistry } from '../../../src/human-identity/registry.mjs'
import { ApprovalService } from '../../../src/exact-action/approval-service.mjs'
import { PostgresExactActionRecords } from '../../../src/exact-action/postgres-records.mjs'
import { ExactActionGate } from '../../../src/exact-action/contracts.mjs'
import { ArtifactStore } from '../../../src/artifacts/artifact-store.mjs'
import { LocalEncryptedBlobs } from '../../../src/artifacts/local-encrypted-blobs.mjs'
import { PostgresArtifactMetadata } from '../../../src/artifacts/postgres-metadata.mjs'
import { ExactArtifactReader } from '../../../src/exact-action/artifact-reader.mjs'
import { Ed25519CapabilityAuthority } from '../../../src/core/ed25519-capability-authority.mjs'
import { PostgresActionBroker } from '../../../src/broker/postgres-action-broker.mjs'
import { PostgresActionStore } from '../../../src/broker/postgres-action-store.mjs'
import { applyBrokerMigrations } from '../../../src/broker/postgres-migrations.mjs'

export async function qualification({ ownerPool, recordsPool, artifactPool, brokerPool, portalOptions = null }) {
  const f = setupExact()
  const context = { tenant_ref: f.binding.tenant_ref, project_ref: f.binding.project_ref, mission: f.binding.mission }
  const scope = canonicalJson(context)
  const artifactContext = { tenant_id: 'tenant:human-test', corpus_id: null, mission_id: 'mission:human-test', exact_context: context }
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dubsar-human-'))
  const key = randomBytes(32), pair = generateKeyPairSync('ed25519')
  const blobs = await LocalEncryptedBlobs.open({ root, context: artifactContext, keys: { get: async () => key } })
  const store = new ArtifactStore({ context: artifactContext, blobs,
    metadata: new PostgresArtifactMetadata({ pool: artifactPool, context: artifactContext }),
    policy: { authorize: async () => true }, evidence: { record: async event => ({ ...event, evidence_ref: `evidence:${event.artifact_id}` }) },
    clock: f.clock, keyRef: 'key:human-ephemeral' })
  const publish = (id, value) => store.publish({ idempotencyKey: id, bytes: canonicalBytes(value), metadata: {
    artifact_type: 'action.payload', media_type: 'application/json', producer: { component: 'qualification', contract_version: '1' },
    origin: { source_ref: null, parent_artifact_ids: [] }, classification: 'internal', expires_at: f.prepared.expires_at,
    retention_policy: { policy_id: 'test', hold: false } } })
  f.prepared.artifact.ref = (await publish(`payload:${root}`, f.proposal.payload)).artifact_id
  f.prepared.display.ref = (await publish(`display:${root}`, f.display)).artifact_id
  const portalLifecycle = portalOptions?.createLifecycle({ context, clock: f.clock }) ?? null
  const registry = new HumanRegistry({ context, clock: f.clock, environment: 'test', portalLifecycle })
  const records = new PostgresExactActionRecords({ pool: recordsPool, context, humanRegistry: registry, requireHuman: true })
  const issuer = portalOptions?.issuer ?? 'issuer:qualification', subject = portalOptions?.subject ?? 'external:qualification', session = `session:${randomBytes(16).toString('hex')}`
  await ownerPool.query(`INSERT INTO dubsar_human.memberships(context_key,issuer,external_subject,principal,environment,active_function,version,enabled)
    VALUES($1,$2,$3,$4,'test','approver',1,true) ON CONFLICT(context_key,issuer,external_subject) DO UPDATE SET enabled=true,version=1`,
    [scope, issuer, subject, 'test-user:1'])
  await records.setPrincipal({ subject: 'test-user:1', active_function: 'approver', eligible: true })
  const claims = { schema: 'dubsar.human-proof/1', issuer, audience: 'dubsar:exact', subject, session, kind: 'human',
    issued_at: Math.floor(Date.parse(f.clock.now()) / 1000) - 10, expires_at: Math.floor(Date.parse(f.prepared.expires_at) / 1000) }
  const proof = { claims, signature: sign(null, canonicalBytes(claims), pair.privateKey).toString('base64url') }
  const verifier = new HumanProofVerifier({ issuer, audience: claims.audience,
    publicKey: portalOptions?.publicKey ?? pair.publicKey.export({ format: 'pem', type: 'spki' }), clock: f.clock })
  const artifacts = new ExactArtifactReader({ store, exactContext: context })
  const service = new ApprovalService({ records, registry, verifier, context, artifacts, clock: f.clock,
    resolveAction: async ref => { if (ref !== 'action:qualification') throw new Error('unknown action')
      return { binding: f.binding, prepared: f.prepared, policy_digest: f.approval.policy_evaluation.policy_digest } } })
  const gate = new ExactActionGate({ records, artifacts })
  const authority = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock, exactActionGate: gate })
  const broker = new PostgresActionBroker({ ...f.brokerOptions, exactActionGate: gate, store: new PostgresActionStore({ pool: brokerPool }) })
  return { f, service, proof, context, scope, records, registry, store, portalLifecycle,
    issue: ref => authority.issueExact({ ...f.issueInput(), decisionRef: ref }),
    submit: signedCapability => broker.submit({ proposal: f.proposal, approval: f.approval, workflow: f.workflow, signedCapability,
      previousEvidenceDigest: `sha256:${'3'.repeat(64)}` }),
    async observe(presentationId) {
      const row = (await ownerPool.query('SELECT result FROM dubsar_human.presentations WHERE context_key=$1 AND presentation_id=$2', [scope, presentationId])).rows[0]
      const ref = row?.result?.decision_ref ?? null
      const count = async (table, where = '', values = []) => Number((await ownerPool.query(`SELECT count(*) AS n FROM ${table} ${where}`, values)).rows[0].n)
      return { result: row?.result ?? null,
        decisions: await count('dubsar_exact_records.decisions', 'WHERE context_key=$1 AND decision_ref=$2', [scope, ref]),
        links: await count('dubsar_human.decision_sessions', 'WHERE context_key=$1 AND decision_ref=$2', [scope, ref]),
        context_decisions: await count('dubsar_exact_records.decisions', 'WHERE context_key=$1', [scope]),
        session_decisions: await count('dubsar_human.decision_sessions', 'WHERE context_key=$1 AND session_id=$2', [scope, session]),
        executions: f.state.executions.length,
        actions: await count('dubsar_broker.broker_actions'),
        jtis: await count('dubsar_broker.broker_consumed_jtis'),
        consumed: Number((await ownerPool.query('SELECT COALESCE(sum(consumed_actions),0) AS n FROM dubsar_broker.broker_approval_usage')).rows[0].n) }
    },
    signClaims(patch) { const value = { ...claims, ...patch }; return { claims: value, signature: sign(null, canonicalBytes(value), pair.privateKey).toString('base64url') } },
    prepare: () => service.handle('prepare', { proof, action_ref: 'action:qualification' }),
    decide: (p, choice = 'APPROVE', id = `id:${p.presentation_id}`) => service.handle('decide', { proof, presentation_id: p.presentation_id,
      display_digest: p.display_digest, choice, idempotency_key: id }),
    revoke: () => ownerPool.query('UPDATE dubsar_human.sessions SET revoked=true WHERE context_key=$1 AND session_id=$2', [scope, session]),
    async execute(ref) {
      const signedCapability = await authority.issueExact({ ...f.issueInput(), decisionRef: ref })
      return broker.submit({ proposal: f.proposal, approval: f.approval, workflow: f.workflow, signedCapability,
        previousEvidenceDigest: `sha256:${'3'.repeat(64)}` })
    },
    async close() { key.fill(0); await fs.rm(root, { recursive: true, force: true }) }
  }
}

export async function createAuthority() {
  const ownerPool = new pg.Pool({ connectionString: process.env.DUBSAR_TEST_POSTGRES_URL })
  const rolePool = name => { const url = new URL(process.env.DUBSAR_TEST_POSTGRES_URL); url.username = name; url.password = ''; return new pg.Pool({ connectionString: url.toString() }) }
  const roles = ['dubsar_broker_runtime', 'dubsar_exact_records_runtime', 'dubsar_artifact_runtime']
  for (const role of roles) await ownerPool.query(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`)
  await applyBrokerMigrations(ownerPool)
  const [brokerPool, recordsPool, artifactPool] = roles.map(rolePool)
  const q = await qualification({ ownerPool, recordsPool, artifactPool, brokerPool })
  // Explicit test-only controls let the Python integration prove the complete pipe.
  const service = { async handle(op, params) {
    if (op === 'view' && params.fixture === 'bootstrap') return { proof: q.proof, action_ref: 'action:qualification' }
    if (op === 'view' && params.fixture === 'observe') return q.observe(params.presentation_id)
    if (op === 'view' && params.fixture === 'execute') { const receipt = await q.execute(params.decision_ref); return { receipt, executions: q.f.state.executions.length } }
    if (op === 'view' && params.fixture === 'revoke') { await q.revoke(); return { revoked: true } }
    if (op === 'view' && params.fixture === 'alternate-session') return { proof: q.signClaims({ session: 'session:alternate' }), action_ref: 'action:qualification' }
    if (op === 'view' && params.fixture === 'missing-mapping') return { proof: q.signClaims({ subject: 'subject:unmapped', session: 'session:unmapped' }), action_ref: 'action:qualification' }
    if (op === 'view' && params.fixture === 'environment') {
      await ownerPool.query('UPDATE dubsar_human.memberships SET environment=$1 WHERE context_key=$2', [params.value, q.scope]); return { updated: true }
    }
    if (op === 'view' && params.fixture === 'eligibility') {
      await ownerPool.query('UPDATE dubsar_human.memberships SET enabled=$1 WHERE context_key=$2', [params.value, q.scope]); return { updated: true }
    }
    return q.service.handle(op, params)
  } }
  return { service, async close() { await q.close(); await Promise.all([ownerPool, brokerPool, recordsPool, artifactPool].map(p => p.end())) } }
}
