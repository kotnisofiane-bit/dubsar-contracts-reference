import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { randomBytes, createHash } from 'node:crypto'
import test from 'node:test'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import pg from 'pg'
import { DeterministicPilotExecutor } from '../../src/broker/deterministic-pilot-executor.mjs'
import { Ed25519CapabilityVerifier, StaticEd25519PublicKeyRing } from '../../src/broker/ed25519-capability-verifier.mjs'
import { PostgresActionBroker } from '../../src/broker/postgres-action-broker.mjs'
import { PostgresActionStore } from '../../src/broker/postgres-action-store.mjs'
import { applyBrokerMigrations } from '../../src/broker/postgres-migrations.mjs'
import { domainSeparatedHash } from '../../src/canonical-json.mjs'
import { Ed25519CapabilityAuthority } from '../../src/core/ed25519-capability-authority.mjs'
import { assertContract } from '../../src/contracts.mjs'
import { setupExact } from '../helpers/exact-action-fixture.mjs'
import { diagnosticPool, diagnosticOutcome } from '../helpers/concurrency-diagnostic.mjs'
import { deadlockReproduction } from '../helpers/deadlock-reproduction.mjs'
import { finalizationUpgradeTests } from '../helpers/finalization-upgrade.mjs'
import { setupSyntheticExact } from '../helpers/synthetic-exact-action-fixture.mjs'
import { assertExactReceipt } from '../../src/exact-action/receipt.mjs'
import { PostgresExactActionRecords } from '../../src/exact-action/postgres-records.mjs'
import { ExactActionGate, hashExact } from '../../src/exact-action/contracts.mjs'
import { canonicalBytes } from '../../src/canonical-json.mjs'
import { ArtifactStore } from '../../src/artifacts/artifact-store.mjs'
import { LocalEncryptedBlobs } from '../../src/artifacts/local-encrypted-blobs.mjs'
import { PostgresArtifactMetadata } from '../../src/artifacts/postgres-metadata.mjs'
import { ExactArtifactReader } from '../../src/exact-action/artifact-reader.mjs'
import { scopeKey, artifactError } from '../../src/artifacts/contracts.mjs'
import { qualification } from '../../fixtures/human-identity/v1/qualification.mjs'

const { Pool } = pg
const DATABASE_URL = process.env.DUBSAR_TEST_POSTGRES_URL
const RUNTIME_ROLE = 'dubsar_broker_runtime'
const NOW = '2026-08-14T10:00:30.000Z'
const RECOVERY_NOW = '2026-08-14T10:00:45.000Z'
const PREVIOUS_EVIDENCE = 'sha256:3333333333333333333333333333333333333333333333333333333333333333'
const CALLER_IDENTITY = Object.freeze({
  workload_id: 'workload_worker_demo_001',
  instance_id: 'instance_worker_demo_001',
})
const BROKER_IDENTITY = Object.freeze({
  workload_id: 'workload_broker_demo_001',
  instance_id: 'instance_broker_demo_001',
})

test('Lot 2C PostgreSQL Broker is durable, concurrent and fail-closed', { skip: !DATABASE_URL }, async t => {
  const ownerPool = new Pool({
    connectionString: DATABASE_URL,
    max: 12,
    connectionTimeoutMillis: 3000,
    idleTimeoutMillis: 3000,
    statement_timeout: 5000,
    query_timeout: 5000,
  })
  let runtimePool
  let recordsPool
  let artifactPool
  try {
    const preexisting = await ownerPool.query(`
      SELECT count(*)::integer AS count
      FROM information_schema.tables
      WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
    `)
    assert.equal(preexisting.rows[0].count, 0, 'integration database must start empty')

    await ownerPool.query(`
      DO $role$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${RUNTIME_ROLE}') THEN
          CREATE ROLE ${RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
        END IF;
      END
      $role$
    `)

    await ownerPool.query(`CREATE ROLE dubsar_exact_records_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`)
    await ownerPool.query(`CREATE ROLE dubsar_artifact_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`)
    const firstMigration = await applyBrokerMigrations(ownerPool)
    assert.deepEqual(firstMigration.applied, ['001_durable_action_broker.sql', '002_exact_action_records.sql', '003_artifact_store.sql', '004_human_identity.sql', '005_broker_finalization_lock_order.sql', '006_portal_session_lifecycle.sql', '007_document_access.sql', '008_operational_context.sql', '009_state_projection.sql'])
    const firstDigest = await schemaDigest(ownerPool)
    const secondMigration = await applyBrokerMigrations(ownerPool)
    const secondDigest = await schemaDigest(ownerPool)
    assert.deepEqual(secondMigration.applied, [])
    assert.equal(secondDigest, firstDigest)
    runtimePool = new Pool({
      connectionString: runtimeDatabaseUrl(DATABASE_URL),
      max: 12,
      connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 3000,
      statement_timeout: 5000,
      query_timeout: 5000,
    })
    assert.equal((await runtimePool.query('SELECT current_user')).rows[0].current_user, RUNTIME_ROLE)
    const recordsUrl = new URL(DATABASE_URL)
    recordsUrl.username = 'dubsar_exact_records_runtime'
    recordsUrl.password = ''
    recordsPool = new Pool({ connectionString: recordsUrl.toString(), max: 8, connectionTimeoutMillis: 3000 })
    const artifactUrl = new URL(DATABASE_URL)
    artifactUrl.username = 'dubsar_artifact_runtime'; artifactUrl.password = ''
    artifactPool = new Pool({ connectionString: artifactUrl.toString(), max: 8, connectionTimeoutMillis: 3000 })

    await t.test('runtime role is a non-owner without inherited or object-creation authority', async () => {
      const role = await ownerPool.query(`
        SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb
        FROM pg_roles WHERE rolname = $1
      `, [RUNTIME_ROLE])
      assert.deepEqual(role.rows[0], {
        rolsuper: false,
        rolinherit: false,
        rolcreaterole: false,
        rolcreatedb: false,
      })
      const memberships = await ownerPool.query(`
        SELECT count(*)::integer AS count
        FROM pg_auth_members memberships
        JOIN pg_roles members ON members.oid = memberships.member
        WHERE members.rolname = $1
      `, [RUNTIME_ROLE])
      assert.equal(memberships.rows[0].count, 0)
      const owners = await ownerPool.query(`
        SELECT DISTINCT owners.rolname
        FROM pg_class objects
        JOIN pg_namespace namespaces ON namespaces.oid = objects.relnamespace
        JOIN pg_roles owners ON owners.oid = objects.relowner
        WHERE namespaces.nspname = 'dubsar_broker'
      `)
      assert.ok(owners.rows.length > 0)
      assert.ok(owners.rows.every(row => row.rolname !== RUNTIME_ROLE))
      assert.equal((await runtimePool.query(
        "SELECT has_schema_privilege(current_user, 'dubsar_broker', 'CREATE') AS allowed",
      )).rows[0].allowed, false)
      await assert.rejects(
        runtimePool.query(`
          CREATE FUNCTION dubsar_broker.runtime_shadow()
          RETURNS integer LANGUAGE sql AS 'SELECT 1'
        `),
        error => error?.code === '42501',
      )
      const client = await runtimePool.connect()
      try {
        await assert.rejects(client.query('SET ROLE dubsar_ci'), error => error?.code === '42501')
      } finally {
        await client.query('RESET ROLE').catch(() => {})
        client.release()
      }
    })

    await t.test('signed capability executes once and persists state, transitions and receipt', async () => {
      await resetActions(ownerPool)
      const runtime = makeRuntime({ pool: runtimePool, jtiNamespace: 'success' })
      const receipt = await runtime.broker.submit(runtime.request())
      assert.doesNotThrow(() => assertContract('action-receipt', receipt))
      assert.equal(receipt.after_state, 'SUCCEEDED')
      assert.equal(runtime.executor.executionCount, 1)

      const action = await runtime.broker.getAction(receipt.proposal_id)
      assert.equal(action.state, 'SUCCEEDED')
      assert.equal(action.version, 3)
      assert.deepEqual(action.transitions.map(item => `${item.from_state}->${item.to_state}`), [
        'RECEIVED->AUTHORIZED',
        'AUTHORIZED->IN_FLIGHT',
        'IN_FLIGHT->SUCCEEDED',
      ])
      for (const transition of action.transitions) assert.doesNotThrow(() => assertContract('state-transition', transition))
      const counts = await durableCounts(ownerPool)
      assert.deepEqual(counts, { actions: 1, idempotency: 1, jtis: 1, receipts: 1, transitions: 3 })
      assert.deepEqual(await approvalConsumption(ownerPool), { consumed_actions: 1, max_actions: 1 })
    })

    await t.test('concurrent consumption of one jti never executes twice', async () => {
      await resetActions(ownerPool)
      const gate = deferred()
      const entered = deferred()
      const executor = new DeterministicPilotExecutor()
      const blockingExecutor = {
        get executionCount() { return executor.executionCount },
        assertSupported(proposal) { executor.assertSupported(proposal) },
        async execute(input) {
          entered.resolve()
          await gate.promise
          return executor.execute(input)
        },
      }
      const runtime = makeRuntime({ pool: runtimePool, jtiNamespace: 'concurrent', executor: blockingExecutor })
      const request = runtime.request()
      const first = runtime.broker.submit(structuredClone(request))
      await entered.promise
      await rejectsCode(runtime.broker.submit(structuredClone(request)), 'BROKER_CAPABILITY_REPLAY')
      gate.resolve()
      const receipt = await first
      assert.equal(receipt.after_state, 'SUCCEEDED')
      assert.equal(blockingExecutor.executionCount, 1)
      assert.equal((await durableCounts(ownerPool)).jtis, 1)
    })

    await t.test('idempotency collision is rejected while a coherent repeat survives restart', async () => {
      await resetActions(ownerPool)
      const keyPair = generateKeyPairSync('ed25519')
      const firstRuntime = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'restart-a' })
      const receipt = await firstRuntime.broker.submit(firstRuntime.request())

      const restarted = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'restart-b' })
      const repeated = await restarted.broker.submit(restarted.request())
      assert.deepEqual(repeated, receipt)
      assert.equal(restarted.executor.executionCount, 0)
      assert.equal((await durableCounts(ownerPool)).jtis, 2)
      assert.deepEqual(await approvalConsumption(ownerPool), { consumed_actions: 1, max_actions: 1 })

      const reissuedApproval = restarted.request()
      reissuedApproval.approval.policy_evaluation.decision_id = 'decision_reissued_demo_002'
      reissuedApproval.signedCapability = restarted.authority.issue({
        proposal: reissuedApproval.proposal,
        workflow: reissuedApproval.workflow,
        approval: reissuedApproval.approval,
        workloadIdentity: CALLER_IDENTITY,
      })
      await rejectsCode(restarted.broker.submit(reissuedApproval), 'BROKER_IDEMPOTENCY_CONFLICT')
      assert.equal(restarted.executor.executionCount, 0)
      assert.deepEqual(await approvalConsumption(ownerPool), { consumed_actions: 1, max_actions: 1 })

      const collisionRequest = restarted.request()
      collisionRequest.proposal.proposal_id = 'proposal_ticketpilot_collision_001'
      collisionRequest.signedCapability = restarted.authority.issue({
        proposal: collisionRequest.proposal,
        workflow: collisionRequest.workflow,
        approval: collisionRequest.approval,
        workloadIdentity: CALLER_IDENTITY,
      })
      await rejectsCode(restarted.broker.submit(collisionRequest), 'BROKER_IDEMPOTENCY_CONFLICT')
      assert.equal(restarted.executor.executionCount, 0)
      assert.deepEqual(await approvalConsumption(ownerPool), { consumed_actions: 1, max_actions: 1 })
    })

    await t.test('concurrent distinct actions cannot exceed approval max_actions', async () => {
      await resetActions(ownerPool)
      const keyPair = generateKeyPairSync('ed25519')
      const executor = new DeterministicPilotExecutor()
      const first = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'limit-a', executor })
      const second = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'limit-b', executor })
      const outcomes = await Promise.allSettled([
        first.broker.submit(first.request('101')),
        second.broker.submit(second.request('102')),
      ])
      assert.equal(outcomes.filter(item => item.status === 'fulfilled').length, 1)
      const rejected = outcomes.find(item => item.status === 'rejected')
      assert.equal(rejected?.reason?.code, 'BROKER_APPROVAL_ACTION_LIMIT_EXCEEDED')
      assert.equal(executor.executionCount, 1)
      assert.deepEqual(await approvalConsumption(ownerPool), { consumed_actions: 1, max_actions: 1 })
      const counts = await durableCounts(ownerPool)
      assert.deepEqual(counts, { actions: 1, idempotency: 1, jtis: 1, receipts: 1, transitions: 3 })
    })

    await t.test('INDETERMINATE is durable and never automatically re-executed', async () => {
      await resetActions(ownerPool)
      const keyPair = generateKeyPairSync('ed25519')
      const uncertainExecutor = {
        executionCount: 0,
        assertSupported() {},
        async execute() {
          this.executionCount += 1
          throw new Error('opaque no-effect executor uncertainty')
        },
      }
      const first = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'indeterminate-a', executor: uncertainExecutor })
      const receipt = await first.broker.submit(first.request())
      assert.equal(receipt.after_state, 'INDETERMINATE')
      assert.equal(uncertainExecutor.executionCount, 1)

      const restarted = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'indeterminate-b' })
      assert.deepEqual(await restarted.broker.submit(restarted.request()), receipt)
      assert.equal(restarted.executor.executionCount, 0)
      assert.equal((await restarted.broker.getAction(receipt.proposal_id)).state, 'INDETERMINATE')
    })

    await t.test('a cut after IN_FLIGHT is recovered as INDETERMINATE without execution', async () => {
      await resetActions(ownerPool)
      const keyPair = generateKeyPairSync('ed25519')
      const interrupted = makeRuntime({
        pool: runtimePool,
        keyPair,
        jtiNamespace: 'cut-a',
        lifecycle: { afterClaim: async () => { throw new Error('simulated process stop') } },
      })
      await rejectsCode(interrupted.broker.submit(interrupted.request()), 'BROKER_IN_FLIGHT_INTERRUPTED')
      assert.equal(interrupted.executor.executionCount, 0)
      assert.equal((await interrupted.broker.getAction('proposal_ticketpilot_001')).state, 'IN_FLIGHT')

      const restarted = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'cut-b', now: RECOVERY_NOW })
      assert.deepEqual(await restarted.broker.recoverInFlight(), { recovered: 1 })
      const action = await restarted.broker.getAction('proposal_ticketpilot_001')
      assert.equal(action.state, 'INDETERMINATE')
      assert.equal(restarted.executor.executionCount, 0)
      const receipt = await restarted.store.getReceipt('action_ticketpilot_001')
      assert.equal(receipt.after_state, 'INDETERMINATE')

      const repeated = makeRuntime({ pool: runtimePool, keyPair, jtiNamespace: 'cut-c', now: RECOVERY_NOW })
      assert.deepEqual(await repeated.broker.submit(repeated.request()), receipt)
      assert.equal(repeated.executor.executionCount, 0)
    })

    await t.test('PostgreSQL rejects an undeclared transition without changing durable state', async () => {
      await resetActions(ownerPool)
      const runtime = makeRuntime({ pool: runtimePool, jtiNamespace: 'forbidden' })
      const receipt = await runtime.broker.submit(runtime.request())
      await assert.rejects(
        ownerPool.query(
          `SELECT dubsar_broker.transition_action(
            $1, 'IN_FLIGHT', 'BROKER', $2, 'INVALID_REENTRY', $3
          )`,
          ['action_ticketpilot_001', BROKER_IDENTITY.workload_id, NOW],
        ),
        error => error?.code === '23514',
      )
      const action = await runtime.broker.getAction(receipt.proposal_id)
      assert.equal(action.state, 'SUCCEEDED')
      assert.equal(action.transitions.length, 3)
    })

    await t.test('runtime role has no direct mutation privilege on protected tables', async () => {
      await resetActions(ownerPool)
      const runtime = makeRuntime({ pool: runtimePool, jtiNamespace: 'permissions' })
      await runtime.broker.submit(runtime.request())
      for (const statement of [
        "UPDATE dubsar_broker.broker_actions SET state = 'INDETERMINATE'",
        'DELETE FROM dubsar_broker.broker_actions',
        `INSERT INTO dubsar_broker.broker_approval_usage
          (approval_digest, approval_id, max_actions, consumed_actions, created_at, updated_at)
         VALUES ('sha256:${'a'.repeat(64)}', 'approval_forbidden_001', 1, 0, clock_timestamp(), clock_timestamp())`,
      ]) {
        await assert.rejects(runtimePool.query(statement), error => error?.code === '42501')
      }
      await assert.rejects(
        runtimePool.query(
          `SELECT dubsar_broker.transition_action(
            'action_ticketpilot_001', 'IN_FLIGHT', 'BROKER', $1, 'BYPASS', $2
          )`,
          [BROKER_IDENTITY.workload_id, NOW],
        ),
        error => error?.code === '42501',
      )
      const action = await runtime.broker.getAction('proposal_ticketpilot_001')
      assert.equal(action.state, 'SUCCEEDED')
    })
    await t.test('exact v2 uses PostgreSQL idempotency across two independent Broker gates', async () => {
      await resetActions(ownerPool)
      const f = setupExact(), otherGate = setupExact().gate
      const diagnosticEvents = []
      const store = new PostgresActionStore({ pool: diagnosticPool(runtimePool, diagnosticEvents) })
      const first = new PostgresActionBroker({ ...f.brokerOptions, store })
      const second = new PostgresActionBroker({ ...f.brokerOptions, store, exactActionGate: otherGate })
      const requests = [await f.request(), await f.request()]
      const results = await Promise.allSettled([first.submit(requests[0]), second.submit(requests[1])])
      t.diagnostic(JSON.stringify({ diagnostic: 'exact-concurrency-v1',
        outcomes: results.map(diagnosticOutcome), events: diagnosticEvents,
        counts: await durableCounts(ownerPool), executions: f.state.executions.length,
        states: (await ownerPool.query('SELECT state, count(*)::integer AS n FROM dubsar_broker.broker_actions GROUP BY state')).rows,
        consumption: (await ownerPool.query('SELECT consumed_actions, max_actions FROM dubsar_broker.broker_approval_usage')).rows }))
      assert.ok(results.some(result => result.status === 'fulfilled'))
      assert.equal(f.state.executions.length, 1)
      const replay = await second.submit(await f.request())
      assertExactReceipt(replay)
      assert.equal(f.state.executions.length, 1)
      assert.deepEqual(await store.getReceipt('action_ticketpilot_001'), replay)
    })

    await t.test('exact v2 recovery persists mission after provider call and finalization failure', async () => {
      await resetActions(ownerPool)
      const f = setupExact(), store = new PostgresActionStore({ pool: runtimePool })
      const interruptedStore = {
        claim: input => store.claim(input), listInFlight: () => store.listInFlight(),
        async finalize() { throw Object.assign(new Error('simulated outage'), { code: 'BROKER_STORAGE_UNAVAILABLE' }) },
      }
      const first = new PostgresActionBroker({ ...f.brokerOptions, store: interruptedStore })
      await assert.rejects(first.submit(await f.request()), error => error.code === 'BROKER_FINALIZATION_UNCERTAIN')
      const restarted = new PostgresActionBroker({ ...f.brokerOptions, store })
      assert.deepEqual(await restarted.recoverInFlight(), { recovered: 1 })
      const receipt = await restarted.submit(await f.request())
      assertExactReceipt(receipt)
      assert.equal(receipt.after_state, 'INDETERMINATE')
      assert.deepEqual(receipt.exact_action.binding, f.binding)
      assert.equal(f.state.executions.length, 1)
    })

    await t.test('exact admission expiry after SQL returns rolls back PostgreSQL consumption', async () => {
      await resetActions(ownerPool)
      const f = setupExact()
      const pool = { async connect() {
        const client = await runtimePool.connect()
        return {
          async query(sql, values) {
            const result = await client.query(sql, values)
            if (sql.includes('dubsar_broker.claim_action(')) f.state.now = f.decision.expires_at
            return result
          }, release: () => client.release(),
        }
      } }
      const broker = new PostgresActionBroker({ ...f.brokerOptions, store: new PostgresActionStore({ pool }) })
      await assert.rejects(broker.submit(await f.request()))
      for (const table of ['broker_actions', 'broker_consumed_jtis', 'broker_approval_usage', 'broker_idempotency']) {
        assert.equal((await ownerPool.query(`SELECT count(*)::integer AS count FROM dubsar_broker.${table}`)).rows[0].count, 0)
      }
      assert.equal(f.state.executions.length, 0)
    })
    await syntheticExactActionPostgresTests(t, { ownerPool, recordsPool, runtimePool })
    await finalizationUpgradeTests(t, { ownerPool, runtimePool })
    await deadlockReproduction(t, { ownerPool, runtimePool, expectDeadlock: false })
    await exactRecordsTests(t, { ownerPool, recordsPool, runtimePool })
    await artifactTests(t, { ownerPool, recordsPool, runtimePool, artifactPool })
    await humanTests(t, { ownerPool, recordsPool, brokerPool: runtimePool, artifactPool })
  } finally {
    await artifactPool?.end()
    await recordsPool?.end()
    await runtimePool?.end()
    await ownerPool.query('TRUNCATE dubsar_broker.broker_approval_usage CASCADE').catch(() => {})
    await ownerPool.end()
  }
})

function makeRuntime({
  pool,
  keyPair = generateKeyPairSync('ed25519'),
  jtiNamespace,
  executor = new DeterministicPilotExecutor(),
  lifecycle,
  now = NOW,
}) {
  let jtiSequence = 0
  const kid = 'core-key_postgres_demo_001'
  const authority = new Ed25519CapabilityAuthority({
    signingKey: keyPair.privateKey,
    kid,
    clock: { now: () => now },
    jtiFactory: () => `jti_pg_${jtiNamespace}_${String(++jtiSequence).padStart(3, '0')}_abcdefghijklmnopqrstu`,
  })
  const keyRing = new StaticEd25519PublicKeyRing({ keys: [{ kid, publicKey: keyPair.publicKey }] })
  const store = new PostgresActionStore({ pool })
  const broker = new PostgresActionBroker({
    clock: { now: () => now },
    capabilityVerifier: new Ed25519CapabilityVerifier({ keyRing }),
    workloadIdentityProvider: { current: async () => structuredClone(CALLER_IDENTITY) },
    executor,
    brokerIdentity: BROKER_IDENTITY,
    store,
    lifecycle,
  })
  return {
    authority,
    broker,
    executor,
    store,
    request(suffix = '001') {
      const proposal = fixture('action-proposal')
      if (suffix !== '001') {
        proposal.proposal_id = `proposal_ticketpilot_${suffix}`
        proposal.run_id = `run_ticketpilot_${suffix}`
        proposal.step_id = `step_create_ticket_${suffix}`
        proposal.idempotency_key = `idem_ticketpilot_action_${suffix}`
      }
      const workflow = fixture('workflow-ir')
      const approval = fixture('approval-record')
      return {
        proposal,
        workflow,
        approval,
        signedCapability: authority.issue({
          proposal,
          workflow,
          approval,
          workloadIdentity: CALLER_IDENTITY,
        }),
        previousEvidenceDigest: PREVIOUS_EVIDENCE,
      }
    },
  }
}

async function humanTests(t, pools) {
  const { ownerPool, recordsPool } = pools
  await resetActions(ownerPool)
  const q = await qualification(pools)
  try {
    let prepared, decision
    await t.test('A04 real artifacts are served in full and a changed displayed digest is refused', async () => {
      prepared = await q.prepare()
      assert.deepEqual(prepared.display, q.f.display)
      await assert.rejects(q.decide({ ...prepared, display_digest: `sha256:${'0'.repeat(64)}` }), /BINDING_MISMATCH/)
      const effect = q.f.prepared.expected_effect
      q.f.prepared.expected_effect = 'changed action'
      await assert.rejects(q.decide(prepared), /BINDING_MISMATCH/)
      q.f.prepared.expected_effect = effect
    })
    await t.test('A05 concurrent identical decisions return one immutable result, conflicting choices fail', async () => {
      const results = await Promise.all([q.decide(prepared), q.decide(prepared)])
      assert.deepEqual(results[0], results[1]); decision = results[0].result.decision_ref
      await assert.rejects(q.decide(prepared, 'REFUSE'), /CONFLICT/)
      const read = await q.service.handle('view', { proof: q.proof, presentation_id: prepared.presentation_id })
      assert.deepEqual(read.result, results[0].result)
      assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_human.decision_sessions WHERE decision_ref=$1', [decision])).rows[0].n, 1)
    })
    await t.test('A06 actual Core and Broker consume a session-bound decision once', async () => {
      const receipt = await q.execute(decision)
      assertExactReceipt(receipt)
      assert.equal(q.f.state.executions.length, 1)
    })
    await t.test('A05 refusal persists without an executable exact decision', async () => {
      const p = await q.prepare(), result = await q.decide(p, 'REFUSE')
      assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_exact_records.decisions WHERE decision_ref=$1', [result.result.decision_ref])).rows[0].n, 0)
    })
    await t.test('A05 fresh process can reread the committed presentation result', async () => {
      const child = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', `
        import pg from 'pg';
        const u=new URL(process.env.DUBSAR_TEST_POSTGRES_URL);u.username='dubsar_exact_records_runtime';u.password='';
        const p=new pg.Pool({connectionString:u.toString()});
        try { const r=await p.query('SELECT result FROM dubsar_human.presentations WHERE presentation_id=$1',[process.argv[1]]);
          process.stdout.write(JSON.stringify(r.rows[0].result)); } finally { await p.end(); }
      `, prepared.presentation_id], { cwd: new URL('../../', import.meta.url), timeout: 10000 })
      assert.equal(JSON.parse(child.stdout).decision_ref, decision)
    })
    for (const after of [false, true]) await t.test(`A05 human decision COMMIT response failure after=${after} recovers idempotently`, async () => {
      let fault = false
      const pool = { async connect() {
        const c = await recordsPool.connect()
        return { on: (...a) => c.on(...a), removeListener: (...a) => c.removeListener(...a), release: v => c.release(v),
          async query(sql, values) { if (sql === 'COMMIT' && fault) { fault = false; if (after) await c.query(sql, values); throw new Error('test response loss') }
            return c.query(sql, values) } }
      } }
      const other = await qualification({ ...pools, recordsPool: pool })
      try {
        const p = await other.prepare(); fault = true
        await assert.rejects(other.decide(p), /STORAGE_UNAVAILABLE/)
        const result = await other.decide(p)
        assert.equal(result.result.choice, 'APPROVE')
        assert.deepEqual(await other.decide(p), result)
      } finally { await other.close() }
    })
    await t.test('A03 runtime cannot administer mappings or undo session revocation', async () => {
      await assert.rejects(recordsPool.query('UPDATE dubsar_human.memberships SET enabled=true'), e => e.code === '42501')
      await assert.rejects(recordsPool.query('UPDATE dubsar_human.sessions SET revoked=false'), e => e.code === '42501')
      await assert.rejects(recordsPool.query('DELETE FROM dubsar_human.decision_sessions'), e => e.code === '42501')
      await assert.rejects(recordsPool.query('UPDATE dubsar_human.memberships SET lock_marker=true'), e => e.code === '23514')
    })
    for (const publicationFirst of [false, true]) await t.test(`A03 real membership/decide lock order publicationFirst=${publicationFirst}`, async () => {
      let armed = false, runtimePid, enter, release
      const entered = new Promise(r => { enter = r }), released = new Promise(r => { release = r })
      // Observe and pause the real runtime transaction before COMMIT; no authority mock.
      const pool = { async connect() {
        const c = await recordsPool.connect(); runtimePid = c.processID
        return { on: (...a) => c.on(...a), removeListener: (...a) => c.removeListener(...a), release: v => c.release(v),
          async query(sql, values) {
            if (sql === 'COMMIT' && armed) { armed = false; enter(); await released }
            return c.query(sql, values)
          } }
      } }
      const other = await qualification({ ...pools, recordsPool: pool })
      const admin = await ownerPool.connect()
      let deciding, disabling
      const waitBlocked = async (pid, blocker) => {
        const deadline = Date.now() + 3000
        while (Date.now() < deadline) {
          const row = (await ownerPool.query(`SELECT wait_event_type, pg_blocking_pids(pid) AS blockers
            FROM pg_stat_activity WHERE pid=$1`, [typeof pid === 'function' ? pid() : pid])).rows[0]
          if (row?.wait_event_type === 'Lock' && row.blockers.includes(blocker)) return
          await new Promise(r => setTimeout(r, 10))
        }
        assert.fail('Expected PostgreSQL blocking relationship was not observed')
      }
      try {
        const p = await other.prepare(), before = await other.observe(p.presentation_id)
        await admin.query('BEGIN')
        if (publicationFirst) {
          armed = true
          deciding = other.decide(p).then(value => ({ value }), error => ({ error }))
          let timer
          try { await Promise.race([entered, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('publication barrier timeout')), 3000) })]) }
          finally { clearTimeout(timer) }
          disabling = admin.query('UPDATE dubsar_human.memberships SET enabled=false WHERE context_key=$1', [other.scope])
            .then(() => ({ ok: true }), error => ({ error }))
          await waitBlocked(admin.processID, runtimePid)
          release()
          const published = await deciding
          assert.equal(published.error, undefined)
          assert.equal((await disabling).error, undefined)
          await admin.query('COMMIT')
          const persisted = await other.observe(p.presentation_id)
          assert.deepEqual(persisted.result, published.value.result)
          assert.equal(persisted.decisions, 1); assert.equal(persisted.links, 1)
          await assert.rejects(other.execute(published.value.result.decision_ref), /MEMBERSHIP_DENIED/)
          assert.deepEqual(await other.observe(p.presentation_id), persisted)
        } else {
          await admin.query('UPDATE dubsar_human.memberships SET enabled=false WHERE context_key=$1', [other.scope])
          deciding = other.decide(p).then(value => ({ value }), error => ({ error }))
          await waitBlocked(() => runtimePid, admin.processID)
          await admin.query('COMMIT')
          assert.match((await deciding).error?.message ?? '', /MEMBERSHIP_DENIED/)
          assert.deepEqual(await other.observe(p.presentation_id), before)
        }
      } finally {
        release()
        if (!publicationFirst) await admin.query('ROLLBACK')
        if (deciding) await deciding
        if (disabling) await disabling
        await admin.query('ROLLBACK'); admin.release()
        await ownerPool.query('UPDATE dubsar_human.memberships SET enabled=true WHERE context_key=$1', [other.scope])
        await other.close()
      }
    })
    await t.test('A02 non-approver membership is rejected by the authoritative schema', async () => {
      await assert.rejects(ownerPool.query("UPDATE dubsar_human.memberships SET active_function='operator' WHERE context_key=$1", [q.scope]), e => e.code === '23514')
    })
    await t.test('A03 revocation waits for current authority transaction and then prevents new admission', async () => {
      let enter, release
      const entered = new Promise(r => { enter = r }), released = new Promise(r => { release = r })
      const current = q.records.withCurrent(decision, async () => { enter(); await released })
      await entered
      let done = false
      const revoke = q.revoke().then(() => { done = true })
      try { await new Promise(r => setTimeout(r, 40)); assert.equal(done, false) }
      finally { release() }
      await current; await revoke
      await assert.rejects(q.records.withCurrent(decision, async () => {}), /SESSION_DENIED/)
      await assert.rejects(q.execute(decision), /SESSION_DENIED/)
      assert.equal(q.f.state.executions.length, 1)
      await assert.rejects(q.prepare(), /SESSION_DENIED/)
      await assert.rejects(ownerPool.query('UPDATE dubsar_human.sessions SET revoked=false WHERE context_key=$1 AND session_id=$2', [q.scope, q.proof.claims.session]), e => e.code === '23514')
    })
  } finally { await q.close() }
}

async function schemaDigest(pool) {
  const [columns, constraints, functions] = await Promise.all([
    pool.query(`
      SELECT table_name, column_name, data_type, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_schema = 'dubsar_broker'
      ORDER BY table_name, ordinal_position
    `),
    pool.query(`
      SELECT c.relname AS table_name, con.conname, pg_get_constraintdef(con.oid, true) AS definition
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'dubsar_broker'
      ORDER BY c.relname, con.conname
    `),
    pool.query(`
      SELECT p.proname, pg_get_functiondef(p.oid) AS definition
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'dubsar_broker'
      ORDER BY p.proname
    `),
  ])
  return domainSeparatedHash('dubsar.broker.postgres-schema.v1', {
    columns: columns.rows,
    constraints: constraints.rows,
    functions: functions.rows,
  })
}

async function durableCounts(pool) {
  const result = await pool.query(`
    SELECT
      (SELECT count(*)::integer FROM dubsar_broker.broker_actions) AS actions,
      (SELECT count(*)::integer FROM dubsar_broker.broker_idempotency) AS idempotency,
      (SELECT count(*)::integer FROM dubsar_broker.broker_consumed_jtis) AS jtis,
      (SELECT count(*)::integer FROM dubsar_broker.broker_receipts) AS receipts,
      (SELECT count(*)::integer FROM dubsar_broker.broker_action_transitions) AS transitions
  `)
  return result.rows[0]
}

async function approvalConsumption(pool) {
  const result = await pool.query(`
    SELECT consumed_actions, max_actions
    FROM dubsar_broker.broker_approval_usage
  `)
  assert.equal(result.rowCount, 1)
  return result.rows[0]
}

async function resetActions(pool) {
  await pool.query('TRUNCATE dubsar_broker.broker_approval_usage CASCADE')
}

function runtimeDatabaseUrl(databaseUrl) {
  const url = new URL(databaseUrl)
  url.username = RUNTIME_ROLE
  url.password = ''
  return url.toString()
}

function fixture(kind) {
  return JSON.parse(fs.readFileSync(new URL(`../../fixtures/v1/${kind}/valid.json`, import.meta.url), 'utf8'))
}

function deferred() {
  let resolve
  const promise = new Promise(resolvePromise => { resolve = resolvePromise })
  return { promise, resolve }
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, error => error?.code === code && error?.message === code)
}

async function syntheticExactActionPostgresTests(t, { ownerPool, recordsPool, runtimePool }) {
  // Real records, Core, gates and Broker; only identity, artifacts and provider are fixtures.
  const recordsFor = (f, pool = recordsPool) => new PostgresExactActionRecords({ pool, waitMs: 10000,
    context: { tenant_ref: f.binding.tenant_ref, project_ref: f.binding.project_ref, mission: f.binding.mission } })
  async function seed(caseId) {
    await resetActions(ownerPool)
    await ownerPool.query('TRUNCATE dubsar_exact_records.authorities CASCADE')
    const f = setupSyntheticExact(caseId)
    const records = recordsFor(f)
    await records.setPrincipal(f.state.record.principal)
    await records.publish({ binding: f.binding, prepared: f.prepared, decision: f.decision,
      presentedDigest: f.decision.display_digest })
    return f
  }
  function runtime(f, { pool = recordsPool, store = new PostgresActionStore({ pool: runtimePool }), executor = f.brokerOptions.executor } = {}) {
    const gate = new ExactActionGate({ records: recordsFor(f, pool),
      artifacts: { read: async ref => f.state.artifacts.get(ref) } })
    const authority = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock, exactActionGate: gate })
    return { broker: new PostgresActionBroker({ ...f.brokerOptions, exactActionGate: gate, store, executor }),
      request: async () => ({ proposal: structuredClone(f.proposal), approval: structuredClone(f.approval),
        workflow: structuredClone(f.workflow), signedCapability: await authority.issueExact(f.issueInput()),
        previousEvidenceDigest: PREVIOUS_EVIDENCE }) }
  }

  await t.test('SX15 observed PostgreSQL claim lock wait crosses expiry and rolls back every admission row', async () => {
    const f = await seed('SX15')
    let claimPid, claimReturned = false
    const observedPool = { async connect() {
      const client = await recordsPool.connect()
      return { on: (...args) => client.on(...args), removeListener: (...args) => client.removeListener(...args),
        release: broken => client.release(broken), async query(sql, values) {
          if (sql.includes('dubsar_broker.claim_action(')) claimPid = client.processID
          const result = await client.query(sql, values)
          if (sql.includes('dubsar_broker.claim_action(')) claimReturned = true
          return result
        } }
    } }
    const r = runtime(f, { pool: observedPool }), request = await r.request()
    const blocker = await ownerPool.connect()
    let admission
    try {
      await blocker.query('BEGIN')
      // SHARE conflicts with INSERT's ROW EXCLUSIVE; the tables initially contain no admission.
      await blocker.query('LOCK TABLE dubsar_broker.broker_approval_usage IN SHARE MODE')
      admission = r.broker.submit(request).then(value => ({ value }), error => ({ error }))
      const deadline = Date.now() + 5000
      let observed = false
      while (Date.now() < deadline) {
        const row = (await ownerPool.query(`SELECT wait_event_type, pg_blocking_pids(pid) AS blockers
          FROM pg_stat_activity WHERE pid=$1`, [claimPid ?? null])).rows[0]
        if (row?.wait_event_type === 'Lock' && row.blockers.includes(blocker.processID)) { observed = true; break }
        await new Promise(resolve => setTimeout(resolve, 10))
      }
      assert.equal(observed, true, 'real claim waiter must be blocked by our transaction before advancing the clock')
      assert.equal(claimReturned, false)
      f.state.now = new Date(Date.parse(f.decision.expires_at) + 1).toISOString()
    } finally {
      await blocker.query('ROLLBACK')
      blocker.release()
      // Always settle the pending submit before later tests truncate its tables.
      if (admission) await admission
    }
    const outcome = await admission
    // Current claimInTransaction maps the capability-expiry exception to this
    // generic storage code; the observed lock, clock and rollback prove the path.
    assert.equal(outcome.error?.code, 'BROKER_STORAGE_UNAVAILABLE')
    assert.equal(claimReturned, true, 'SQL returned, then the real admission recheck rejected expiry')
    assert.deepEqual(await durableCounts(ownerPool), { actions: 0, idempotency: 0, jtis: 0, receipts: 0, transitions: 0 })
    assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_broker.broker_approval_usage')).rows[0].n, 0)
    assert.equal(f.state.executions.length, 0)
  })

  await t.test('SX16 two independent PostgreSQL gates resume one exact request with one admission and dispatch', async () => {
    const f = await seed('SX16'), first = runtime(f), second = runtime(f)
    const request = await first.request()
    const results = await Promise.allSettled([first.broker.submit(request), second.broker.submit(structuredClone(request))])
    const completed = results.filter(result => result.status === 'fulfilled')
    assert.equal(completed.length, 1)
    assert.equal(results.filter(result => result.status === 'rejected').length, 1)
    assert.equal(f.state.executions.length, 1)
    assertExactReceipt(completed[0].value)
    assert.deepEqual(completed[0].value.exact_action.binding, f.binding)
    const counts = await durableCounts(ownerPool)
    assert.equal(counts.actions, 1)
    assert.equal(counts.idempotency, 1)
    assert.equal(counts.jtis, 1)
    assert.equal(counts.receipts, 1)
    assert.equal((await approvalConsumption(ownerPool)).consumed_actions, 1)
    const replay = await second.broker.submit(await second.request())
    assert.deepEqual(replay, completed[0].value)
    assert.equal(f.state.executions.length, 1)
    assert.equal((await approvalConsumption(ownerPool)).consumed_actions, 1)
  })

  await t.test('SX17 hidden provider acceptance and lost response recover as indeterminate without a second dispatch', async () => {
    const f = await seed('SX17'), store = new PostgresActionStore({ pool: runtimePool })
    // Harness-only oracle. Neither accepted status nor provider id is returned to the Broker.
    const oracle = { accepted: 0 }
    const executor = { ...f.brokerOptions.executor, async execute(input) {
      await f.brokerOptions.executor.execute(input)
      oracle.accepted++
      throw new Error('synthetic provider response lost')
    } }
    const interruptedStore = {
      claim: input => store.claim(input),
      claimInTransaction: (input, transaction) => store.claimInTransaction(input, transaction),
      listInFlight: () => store.listInFlight(),
      async finalize() { throw Object.assign(new Error('synthetic process interruption'), { code: 'BROKER_STORAGE_UNAVAILABLE' }) },
    }
    const first = runtime(f, { store: interruptedStore, executor })
    await assert.rejects(first.broker.submit(await first.request()), error => error.code === 'BROKER_FINALIZATION_UNCERTAIN')
    assert.equal(oracle.accepted, 1)
    assert.equal(f.state.executions.length, 1)
    assert.equal((await store.listInFlight()).length, 1)
    assert.equal((await durableCounts(ownerPool)).receipts, 0)
    const restarted = runtime(f, { store, executor })
    assert.deepEqual(await restarted.broker.recoverInFlight(), { recovered: 1 })
    const receipt = await restarted.broker.submit(await restarted.request())
    assertExactReceipt(receipt)
    assert.equal(receipt.after_state, 'INDETERMINATE')
    assert.deepEqual(receipt.exact_action.binding, f.binding)
    assert.deepEqual(await restarted.broker.recoverInFlight(), { recovered: 0 })
    assert.equal(oracle.accepted, 1)
    assert.equal(f.state.executions.length, 1)
    assert.equal((await approvalConsumption(ownerPool)).consumed_actions, 1)
    assert.equal((await durableCounts(ownerPool)).actions, 1)
    assert.equal((await durableCounts(ownerPool)).receipts, 1)
    // No positive provider reconciliation, delivery or business-outcome assertion is made here.
  })
}

async function exactRecordsTests(t, { ownerPool, recordsPool, runtimePool }) {
  const ctx = f => ({ tenant_ref: f.binding.tenant_ref, project_ref: f.binding.project_ref, mission: f.binding.mission })
  const publish = (records, f) => records.publish({ binding: f.binding, prepared: f.prepared,
    decision: f.decision, presentedDigest: f.decision.display_digest })
  const make = (f, overrides = {}) => new PostgresExactActionRecords({ pool: recordsPool, context: ctx(f), ...overrides })
  async function seed(mutate = () => {}) {
    await resetActions(ownerPool)
    await ownerPool.query('TRUNCATE dubsar_exact_records.authorities CASCADE')
    const f = setupExact()
    mutate(f)
    const records = make(f)
    await records.setPrincipal(f.state.record.principal)
    await publish(records, f)
    return { f, records }
  }
  function runtime(f, records, store = new PostgresActionStore({ pool: runtimePool })) {
    const gate = new ExactActionGate({ records, artifacts: { async read(ref) {
      if (f.state.onRead) await f.state.onRead(ref)
      return f.state.artifacts.get(ref)
    } } })
    const authority = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock, exactActionGate: gate })
    return { broker: new PostgresActionBroker({ ...f.brokerOptions, store, exactActionGate: gate }),
      async issueRequest() {
        return { proposal: structuredClone(f.proposal), approval: structuredClone(f.approval), workflow: structuredClone(f.workflow),
          signedCapability: await authority.issueExact(f.issueInput()), previousEvidenceDigest: PREVIOUS_EVIDENCE }
      } }
  }
  async function noConsumption(f) {
    assert.equal(f.state.executions.length, 0)
    assert.deepEqual(await durableCounts(ownerPool), { actions: 0, idempotency: 0, jtis: 0, receipts: 0, transitions: 0 })
    assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_broker.broker_approval_usage')).rows[0].n, 0)
  }
  async function waitForBlocked(fragment) {
    const deadline = Date.now() + 2500
    while (Date.now() < deadline) {
      const rows = await ownerPool.query(`SELECT pid FROM pg_stat_activity WHERE usename = 'dubsar_exact_records_runtime'
        AND wait_event_type = 'Lock' AND position($1 in query) > 0`, [fragment])
      if (rows.rowCount > 0) return
      await new Promise(r => setTimeout(r, 5))
    }
    assert.fail(`no PostgreSQL lock waiter observed for ${fragment}`)
  }

  await t.test('D01 exact documents survive a new process with identical digests', async () => {
    const { f, records } = await seed()
    const before = await records.withCurrent(f.decision.decision_ref, value => value)
    const child = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', `
      import pg from 'pg';
      import { PostgresExactActionRecords } from './src/exact-action/postgres-records.mjs';
      const url = new URL(process.env.DUBSAR_TEST_POSTGRES_URL);
      url.username = 'dubsar_exact_records_runtime'; url.password = '';
      const pool = new pg.Pool({ connectionString: url.toString(), connectionTimeoutMillis: 3000 });
      try {
        const records = new PostgresExactActionRecords({ pool, context: JSON.parse(process.env.EXACT_TEST_CONTEXT) });
        const value = await records.withCurrent('decision:exact:1', value => value);
        process.stdout.write(JSON.stringify(value));
      } finally { await pool.end(); }
    `], { cwd: new URL('../../', import.meta.url), env: { ...process.env, EXACT_TEST_CONTEXT: JSON.stringify(ctx(f)) }, timeout: 10000 })
    const after = JSON.parse(child.stdout)
    assert.deepEqual(after, before)
    assert.equal(hashExact('decision', after.decision), hashExact('decision', f.decision))
  })

  await t.test('D02 two real authority adapters and Core/Broker persist a single exact action', async () => {
    const { f } = await seed()
    const events = []
    const observedRecords = diagnosticPool(recordsPool, events, 'records')
    const observedBroker = diagnosticPool(runtimePool, events, 'broker')
    const first = runtime(f, make(f, { pool: observedRecords }), new PostgresActionStore({ pool: observedBroker }))
    const second = runtime(f, make(f, { pool: observedRecords }), new PostgresActionStore({ pool: observedBroker }))
    const requests = [await first.issueRequest(), await second.issueRequest()]
    const results = await Promise.allSettled([first.broker.submit(requests[0]), second.broker.submit(requests[1])])
    const observedEvents = events.slice()
    const counters = { executions: f.state.executions.length }
    try {
      counters.receipts = (await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_broker.broker_receipts')).rows[0].n
    } catch { counters.receipts = 'UNAVAILABLE' }
    try {
      counters.consumed_actions = (await ownerPool.query('SELECT consumed_actions FROM dubsar_broker.broker_approval_usage')).rows[0]?.consumed_actions ?? 'UNAVAILABLE'
    } catch { counters.consumed_actions = 'UNAVAILABLE' }
    t.diagnostic(JSON.stringify({ scenario: 'D02', results: results.map(diagnosticOutcome), events: observedEvents, counters }))
    assert.ok(results.some(result => result.status === 'fulfilled'))
    assert.equal(f.state.executions.length, 1)
    const receipt = await second.broker.submit(await second.issueRequest())
    assertExactReceipt(receipt)
    assert.equal(f.state.executions.length, 1)
    assert.equal((await approvalConsumption(ownerPool)).consumed_actions, 1)
  })

  for (const variant of ['tenant', 'project', 'mission', 'missing', 'refused', 'revoked', 'ineligible', 'function']) {
    await t.test(`D03 ${variant} denies before new consumption or effect`, async () => {
      const { f, records } = await seed(f => { if (variant === 'refused') f.decision.decision = 'REFUSE' })
      // A signed request from the fixture is deliberately untrusted with respect
      // to the current PostgreSQL authority; Broker must resolve the latter.
      const request = await f.request().catch(() => null)
      let selected = records
      if (['tenant', 'project', 'mission'].includes(variant)) {
        const changed = structuredClone(ctx(f))
        if (variant === 'mission') changed.mission.id = 'mis_other'
        else changed[`${variant}_ref`] = `${variant}_other`
        selected = make(f, { context: changed })
      }
      if (variant === 'missing') await ownerPool.query('TRUNCATE dubsar_exact_records.authorities CASCADE')
      if (variant === 'revoked') await records.revoke(f.decision.decision_ref)
      if (variant === 'ineligible' || variant === 'function') await records.setPrincipal({ ...f.state.record.principal,
        eligible: variant !== 'ineligible', active_function: variant === 'function' ? 'other' : 'reviewer' })
      const current = runtime(f, selected)
      await assert.rejects(current.issueRequest())
      if (request) await assert.rejects(current.broker.submit(request))
      await noConsumption(f)
    })
  }

  for (const mutation of ['revocation', 'eligibility', 'function']) {
    await t.test(`D04/D05/D07 admission holds SQL locks against concurrent ${mutation}`, async () => {
      const { f, records } = await seed()
      const first = runtime(f, records), other = make(f)
      const request = await first.issueRequest()
      const entered = deferred(), release = deferred()
      f.state.onRead = async () => { entered.resolve(); await release.promise }
      const admission = first.broker.submit(request)
      // Attach handlers immediately so test failures cannot produce unhandled rejections.
      admission.catch(() => {})
      await entered.promise
      const change = mutation === 'revocation' ? other.revoke(f.decision.decision_ref)
        : other.setPrincipal({ ...f.state.record.principal, eligible: mutation !== 'eligibility',
          active_function: mutation === 'function' ? 'other' : 'reviewer' })
      change.catch(() => {})
      try {
        await waitForBlocked(mutation === 'revocation' ? 'UPDATE dubsar_exact_records.revocations' : 'INSERT INTO dubsar_exact_records.authorities')
      } finally { release.resolve() }
      await Promise.all([admission, change])
      assert.equal(f.state.executions.length, 1)
      assert.equal((await approvalConsumption(ownerPool)).consumed_actions, 1)
      delete f.state.onRead
      await assert.rejects(runtime(f, other).issueRequest())
    })
  }

  await t.test('D06 callback failure rolls back/releases and permits a fresh read', async () => {
    const { f, records } = await seed()
    await assert.rejects(records.withCurrent(f.decision.decision_ref, () => { throw new Error('callback stopped') }), /callback stopped/)
    await make(f).setPrincipal({ ...f.state.record.principal, eligible: false })
    assert.equal(await records.withCurrent(f.decision.decision_ref, row => row.principal.eligible), false)
    await noConsumption(f)
  })

  await t.test('D06 lock timeout refuses and a retry after lock release can read current state', async () => {
    const { f } = await seed()
    const blocker = await ownerPool.connect()
    try {
      await blocker.query('BEGIN')
      await blocker.query('SELECT * FROM dubsar_exact_records.authorities FOR UPDATE')
      await assert.rejects(make(f, { waitMs: 50 }).withCurrent(f.decision.decision_ref, () => assert.fail()), /SQL_TIMEOUT/)
      await noConsumption(f)
    } finally { await blocker.query('ROLLBACK'); blocker.release() }
    assert.equal(await make(f).withCurrent(f.decision.decision_ref, row => row.revoked), false)
  })

  await t.test('D06 connection loss during read fails before Broker consumption', async () => {
    const { f } = await seed()
    let killed = false
    const pool = { async connect() {
      const client = await recordsPool.connect()
      const original = client.query.bind(client)
      const wrapped = {
        on: (...args) => client.on(...args), removeListener: (...args) => client.removeListener(...args),
        release: broken => client.release(broken),
        async query(sql, values) {
          if (!killed && sql.startsWith('SELECT subject, documents')) {
            killed = true
            await ownerPool.query('SELECT pg_terminate_backend($1)', [client.processID])
          }
          return original(sql, values)
        },
      }
      return wrapped
    } }
    await assert.rejects(runtime(f, make(f, { pool })).broker.submit(await f.request()), /STORAGE_UNAVAILABLE/)
    await noConsumption(f)
    assert.equal(await make(f).withCurrent(f.decision.decision_ref, row => row.revoked), false)
  })

  await t.test('D08 immutable/idempotent publication cannot reset revoked state', async () => {
    const { f, records } = await seed()
    await publish(make(f), f)
    await records.revoke(f.decision.decision_ref)
    await publish(records, f)
    assert.equal(await records.withCurrent(f.decision.decision_ref, row => row.revoked), true)
    const changed = structuredClone(f.decision)
    changed.decision = 'REFUSE'
    await assert.rejects(records.publish({ binding: f.binding, prepared: f.prepared, decision: changed,
      presentedDigest: changed.display_digest }), /IMMUTABLE_CONFLICT/)
    assert.deepEqual(await records.withCurrent(f.decision.decision_ref, row => row.decision), f.decision)
  })

  await t.test('D06 session lost during artifact read, then revocation, leaves zero admission', async () => {
    const { f, records } = await seed()
    const request = await f.request()
    const entered = deferred(), release = deferred()
    let authorityPid
    const pool = { async connect() {
      const client = await recordsPool.connect()
      authorityPid = client.processID
      return client
    } }
    f.state.onRead = async () => { entered.resolve(); await release.promise }
    const broker = runtime(f, make(f, { pool })).broker
    const admission = broker.submit(request)
    admission.catch(() => {})
    try {
      await entered.promise
      assert.equal((await ownerPool.query('SELECT pg_terminate_backend($1) AS killed', [authorityPid])).rows[0].killed, true)
      await records.revoke(f.decision.decision_ref)
      assert.equal(await records.withCurrent(f.decision.decision_ref, row => row.revoked), true)
    } finally { release.resolve() }
    await assert.rejects(admission, /STORAGE_UNAVAILABLE/)
    await noConsumption(f)
  })

  for (const interruption of ['disconnect', 'expiry']) {
    await t.test(`D06 ${interruption} after claim SQL rolls back the shared admission transaction`, async () => {
      const { f } = await seed()
      let claimReturned = false
      const pool = { async connect() {
        const client = await recordsPool.connect()
        return {
          on: (...args) => client.on(...args), removeListener: (...args) => client.removeListener(...args),
          release: broken => client.release(broken),
          async query(sql, values) {
            const result = await client.query(sql, values)
            if (sql.includes('dubsar_broker.claim_action(')) {
              claimReturned = true
              if (interruption === 'expiry') f.state.now = f.decision.expires_at
              else await ownerPool.query('SELECT pg_terminate_backend($1)', [client.processID])
            }
            return result
          },
        }
      } }
      await assert.rejects(runtime(f, make(f, { pool })).broker.submit(await f.request()))
      assert.equal(claimReturned, true)
      await noConsumption(f)
    })
  }

  await t.test('D08 exact runtime cannot migrate, rewrite documents, delete or undo revocation', async () => {
    const { f, records } = await seed()
    await records.revoke(f.decision.decision_ref)
    for (const statement of [
      'CREATE TABLE dubsar_exact_records.forbidden (id integer)',
      'DELETE FROM dubsar_exact_records.decisions',
      "UPDATE dubsar_exact_records.decisions SET documents = '{}'::jsonb",
      'TRUNCATE dubsar_exact_records.revocations',
    ]) await assert.rejects(recordsPool.query(statement), error => error.code === '42501')
    await assert.rejects(recordsPool.query('UPDATE dubsar_exact_records.revocations SET revoked = false'), error => error.code === '23514')
    await assert.rejects(applyBrokerMigrations(recordsPool), error => error.code === '42501')
    await assert.rejects(ownerPool.query("UPDATE dubsar_exact_records.decisions SET documents = '{}'::jsonb"), error => error.code === '23514')
    assert.deepEqual((await applyBrokerMigrations(ownerPool)).applied, [])
    assert.equal((await recordsPool.query("SELECT has_schema_privilege(current_user, 'dubsar_exact_records', 'CREATE') AS allowed")).rows[0].allowed, false)
  })
}

async function artifactTests(t, { ownerPool, recordsPool, runtimePool, artifactPool }) {
  const f = setupExact()
  const exactContext = { tenant_ref: f.binding.tenant_ref, project_ref: f.binding.project_ref, mission: f.binding.mission }
  const context = { tenant_id: 'tenant:artifact-test', corpus_id: null, mission_id: 'mission:artifact-test', exact_context: exactContext }
  const key = randomBytes(32), keys = { get: async () => key }
  const state = { available: true, allowed: true, now: NOW }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dubsar-artifact-pg-'))
  const blobs = await LocalEncryptedBlobs.open({ root, context, keys })
  const metadata = new PostgresArtifactMetadata({ pool: artifactPool, context })
  const evidence = { async record(event) {
    if (!state.available) throw new Error('fixture unavailable')
    return { ...event, evidence_ref: `evidence:${event.artifact_id}` }
  } }
  const options = { context, metadata, blobs, policy: { authorize: async () => state.allowed }, evidence,
    clock: { now: () => state.now }, keyRef: 'key:pg-ephemeral' }
  const store = new ArtifactStore(options)
  const input = (id = 'one', value = { text: 'approved bytes' }) => ({ idempotencyKey: id, bytes: canonicalBytes(value), metadata: {
    artifact_type: 'action.payload', media_type: 'application/json', producer: { component: 'fixture', contract_version: '1' },
    origin: { source_ref: null, parent_artifact_ids: [] }, classification: 'internal', expires_at: '2026-08-14T11:00:00.000Z',
    retention_policy: { policy_id: 'policy:fixture', hold: false },
  } })
  const file = ref => path.join(root, createHash('sha256').update(scopeKey(context)).digest('hex'), 'objects', ref.location.slice(5), 'content')
  let counter = 0
  const nextInput = () => input(`fault:${++counter}`)
  try {
    await t.test('B02 artifacts and SQL metadata survive a fresh process with an ephemeral test key', async () => {
      const ref = await store.publish(input('restart'))
      const child = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', `
        import pg from 'pg';
        import { ArtifactStore } from './src/artifacts/artifact-store.mjs';
        import { LocalEncryptedBlobs } from './src/artifacts/local-encrypted-blobs.mjs';
        import { PostgresArtifactMetadata } from './src/artifacts/postgres-metadata.mjs';
        const url = new URL(process.env.DUBSAR_TEST_POSTGRES_URL);
        url.username = 'dubsar_artifact_runtime'; url.password = '';
        const pool = new pg.Pool({ connectionString: url.toString(), connectionTimeoutMillis: 3000 });
        try {
          const context = JSON.parse(process.env.ARTIFACT_TEST_CONTEXT);
          const blobs = await LocalEncryptedBlobs.open({ root: process.env.ARTIFACT_TEST_ROOT, context,
            keys: { get: async () => Buffer.from(process.env.ARTIFACT_TEST_KEY, 'hex') } });
          const metadata = new PostgresArtifactMetadata({ pool, context });
          const store = new ArtifactStore({ context, blobs, metadata, policy: { authorize: async () => true },
            evidence: { record: async () => { throw new Error('read must not write evidence') } },
            clock: { now: () => '${NOW}' }, keyRef: 'key:pg-ephemeral' });
          const result = await store.read(process.env.ARTIFACT_TEST_ID);
          process.stdout.write(JSON.stringify({ reference: result.reference, bytes: result.bytes.toString('base64') }));
        } finally { await pool.end(); }
      `], { cwd: new URL('../../', import.meta.url), timeout: 10000,
        env: { ...process.env, ARTIFACT_TEST_CONTEXT: JSON.stringify(context), ARTIFACT_TEST_ROOT: root,
          ARTIFACT_TEST_KEY: key.toString('hex'), ARTIFACT_TEST_ID: ref.artifact_id } })
      const result = JSON.parse(child.stdout)
      assert.deepEqual(result.reference, ref)
      assert.deepEqual(Buffer.from(result.bytes, 'base64'), input().bytes)
      assert.equal(fs.readFileSync(file(ref)).includes(input().bytes), false)
      assert.equal(fs.readFileSync(file(ref)).includes(key), false)
    })

    await t.test('B03 real PostgreSQL publishers serialize idempotency without overwriting', async () => {
      const second = new ArtifactStore({ ...options, metadata: new PostgresArtifactMetadata({ pool: artifactPool, context }) })
      const refs = await Promise.all([store.publish(input('concurrent')), second.publish(input('concurrent'))])
      assert.deepEqual(refs[0], refs[1])
      await assert.rejects(second.publish(input('concurrent', { text: 'different' })), /IMMUTABLE_CONFLICT/)
      assert.equal((await ownerPool.query('SELECT count(*)::integer AS n FROM dubsar_artifacts.objects WHERE idempotency_key = $1', ['concurrent'])).rows[0].n, 1)
    })

    for (const point of ['before-object', 'after-object', 'evidence']) {
      await t.test(`B04 ${point} failure leaves STAGING unreadable and recovery explicit`, async () => {
        const data = nextInput()
        const interrupted = new ArtifactStore({ ...options, blobs: { scopeKey: blobs.scopeKey, read: (...args) => blobs.read(...args),
          async install(...args) {
            if (point === 'before-object') throw artifactError('ARTIFACT_TEST_INTERRUPTION')
            await blobs.install(...args)
            if (point === 'after-object') throw artifactError('ARTIFACT_TEST_INTERRUPTION')
          } } })
        state.available = point !== 'evidence'
        await assert.rejects(interrupted.publish(data))
        const row = (await ownerPool.query('SELECT artifact_id, state FROM dubsar_artifacts.objects WHERE idempotency_key = $1', [data.idempotencyKey])).rows[0]
        assert.equal(row.state, 'STAGING')
        await assert.rejects(store.read(row.artifact_id), /NOT_PUBLISHED/)
        state.available = true
        if (point === 'before-object') {
          assert.equal((await store.reconcile(row.artifact_id)).state, 'INDETERMINATE')
          await store.publish(data)
        } else assert.equal((await store.reconcile(row.artifact_id)).state, 'PUBLISHED')
        assert.deepEqual((await store.read(row.artifact_id)).bytes, data.bytes)
      })
    }

    for (const afterCommit of [false, true]) {
      await t.test(`B04 metadata failure ${afterCommit ? 'after' : 'before'} COMMIT reconciles without partial publication`, async () => {
        const data = nextInput()
        let commits = 0, failed = false
        const pool = { async connect() {
          const client = await artifactPool.connect()
          return { on: (...args) => client.on(...args), removeListener: (...args) => client.removeListener(...args), release: broken => client.release(broken),
            async query(sql, values) {
              if (sql === 'COMMIT' && ++commits === 2 && !failed) {
                failed = true
                if (afterCommit) await client.query(sql, values)
                throw new Error('simulated connection response loss')
              }
              return client.query(sql, values)
            } }
        } }
        await assert.rejects(new ArtifactStore({ ...options, metadata: new PostgresArtifactMetadata({ pool, context }) }).publish(data), /STORAGE_UNAVAILABLE/)
        const row = (await ownerPool.query('SELECT artifact_id, state FROM dubsar_artifacts.objects WHERE idempotency_key = $1', [data.idempotencyKey])).rows[0]
        assert.equal(row.state, afterCommit ? 'PUBLISHED' : 'STAGING')
        if (!afterCommit) await assert.rejects(store.read(row.artifact_id), /NOT_PUBLISHED/)
        assert.equal((await store.reconcile(row.artifact_id)).state, 'PUBLISHED')
        assert.equal((await store.publish(data)).artifact_id, row.artifact_id)
      })
    }

    await t.test('B04 SQL recovery preserves first publication after transient key and object loss', async () => {
      const ref = await store.publish(input('recovery-identity'))
      const originalGet = keys.get
      keys.get = async () => { throw new Error('temporary key outage') }
      assert.equal((await store.reconcile(ref.artifact_id)).state, 'INDETERMINATE')
      keys.get = originalGet
      state.now = '2026-08-14T10:30:00.000Z'
      for (const field of ['published_at', 'evidence_ref']) {
        await assert.rejects(artifactPool.query(`UPDATE dubsar_artifacts.objects SET reference = jsonb_set(reference, '{${field}}', to_jsonb($1::text)) WHERE artifact_id=$2`,
          [field === 'published_at' ? state.now : 'evidence:replacement', ref.artifact_id]), error => error.code === '23514')
      }
      assert.equal((await store.reconcile(ref.artifact_id)).state, 'PUBLISHED')
      assert.deepEqual((await store.read(ref.artifact_id)).reference, ref)
      const ciphertext = fs.readFileSync(file(ref))
      fs.unlinkSync(file(ref))
      assert.equal((await store.reconcile(ref.artifact_id)).state, 'INDETERMINATE')
      fs.writeFileSync(file(ref), ciphertext, { mode: 0o600 })
      assert.equal((await store.reconcile(ref.artifact_id)).state, 'PUBLISHED')
      assert.deepEqual((await store.read(ref.artifact_id)).reference, ref)
      state.now = NOW
    })

    await t.test('B05 copied artifact ids cannot cross tenant, corpus or mission scopes', async () => {
      const ref = await store.publish(input('scope'))
      for (const field of ['tenant_id', 'corpus_id', 'mission_id']) {
        const changed = { ...context, [field]: 'other-scope' }
        const other = new ArtifactStore({ ...options, context: changed,
          metadata: new PostgresArtifactMetadata({ pool: artifactPool, context: changed }),
          blobs: await LocalEncryptedBlobs.open({ root, context: changed, keys }) })
        await assert.rejects(other.read(ref.artifact_id), /NOT_FOUND/)
        assert.deepEqual((await other.inspectOrphans()).orphans, [])
      }
    })

    await t.test('B07 Core/Broker use real artifact files and exact PostgreSQL decisions; corruption prevents consumption', async () => {
      await resetActions(ownerPool)
      await ownerPool.query('TRUNCATE dubsar_exact_records.authorities CASCADE')
      const payload = await store.publish(input('exact-payload', f.proposal.payload))
      const display = await store.publish(input('exact-display', f.display))
      f.prepared.artifact.ref = payload.artifact_id
      f.prepared.display.ref = display.artifact_id
      f.decision.prepared_digest = hashExact('prepared', f.prepared)
      const records = new PostgresExactActionRecords({ pool: recordsPool, context: exactContext })
      await records.setPrincipal(f.state.record.principal)
      await records.publish({ binding: f.binding, prepared: f.prepared, decision: f.decision, presentedDigest: f.decision.display_digest })
      const gate = new ExactActionGate({ records, artifacts: new ExactArtifactReader({ store, exactContext }) })
      const authority = new Ed25519CapabilityAuthority({ signingKey: f.privateKey, kid: f.kid, clock: f.clock, exactActionGate: gate })
      const broker = new PostgresActionBroker({ ...f.brokerOptions, exactActionGate: gate, store: new PostgresActionStore({ pool: runtimePool }) })
      const request = async () => ({ proposal: structuredClone(f.proposal), approval: structuredClone(f.approval), workflow: structuredClone(f.workflow),
        signedCapability: await authority.issueExact(f.issueInput()), previousEvidenceDigest: PREVIOUS_EVIDENCE })
      const receipt = await broker.submit(await request())
      assertExactReceipt(receipt)
      assert.equal(f.state.executions.length, 1)
      await resetActions(ownerPool)
      f.state.executions.length = 0
      const signedBeforeCorruption = await request()
      const ciphertext = fs.readFileSync(file(payload)); ciphertext[ciphertext.length - 1] ^= 1
      fs.writeFileSync(file(payload), ciphertext)
      await assert.rejects(broker.submit(signedBeforeCorruption), /INTEGRITY_FAILED/)
      await assert.rejects(request(), /INTEGRITY_FAILED/)
      assert.deepEqual(await durableCounts(ownerPool), { actions: 0, idempotency: 0, jtis: 0, receipts: 0, transitions: 0 })
      assert.equal(f.state.executions.length, 0)
      assert.equal((await store.reconcile(payload.artifact_id)).state, 'QUARANTINED')
    })

    await t.test('B08 artifact runtime cannot mutate identity, delete rows or migrate', async () => {
      const ref = await store.publish(input('permissions'))
      for (const sql of ['CREATE TABLE dubsar_artifacts.forbidden(id integer)', 'DELETE FROM dubsar_artifacts.objects',
        "UPDATE dubsar_artifacts.objects SET key_ref = 'other'", 'TRUNCATE dubsar_artifacts.objects']) {
        await assert.rejects(artifactPool.query(sql), error => error.code === '42501')
      }
      await assert.rejects(artifactPool.query("UPDATE dubsar_artifacts.objects SET reference = jsonb_set(reference, '{digest}', to_jsonb($1::text)) WHERE artifact_id=$2",
        [`sha256:${'0'.repeat(64)}`, ref.artifact_id]), error => error.code === '23514')
      await assert.rejects(applyBrokerMigrations(artifactPool), error => error.code === '42501')
      assert.deepEqual((await applyBrokerMigrations(ownerPool)).applied, [])
    })
  } finally {
    // Generated temporary test root only; never a product root or recursive inventory cleanup.
    fs.rmSync(root, { recursive: true, force: true })
    key.fill(0)
  }
}
