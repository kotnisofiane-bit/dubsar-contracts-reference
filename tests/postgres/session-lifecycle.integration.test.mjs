import test from 'node:test'
import assert from 'node:assert/strict'
import pg from 'pg'
import { generateKeyPairSync } from 'node:crypto'
import { applyBrokerMigrations } from '../../src/broker/postgres-migrations.mjs'
import { PortalSessionLifecycle } from '../../src/human-identity/lifecycle.mjs'
import { signMessage } from '../../src/human-identity/lifecycle-wire.mjs'
import { qualification } from '../../fixtures/human-identity/v1/qualification.mjs'

test('S09 additive 006 preserves populated 005 records and existing grants', async () => {
  assert.ok(process.env.DUBSAR_TEST_POSTGRES_URL)
  const bootstrap = new pg.Pool({ connectionString: process.env.DUBSAR_TEST_POSTGRES_URL, connectionTimeoutMillis: 1000 })
  const databaseUrl = new URL(process.env.DUBSAR_TEST_POSTGRES_URL)
  databaseUrl.pathname = '/b1_upgrade_006'
  const owner = new pg.Pool({ connectionString: databaseUrl.toString(), connectionTimeoutMillis: 1000 })
  const pools = [bootstrap, owner]
  let q
  try {
    // Dedicated disposable database: migration fixtures cannot reuse principal mappings.
    await bootstrap.query('CREATE DATABASE b1_upgrade_006')
    const roles = ['dubsar_broker_runtime', 'dubsar_exact_records_runtime', 'dubsar_artifact_runtime']
    for (const role of roles) await owner.query(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`)
    const stopBefore006 = { async connect() {
      const client = await owner.connect()
      return { async query(sql, values) {
        if (sql.includes('CREATE TABLE dubsar_human.portal_parents')) throw new Error('PAUSE_BEFORE_006')
        return client.query(sql, values)
      }, release: (...args) => client.release(...args) }
    } }
    await assert.rejects(applyBrokerMigrations(stopBefore006), /PAUSE_BEFORE_006/)
    const history = (await owner.query('SELECT version,sha256 FROM dubsar_broker.schema_migrations ORDER BY version')).rows
    assert.equal(history.length, 5)
    const rolePool = role => { const u = new URL(databaseUrl); u.username = role; u.password = ''; const p = new pg.Pool({ connectionString: u.toString() }); pools.push(p); return p }
    const [brokerPool, recordsPool, artifactPool] = roles.map(rolePool)
    q = await qualification({ ownerPool: owner, brokerPool, recordsPool, artifactPool })
    const presentation = await q.prepare()
    await q.decide(presentation)
    const tables = (await owner.query("SELECT schemaname,tablename FROM pg_tables WHERE schemaname LIKE 'dubsar_%' AND tablename<>'schema_migrations' ORDER BY schemaname,tablename")).rows
    const snapshot = async () => {
      const result = {}
      for (const { schemaname, tablename } of tables) {
        assert.match(schemaname + tablename, /^[a-z0-9_]+$/)
        result[schemaname + '.' + tablename] = (await owner.query(`SELECT to_jsonb(t) AS row FROM ${schemaname}.${tablename} t ORDER BY to_jsonb(t)::text`)).rows
      }
      return result
    }
    const before = await snapshot()
    assert.ok(Object.values(before).some(rows => rows.length > 0))
    const grants = (await owner.query("SELECT table_schema,table_name,grantee,privilege_type FROM information_schema.role_table_grants WHERE table_schema LIKE 'dubsar_%' ORDER BY 1,2,3,4")).rows
    assert.deepEqual((await applyBrokerMigrations(owner)).applied, ['006_portal_session_lifecycle.sql', '007_document_access.sql', '008_operational_context.sql', '009_state_projection.sql'])
    assert.deepEqual(await snapshot(), before)
    assert.deepEqual((await owner.query("SELECT version,sha256 FROM dubsar_broker.schema_migrations WHERE version<'006' ORDER BY version")).rows, history)
    const afterGrants = (await owner.query("SELECT table_schema,table_name,grantee,privilege_type FROM information_schema.role_table_grants WHERE table_schema LIKE 'dubsar_%' ORDER BY 1,2,3,4")).rows
    for (const grant of grants) assert.ok(afterGrants.some(row => JSON.stringify(row) === JSON.stringify(grant)))
    assert.deepEqual((await applyBrokerMigrations(owner)).applied, [])
  } finally { if (q) await q.close(); await Promise.all(pools.map(p => p.end())) }
})

for (const admissionWins of [true, false]) test(`S05/S06/S07/S09 PG: admissionWins=${admissionWins}, closure=${admissionWins ? 'javascript' : 'postgres'}`, async t => {
  assert.ok(process.env.DUBSAR_TEST_POSTGRES_URL, 'PostgreSQL is required, never skipped')
  const owner = new pg.Pool({ connectionString: process.env.DUBSAR_TEST_POSTGRES_URL, connectionTimeoutMillis: 1000 })
  const pools = [owner]
  let q
  try {
    for (const role of ['dubsar_broker_runtime', 'dubsar_exact_records_runtime', 'dubsar_artifact_runtime'])
      await owner.query(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`)
    await applyBrokerMigrations(owner)
    assert.deepEqual((await applyBrokerMigrations(owner)).applied, [])
    await owner.query('ALTER ROLE dubsar_human_lifecycle_runtime LOGIN')
    const rolePool = role => { const u = new URL(process.env.DUBSAR_TEST_POSTGRES_URL); u.username = role; u.password = ''; const p = new pg.Pool({ connectionString: u.toString(), connectionTimeoutMillis: 1000 }); pools.push(p); return p }
    const rawRecordsPool = rolePool('dubsar_exact_records_runtime'), brokerPool = rolePool('dubsar_broker_runtime'), artifactPool = rolePool('dubsar_artifact_runtime'), lifecyclePool = rolePool('dubsar_human_lifecycle_runtime')
    const events = [], poolErrors = []
    rawRecordsPool.on('error', error => { poolErrors.push(error.code ?? 'unknown') })
    let closing = false, endObserved, closedPid
    const ended = new Promise(resolve => { endObserved = resolve })
    const recordsPool = { async connect() {
      const client = await rawRecordsPool.connect(), watched = closing
      if (watched) {
        closedPid = client.processID
        client.on('error', error => events.push({ event: 'error', code: error.code ?? 'unknown', handled: client.listenerCount('error') > 1 }))
        client.once('end', () => { events.push({ event: 'end' }); endObserved() })
      }
      return {
        on: (...args) => client.on(...args), once: (...args) => client.once(...args),
        removeListener: (...args) => client.removeListener(...args),
        async query(sql, values) {
          if (watched && sql.includes("set_config('idle_in_transaction_session_timeout'"))
            values = [values[0], admissionWins ? '6000ms' : '100ms']
          return client.query(sql, values)
        },
        release(destroy) { if (watched) events.push({ event: 'release', destroy: Boolean(destroy) }); client.release(destroy) },
      }
    } }
    const portal = generateKeyPairSync('ed25519'), core = generateKeyPairSync('ed25519')
    let active = true, pause = null, pauseRevocation = null, loseCommitReply = false
    const boundedPool = { async connect() {
      const client = await lifecyclePool.connect()
      return { on: (...args) => client.on(...args), once: (...args) => client.once(...args),
        removeListener: (...args) => client.removeListener(...args), async query(sql, values) {
        const result = await client.query(sql, values)
        if (loseCommitReply && sql === 'COMMIT') { loseCommitReply = false; throw new Error('injected lost COMMIT response') }
        if (pauseRevocation && sql.startsWith('UPDATE dubsar_human.portal_parents SET revoked=true')) await pauseRevocation()
        return result
      }, release: (...args) => client.release(...args) }
    } }
    await owner.query('TRUNCATE dubsar_broker.broker_approval_usage CASCADE')
    q = await qualification({ ownerPool: owner, recordsPool, brokerPool, artifactPool, portalOptions: {
      issuer: 'portal:test', subject: 'external:test', createLifecycle: ({ context, clock }) => new PortalSessionLifecycle({ pool: boundedPool,
        context, clock, humanIssuer: 'portal:test', commandVerifier: { issuer: 'portal', audience: 'core', publicKey: portal.publicKey },
        replySigner: { issuer: 'core', audience: 'portal', privateKey: core.privateKey },
        verifySource: async b => { if (pause && b.purpose === 'admit') await pause(); if (!active) throw new Error('source inactive'); return Math.floor(Date.parse(clock.now()) / 1000) + 300 } }) } })
    const body = { context: q.context, human_issuer: 'portal:test', subject: 'external:test', parent_id: `parent:pg:${admissionWins}` }
    const cmd = (operation, payload) => signMessage({ issuer: 'portal', audience: 'core', operation, body: payload, privateKey: portal.privateKey, now: Date.parse(q.f.clock.now()) })
    const register = cmd('register', { ...body, session_id: q.proof.claims.session, expires_at: q.proof.claims.expires_at })
    await q.portalLifecycle.handle(register)
    // A suspended business port must not retain the parent indefinitely.
    let resumePort, latePort
    closing = true
    const hung = q.records.humanTransaction(async query => {
      await q.portalLifecycle.check(query, q.proof.claims.session)
      latePort = query
      await new Promise(r => { resumePort = r })
      await query('SELECT 1')
    })
    await assert.rejects(hung, admissionWins ? /TRANSACTION_TIMEOUT/ : /STORAGE_UNAVAILABLE/)
    closing = false
    let endTimer
    try { await Promise.race([ended, new Promise((_, reject) => { endTimer = setTimeout(() => reject(new Error('connection end missing')), 1000) })]) }
    finally { clearTimeout(endTimer) }
    assert.deepEqual(events.filter(e => e.event === 'release'), [{ event: 'release', destroy: true }])
    assert.equal(events.filter(e => e.event === 'end').length, 1)
    if (!admissionWins) assert.ok(events.some(e => e.event === 'error' && e.code === '25P03'))
    assert.ok(events.filter(e => e.event === 'error').every(e => e.handled), 'observer never substitutes for product error handling')
    assert.deepEqual(poolErrors, [])
    const fresh = await rawRecordsPool.connect()
    try { assert.notEqual(fresh.processID, closedPid) } finally { fresh.release() }
    t.diagnostic(JSON.stringify({ closure: admissionWins ? 'javascript' : 'postgres', events, poolErrors }))
    assert.equal(typeof resumePort, 'function', 'business port was reached under parent lock')
    await assert.rejects(latePort('SELECT 1'))
    resumePort()
    const unlocked = await owner.connect()
    try {
      await unlocked.query("BEGIN; SET LOCAL lock_timeout='500ms'")
      const row = await unlocked.query('SELECT * FROM dubsar_human.portal_parents WHERE context_key=$1 AND parent_id=$2 FOR UPDATE', [q.scope, body.parent_id])
      assert.equal(row.rowCount, 1)
      await unlocked.query('ROLLBACK')
    } finally { unlocked.release() }
    await assert.rejects(q.portalLifecycle.handle(cmd('register', { ...register.body, context: { ...q.context, mission_id: 'mission:substituted' } })))
    const conflict = signMessage({ issuer: 'portal', audience: 'core', operation: 'register',
      body: { ...register.body, parent_id: 'parent:substituted' }, requestId: register.request_id,
      privateKey: portal.privateKey, now: Date.parse(q.f.clock.now()) })
    await assert.rejects(q.portalLifecycle.handle(conflict))
    const p = await q.prepare()
    const nextProof = q.signClaims({ session: `session:next:${admissionWins}` })
    const nextRegister = cmd('register', { ...body, session_id: nextProof.claims.session, expires_at: nextProof.claims.expires_at })
    loseCommitReply = true
    await assert.rejects(q.portalLifecycle.handle(nextRegister), /lost COMMIT response/)
    await q.portalLifecycle.handle(nextRegister)
    await assert.rejects(q.service.handle('view', { proof: nextProof, presentation_id: p.presentation_id }))
    const nextPresentation = await q.service.handle('prepare', { proof: nextProof, action_ref: 'action:qualification' })
    assert.notEqual(nextPresentation.presentation_id, p.presentation_id)
    const decision = await q.decide(p)
    const cap = await q.issue(decision.result.decision_ref)
    active = false
    await assert.rejects(q.submit(cap))
    assert.equal(q.f.state.executions.length, 0)
    active = true
    let entered, release
    const enteredPromise = new Promise(r => { entered = r }), released = new Promise(r => { release = r })
    let admission, revocation
    if (admissionWins) {
      pause = async () => { entered(); await released }
      admission = q.submit(cap)
      await enteredPromise
      revocation = q.portalLifecycle.handle(cmd('revoke', body))
    } else {
      pauseRevocation = async () => { entered(); await released }
      revocation = q.portalLifecycle.handle(cmd('revoke', body))
      await enteredPromise
      admission = assert.rejects(q.submit(cap))
    }
    // Observe a real lock waiter, not a sleep-based concurrency assertion.
    let blocked = false
    for (let i = 0; i < 100; i++) {
      const r = await owner.query("SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND cardinality(pg_blocking_pids(pid))>0",
        [admissionWins ? 'dubsar_human_lifecycle_runtime' : 'dubsar_exact_records_runtime'])
      if (r.rowCount) { blocked = true; break }
    }
    release(); pause = null; pauseRevocation = null
    assert.equal(blocked, true)
    await admission; await revocation
    assert.equal(q.f.state.executions.length, admissionWins ? 1 : 0)
    await assert.rejects(q.prepare())
    await assert.rejects(q.decide(p))
    await assert.rejects(q.issue(decision.result.decision_ref))
    await assert.rejects(q.submit(cap))
    await assert.rejects(q.portalLifecycle.handle(cmd('register', { ...body, session_id: 'late:child', expires_at: q.proof.claims.expires_at })))
    // Prior successful register replay cannot undo the tombstone.
    await q.portalLifecycle.handle(register)
    await assert.rejects(q.prepare())
    await assert.rejects(rawRecordsPool.query('UPDATE dubsar_human.portal_parents SET revoked=false'))
    await assert.rejects(lifecyclePool.query('UPDATE dubsar_human.memberships SET enabled=true'))
    await assert.rejects(lifecyclePool.query('UPDATE dubsar_human.portal_parents SET revoked=false'))
    assert.equal(q.f.state.executions.length, admissionWins ? 1 : 0)
    const malformed = { ...register, request_id: 'bad:signature' }
    await assert.rejects(q.portalLifecycle.handle(malformed))
  } finally { if (q) await q.close(); await Promise.all(pools.map(p => p.end())) }
})
