import test from 'node:test'
import assert from 'node:assert/strict'
import { setup, request, context } from './helpers/document-access-fixture.mjs'

test('DA01–DA07 real PostgreSQL documentary authorization', { skip: !process.env.DUBSAR_TEST_POSTGRES_URL }, async t => {
  const q = await setup()
  const authorize = () => q.authority.authorize(request(q.proof()))
  const revalidate = d => q.authority.revalidate({ proof: q.proof(), decision_id: d.decision_id, scope_digest: d.scope_digest })
  try {
    await t.test('DA01 persisted exact resources survive a fresh authority instance', async () => {
      const r = await authorize(); assert.equal(r.status, 'allow'); assert.equal(r.decision.resources[0].resource_version, 'v1')
      assert.equal((await q.make().revalidate({ proof: q.proof(), decision_id: r.decision.decision_id, scope_digest: r.decision.scope_digest })).status, 'allow')
      assert.equal((await q.owner.query('SELECT count(*) FROM dubsar_document_access.decisions')).rows[0].count, '1')
      await assert.rejects(q.reader.query('UPDATE dubsar_document_access.decisions SET document=document'), /permission denied/)
      await q.mutate('resource', { ...q.resource, document_ref: 'document:b' })
      await q.mutate('grant', { ...q.grant, document_ref: 'document:b' })
      const refs = ['document:b', 'document:a'].map(document_ref => ({ corpus_ref: 'drive', document_ref }))
      const pair = await q.authority.authorize({ ...request(q.proof()), requested_resources: refs })
      const reversed = await q.authority.authorize({ ...request(q.proof()), requested_resources: [...refs].reverse() })
      assert.equal(pair.status, 'allow'); assert.equal(reversed.status, 'allow')
      assert.deepEqual(pair.decision.resources, reversed.decision.resources)
      assert.deepEqual(pair.decision.resources.map(r => r.document_ref), ['document:a', 'document:b'])
    })
    await t.test('DA02 wrong context, subject, function and unknown resources deny', async () => {
      assert.equal((await q.authority.authorize({ ...request(q.proof()), context: { ...context, tenant_ref: 'tenant:b' } })).status, 'deny')
      assert.equal((await q.authority.authorize(request(q.proof({ subject: 'other' })))).status, 'deny')
      assert.equal((await q.authority.authorize({ ...request(q.proof()), requested_resources: [{ corpus_ref: 'drive', document_ref: 'missing' }] })).status, 'deny')
      await q.mutate('session', { ...q.session, session_ref: 'other-session', active_function: 'other' })
      assert.equal((await q.authority.authorize(request(q.proof({ session: 'other-session' })))).status, 'deny')
    })
    for (const [kind, body] of [['grant', q.grant], ['resource', q.resource], ['membership', q.membership]]) {
      await t.test(`DA04 ${kind} revoked between authorization and revalidation`, async () => {
        const r = await authorize(); assert.equal(r.status, 'allow')
        await q.mutate(kind, { ...body, enabled: false })
        assert.equal((await revalidate(r.decision)).status, 'deny')
        assert.equal((await authorize()).status, 'deny')
        await q.mutate(kind, body)
        assert.equal((await revalidate(r.decision)).status, 'deny')
      })
    }
    await t.test('DA05 version, digest, context and expiration invalidate', async () => {
      const r = await authorize(); assert.equal(r.status, 'allow')
      assert.equal((await revalidate({ ...r.decision, scope_digest: 'sha256:' + '0'.repeat(64) })).status, 'deny')
      assert.equal((await q.make({ context: { ...context, context_ref: 'other' } }).revalidate({ proof: q.proof(), decision_id: r.decision.decision_id, scope_digest: r.decision.scope_digest })).status, 'deny')
      await q.mutate('resource', { ...q.resource, resource_version: 'v2' })
      assert.equal((await revalidate(r.decision)).status, 'deny')
      const fresh = await authorize(); assert.equal(fresh.status, 'allow')
      q.state.now += 61000
      assert.equal((await revalidate(fresh.decision)).status, 'deny')
      q.state.now -= 61000
    })
    await t.test('DA07 reader/admin cannot mutate policy outside epoch port', async () => {
      for (const pool of [q.reader, q.admin]) {
        for (const table of ['grants', 'resources', 'memberships', 'sessions']) {
          await assert.rejects(pool.query(`DELETE FROM dubsar_document_access.${table}`), /permission denied/)
        }
        await assert.rejects(pool.query('UPDATE dubsar_document_access.contexts SET policy_epoch=1'), /permission denied/)
      }
      await assert.rejects(q.reader.query("SELECT dubsar_document_access.mutate('tenant:a','context:a','context','{}')"), /permission denied/)
      const before = (await q.owner.query('SELECT policy_epoch FROM dubsar_document_access.contexts')).rows[0].policy_epoch
      await assert.rejects(q.mutate('grant', { ...q.grant, extra: true }), /invalid documentary fields/)
      assert.equal((await q.owner.query('SELECT policy_epoch FROM dubsar_document_access.contexts')).rows[0].policy_epoch, before)
    })
    await t.test('DA05 expiration during commit never returns an allow', async () => {
      const pool = { async connect() {
        const c = await q.reader.connect()
        return { async query(sql, values) {
          const result = await c.query(sql, values)
          if (sql === 'COMMIT') q.state.now += 61000
          return result
        }, release: () => c.release() }
      } }
      try { assert.equal((await q.make({ pool }).authorize(request(q.proof()))).status, 'deny') }
      finally { q.state.now -= 61000 }
    })
    await t.test('DA02 function rotation requires a new session and explicit new grants', async () => {
      const old = await authorize(); assert.equal(old.status, 'allow')
      await q.mutate('grant', { ...q.grant, enabled: false })
      await q.mutate('membership', { ...q.membership, active_function: 'manager' })
      assert.equal((await revalidate(old.decision)).status, 'deny')
      assert.equal((await authorize()).status, 'deny')
      await q.mutate('session', { ...q.session, session_ref: 'manager-session', active_function: 'manager' })
      const managerRequest = request(q.proof({ session: 'manager-session' }))
      assert.equal((await q.authority.authorize(managerRequest)).status, 'deny')
      await q.mutate('grant', { ...q.grant, active_function: 'manager' })
      assert.equal((await q.authority.authorize(managerRequest)).status, 'allow')
      await q.mutate('membership', q.membership)
      await q.mutate('grant', q.grant)
      assert.equal((await revalidate(old.decision)).status, 'deny')
    })
    await t.test('DA06 deterministic committed revocation wins over blocked revalidation', async () => {
      const r = await authorize(); assert.equal(r.status, 'allow')
      const admin = await q.admin.connect()
      try {
        await admin.query('BEGIN')
        await admin.query('SELECT dubsar_document_access.mutate($1,$2,$3,$4)', [context.tenant_ref, context.context_ref, 'grant', { ...q.grant, enabled: false }])
        const pending = revalidate(r.decision)
        // Observe an actual lock wait, not an assumed sleep ordering.
        let waiting = false
        for (let i = 0; i < 100; i++) {
          const row = (await q.owner.query("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT policy_epoch%'")).rows[0]
          if (Number(row.count) > 0) { waiting = true; break }
          await new Promise(resolve => setTimeout(resolve, 5))
        }
        assert.ok(waiting, 'revalidation must be waiting on epoch')
        await admin.query('COMMIT')
        assert.equal((await pending).status, 'deny')
      } finally { await admin.query('ROLLBACK'); admin.release() }
      await q.mutate('grant', q.grant)
    })
    await t.test('DA06 SQL lock timeout rolls back and next fresh request succeeds', async () => {
      const admin = await q.admin.connect()
      try {
        await admin.query('BEGIN')
        await admin.query('SELECT dubsar_document_access.mutate($1,$2,$3,$4)', [context.tenant_ref, context.context_ref, 'context', {}])
        assert.equal((await authorize()).status, 'unavailable')
      } finally { await admin.query('ROLLBACK'); admin.release() }
      assert.equal((await authorize()).status, 'allow')
    })
    await t.test('DA04 source revocation during a call and permanent session revocation', async () => {
      let checks = 0
      const changing = q.make({ verifySession: async claims => ++checks === 1 && await q.verifySession(claims) })
      assert.equal((await changing.authorize(request(q.proof()))).status, 'deny')
      const r = await authorize(); assert.equal(r.status, 'allow')
      await q.mutate('session', { ...q.session, revoked: true })
      assert.equal((await revalidate(r.decision)).status, 'deny')
      await assert.rejects(q.mutate('session', q.session), /immutable documentary session/)
    })
  } finally { await q.close() }
})
