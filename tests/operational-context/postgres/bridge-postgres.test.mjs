import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { resourceIdentity } from '../../../src/operational-context/identity.mjs'
import {
  OC_BRIDGE_BOUNDS,
  OC_BRIDGE_CONTRACTS,
  createOperationalContextBridge,
} from '../../../src/operational-context/index.mjs'
import { observation, resource, trust, viewRequest } from '../helpers/fixtures.mjs'
import { seedComparability, setupKernel } from '../helpers/postgres.mjs'

const labPath = fileURLToPath(new URL('../../../tools/operational-context/bridge-stdio-lab.mjs', import.meta.url))

function requestOf(operation, payload, requestId) {
  return {
    contract: OC_BRIDGE_CONTRACTS.request,
    version: 1,
    request_id: requestId,
    operation,
    payload,
  }
}

function scopeGrant(principalId, action, extra = {}) {
  const host = trust()
  return {
    tenant_id: host.tenant_id,
    environment_id: host.environment_id,
    principal_id: principalId,
    action,
    ...extra,
  }
}

function spawnLab({ hostTrust, grants }) {
  const child = spawn(process.execPath, [labPath, '--lab'], {
    env: {
      ...process.env,
      OC_HOST_TRUST_JSON: JSON.stringify(hostTrust),
      OC_LAB_GRANTS_JSON: JSON.stringify(grants),
      OC_LAB_CLOCK_NOW: '2026-09-18T09:05:00.000Z',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  child.stderrBuffers = []
  child.stdoutBuffers = []
  child.stderr.on('data', chunk => child.stderrBuffers.push(chunk))
  child.stdout.on('data', chunk => child.stdoutBuffers.push(chunk))
  return child
}

function waitReady(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup()
      reject(new Error(`lab ready timeout: ${Buffer.concat(child.stderrBuffers).toString('utf8')}`))
    }, 8000)
    const onClose = code => {
      cleanup()
      reject(new Error(`lab exited ${code}: ${Buffer.concat(child.stderrBuffers).toString('utf8')}`))
    }
    const tryParse = () => {
      const text = Buffer.concat(child.stderrBuffers).toString('utf8')
      if (text.includes('"ready":true')) {
        cleanup()
        resolve(JSON.parse(text.trim().split('\n').find(line => line.includes('"ready":true'))))
      }
    }
    const cleanup = () => {
      clearTimeout(timer)
      child.stderr.off('data', tryParse)
      child.off('close', onClose)
    }
    child.stderr.on('data', tryParse)
    child.on('close', onClose)
    tryParse()
  })
}

function sendRequest(child, body) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup()
      reject(new Error(`lab response timeout: ${Buffer.concat(child.stdoutBuffers).toString('utf8')}`))
    }, 8000)
    const onData = () => {
      const text = Buffer.concat(child.stdoutBuffers).toString('utf8')
      const nl = text.indexOf('\n')
      if (nl !== -1) {
        cleanup()
        resolve(JSON.parse(text.slice(0, nl)))
      }
    }
    const cleanup = () => {
      clearTimeout(timer)
      child.stdout.off('data', onData)
    }
    child.stdout.on('data', onData)
    child.stdin.write(`${JSON.stringify(body)}\n`)
    onData()
  })
}

function closeLab(child) {
  return new Promise(resolve => {
    child.on('close', resolve)
    child.stdin.end()
  })
}

test('B03 observe delegates to ingestObservation on real PostgreSQL', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const seeded = await seedComparability(ctx.kernel)
  const host = trust()
  const bridge = createOperationalContextBridge({
    kernel: ctx.kernel,
    async resolveTrust() { return host },
  })
  const payload = observation({ subject: seeded.a, delivery_id: 'delivery:bridge-b03' })
  const applied = await bridge.handle(requestOf('observe', payload, 'req-b03-applied'))
  assert.equal(applied.ok, true)
  assert.equal(applied.result.outcome, 'applied')
  const replay = await bridge.handle(requestOf('observe', payload, 'req-b03-replay'))
  assert.equal(replay.ok, true)
  assert.equal(replay.result.outcome, 'duplicate_identical')
  const conflict = await bridge.handle(requestOf('observe', observation({
    subject: seeded.a,
    delivery_id: 'delivery:bridge-b03',
    result: { kind: 'measured', value_type: 'boolean', value: false },
  }), 'req-b03-conflict'))
  assert.equal(conflict.ok, true)
  assert.equal(conflict.result.outcome, 'integrity_conflict')
  const mixed = await bridge.handle(requestOf('observe', observation({
    subject: resource({ tenant_id: 'tenant:other', source_id: 'export-commandes' }),
    delivery_id: 'delivery:bridge-scope',
  }), 'req-b03-scope'))
  assert.equal(mixed.ok, true)
  assert.equal(mixed.result.outcome, 'rejected')
})

test('B04 get_context_view delegates to readView without leaking unauthorized supports', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const seeded = await seedComparability(ctx.kernel)
  await ctx.kernel.ingestObservation(seeded.admin, observation({
    subject: seeded.a,
    delivery_id: 'delivery:bridge-b04-a',
    provenance: { ...observation().provenance, producer_id: 'producer:a' },
  }))
  await ctx.kernel.ingestObservation(seeded.admin, observation({
    subject: seeded.a,
    delivery_id: 'delivery:bridge-b04-b',
    result: { kind: 'measured', value_type: 'boolean', value: false },
    provenance: { ...observation().provenance, producer_id: 'producer:b' },
  }))
  const aRef = resourceIdentity(seeded.a).local_ref
  ctx.authority.grant({
    tenant_id: seeded.admin.tenant_id,
    environment_id: seeded.admin.environment_id,
    principal_id: 'principal:restricted',
    action: 'read',
    resource_local_ref: aRef,
    producer_id: 'producer:a',
  })
  const restricted = createOperationalContextBridge({
    kernel: ctx.kernel,
    async resolveTrust() { return trust({ principal_id: 'principal:restricted' }) },
  })
  const view = await restricted.handle(requestOf(
    'get_context_view',
    viewRequest([seeded.a], { properties: ['enabled'], relation_depth: 0 }),
    'req-b04-view',
  ))
  assert.equal(view.ok, true)
  assert.equal(view.result.selection_receipt, 'complete_in_authorized_selection')
  const text = JSON.stringify(view.result)
  assert.match(text, /producer:a/)
  assert.doesNotMatch(text, /producer:b|hidden_count|redacted|forbidden_support/)
  const deep = await restricted.handle(requestOf(
    'get_context_view',
    viewRequest([seeded.a], { relation_depth: 2 }),
    'req-b04-depth',
  ))
  assert.equal(deep.ok, false)
  assert.ok(['OC_BOUND_EXCEEDED', 'OC_CONTRACT_INVALID'].includes(deep.error.code))
})

test('B05 distinct producer and reader processes persist through PostgreSQL', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const seeded = await seedComparability(ctx.kernel)
  const producerTrust = trust({ principal_id: 'principal:producer-a', principal_kind: 'producer' })
  const readerTrust = trust({ principal_id: 'principal:ops' })
  const payload = observation({ subject: seeded.a, delivery_id: 'delivery:bridge-b05' })
  const viewPayload = viewRequest([seeded.a], { properties: ['enabled'], relation_depth: 0 })

  const producer = spawnLab({
    hostTrust: producerTrust,
    grants: [scopeGrant('principal:producer-a', 'observe')],
  })
  await waitReady(producer)
  const pidA = producer.pid
  const observed = await sendRequest(producer, requestOf('observe', payload, 'req-b05-obs'))
  assert.equal(observed.ok, true, JSON.stringify(observed))
  assert.equal(observed.result.outcome, 'applied')
  const codeA = await closeLab(producer)
  assert.equal(codeA, 0)
  assert.notEqual(pidA, process.pid)

  const reader = spawnLab({
    hostTrust: readerTrust,
    grants: [scopeGrant('principal:ops', 'read')],
  })
  await waitReady(reader)
  const pidB = reader.pid
  assert.notEqual(pidB, pidA)
  assert.notEqual(pidB, process.pid)
  const firstView = await sendRequest(reader, requestOf('get_context_view', viewPayload, 'req-b05-view-1'))
  assert.equal(firstView.ok, true, JSON.stringify(firstView))
  assert.equal(firstView.result.selection_receipt, 'complete_in_authorized_selection')
  assert.match(JSON.stringify(firstView.result), /producer:a/)
  const codeB = await closeLab(reader)
  assert.equal(codeB, 0)

  const readerRestart = spawnLab({
    hostTrust: readerTrust,
    grants: [scopeGrant('principal:ops', 'read')],
  })
  await waitReady(readerRestart)
  const pidB2 = readerRestart.pid
  assert.notEqual(pidB2, pidB)
  assert.notEqual(pidB2, pidA)
  const secondView = await sendRequest(readerRestart, requestOf('get_context_view', viewPayload, 'req-b05-view-2'))
  assert.equal(secondView.ok, true, JSON.stringify(secondView))
  assert.equal(secondView.result.selection_receipt, 'complete_in_authorized_selection')
  assert.match(JSON.stringify(secondView.result), /producer:a/)
  const codeB2 = await closeLab(readerRestart)
  assert.equal(codeB2, 0)
  process.stdout.write(`${JSON.stringify({
    gate: 'oc-bridge-b05',
    pid_parent: process.pid,
    pid_producer_a: pidA,
    pid_reader_b: pidB,
    pid_reader_b_restart: pidB2,
    distinct: pidA !== pidB && pidB !== pidB2 && pidA !== process.pid,
  })}\n`)
})

test('B06 authorization isolation: deny, scope mismatch, producer cannot read', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const seeded = await seedComparability(ctx.kernel)
  await ctx.kernel.ingestObservation(seeded.admin, observation({
    subject: seeded.a,
    delivery_id: 'delivery:bridge-b06',
  }))
  const viewPayload = viewRequest([seeded.a], { properties: ['enabled'] })

  const stranger = spawnLab({
    hostTrust: trust({ principal_id: 'principal:stranger', principal_kind: 'producer' }),
    grants: [],
  })
  await waitReady(stranger)
  const denied = await sendRequest(stranger, requestOf('get_context_view', viewPayload, 'req-b06-deny'))
  assert.equal(denied.ok, false)
  assert.equal(denied.error.code, 'OC_UNAUTHORIZED')
  await closeLab(stranger)

  const mismatch = spawnLab({
    hostTrust: trust({ principal_id: 'principal:restricted' }),
    grants: [scopeGrant('principal:restricted', 'read', { resource_local_ref: resourceIdentity(seeded.b).local_ref })],
  })
  await waitReady(mismatch)
  const scoped = await sendRequest(mismatch, requestOf('get_context_view', viewPayload, 'req-b06-scope'))
  assert.equal(scoped.ok, false)
  assert.equal(scoped.error.code, 'OC_UNAUTHORIZED')
  await closeLab(mismatch)

  const producer = spawnLab({
    hostTrust: trust({ principal_id: 'principal:producer-a', principal_kind: 'producer' }),
    grants: [scopeGrant('principal:producer-a', 'observe')],
  })
  await waitReady(producer)
  const producerRead = await sendRequest(producer, requestOf('get_context_view', viewPayload, 'req-b06-producer'))
  assert.equal(producerRead.ok, false)
  assert.equal(producerRead.error.code, 'OC_UNAUTHORIZED')
  await closeLab(producer)
})

test('B07 lab transport refuses oversized requests without truncation', async t => {
  const ctx = await setupKernel()
  t.after(() => ctx.close())
  const bridge = createOperationalContextBridge({
    kernel: ctx.kernel,
    async resolveTrust() { return trust() },
  })
  const oversize = await bridge.handle(requestOf('observe', observation({
    subject: resource(),
    delivery_id: 'delivery:bridge-b07',
    result: { kind: 'measured', value_type: 'string', value: 'x'.repeat(70_000) },
  }), 'req-b07-obs'))
  assert.equal(oversize.ok, true)
  assert.equal(oversize.result.outcome, 'rejected')
  assert.equal(oversize.result.code, 'OC_BOUND_EXCEEDED')

  const lab = spawnLab({
    hostTrust: trust(),
    grants: [scopeGrant('principal:ops', 'observe')],
  })
  await waitReady(lab)
  lab.stdin.write('z'.repeat(OC_BRIDGE_BOUNDS.max_request_utf8_bytes + 64))
  const line = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('overflow timeout')), 8000)
    const tryParse = () => {
      const text = Buffer.concat(lab.stdoutBuffers).toString('utf8')
      const nl = text.indexOf('\n')
      if (nl !== -1) {
        clearTimeout(timer)
        resolve(JSON.parse(text.slice(0, nl)))
      }
    }
    lab.stdout.on('data', tryParse)
    tryParse()
  })
  assert.equal(line.ok, false)
  assert.equal(line.error.code, 'OC_BOUND_EXCEEDED')
  const code = await closeLab(lab)
  assert.equal(code, 1)
})
