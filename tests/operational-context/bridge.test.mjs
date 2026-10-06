import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import {
  OC_BRIDGE_BOUNDS,
  OC_BRIDGE_CONTRACTS,
  OC_BRIDGE_OPERATIONS,
  OC_BRIDGE_PUBLIC_MESSAGES,
  createOperationalContextBridge,
  createOperationalContextKernel,
  OC_CONTRACTS,
  parseBridgeRequest,
  validateObservation,
  validateTrust,
  validateViewRequest,
} from '../../src/operational-context/index.mjs'
import { observation, resource, trust, viewRequest } from './helpers/fixtures.mjs'

const labPath = fileURLToPath(new URL('../../tools/operational-context/bridge-stdio-lab.mjs', import.meta.url))
const bridgeSource = fs.readFileSync(new URL('../../src/operational-context/bridge.mjs', import.meta.url), 'utf8')
const protocolSource = fs.readFileSync(new URL('../../src/operational-context/bridge-protocol.mjs', import.meta.url), 'utf8')
const labSource = fs.readFileSync(new URL('../../tools/operational-context/bridge-stdio-lab.mjs', import.meta.url), 'utf8')
const indexSource = fs.readFileSync(new URL('../../src/operational-context/index.mjs', import.meta.url), 'utf8')

function wrapIngest(error) {
  if ([
    'OC_UNAUTHORIZED', 'OC_AUTHORITY_MISSING', 'OC_REFUSED', 'OC_CONTRACT_INVALID',
    'OC_CONTRACT_UNKNOWN', 'OC_BOUND_EXCEEDED', 'OC_INJECTION_REFUSED',
  ].includes(error?.code)) {
    return { contract: OC_CONTRACTS.ingestResult, outcome: 'rejected', code: error.code, message: error.message }
  }
  if (error?.code === 'OC_AUTHORITY_UNAVAILABLE' || error?.code === 'OC_UNAVAILABLE') {
    return { contract: OC_CONTRACTS.ingestResult, outcome: 'unavailable', code: error.code }
  }
  if (error?.code === 'OC_INTEGRITY_CONFLICT') {
    return { contract: OC_CONTRACTS.ingestResult, outcome: 'integrity_conflict', code: error.code }
  }
  throw error
}

function validatingKernel(overrides = {}) {
  const calls = []
  return {
    calls,
    authority: {
      authorize: async () => ({ decision: 'allow' }),
      revalidate: async () => ({ decision: 'allow' }),
    },
    async ingestObservation(hostTrust, payload) {
      calls.push({ port: 'ingestObservation', trust: hostTrust, payload })
      if (overrides.ingest) return overrides.ingest(hostTrust, payload)
      try {
        validateTrust(hostTrust)
        validateObservation(payload)
        return { contract: OC_CONTRACTS.ingestResult, outcome: 'applied', observation_ref: 'oco_lab' }
      } catch (error) {
        return wrapIngest(error)
      }
    },
    async readView(hostTrust, payload) {
      calls.push({ port: 'readView', trust: hostTrust, payload })
      if (overrides.read) return overrides.read(hostTrust, payload)
      validateTrust(hostTrust)
      validateViewRequest(payload)
      return {
        contract: OC_CONTRACTS.view,
        view_ref: 'ocv_lab',
        instant: '2026-09-18T09:05:00.000Z',
        selection_receipt: 'complete_in_authorized_selection',
        resources: [],
        associations: [],
        reserves: [{ code: 'AUTHORIZED_SELECTION_ONLY' }],
        bounds: {
          max_resources: 20,
          relation_depth: payload.relation_depth,
          max_observations_examined: 200,
          truncated: false,
        },
      }
    },
  }
}

function hostBridge(kernel, hostTrust = trust()) {
  return createOperationalContextBridge({
    kernel,
    async resolveTrust() {
      return hostTrust
    },
  })
}

function requestOf(operation, payload, requestId = 'req-1', extra = {}) {
  return {
    contract: OC_BRIDGE_CONTRACTS.request,
    version: 1,
    request_id: requestId,
    operation,
    payload,
    ...extra,
  }
}

function assertClosedFailure(response, requestId, code) {
  assert.equal(response.contract, OC_BRIDGE_CONTRACTS.response)
  assert.equal(response.version, 1)
  assert.equal(response.request_id, requestId)
  assert.equal(response.ok, false)
  assert.equal(response.error.code, code)
  assert.equal(response.error.message, OC_BRIDGE_PUBLIC_MESSAGES[code] ?? OC_BRIDGE_PUBLIC_MESSAGES.OC_UNAVAILABLE)
  assert.equal(Object.hasOwn(response, 'result'), false)
  assert.deepEqual(Object.keys(response).sort(), ['contract', 'error', 'ok', 'request_id', 'version'])
  assert.deepEqual(Object.keys(response.error).sort(), ['code', 'message'])
  const text = JSON.stringify(response)
  assert.doesNotMatch(text, /postgresql:\/\/|password=|\/workspace\/|\/home\/|\/tmp\/|\/run\/|\/mnt\/|\/data\/|SimulatedAuthority|stack trace|at Kernel\.readView/i)
}

function assertClosedSuccess(response, requestId) {
  assert.equal(response.contract, OC_BRIDGE_CONTRACTS.response)
  assert.equal(response.version, 1)
  assert.equal(response.request_id, requestId)
  assert.equal(response.ok, true)
  assert.equal(Object.hasOwn(response, 'error'), false)
  assert.deepEqual(Object.keys(response).sort(), ['contract', 'ok', 'request_id', 'result', 'version'])
}

test('B01 closed protocol admits only observe and get_context_view', async () => {
  assert.deepEqual([...OC_BRIDGE_OPERATIONS], ['observe', 'get_context_view'])
  const kernel = validatingKernel()
  const bridge = hostBridge(kernel)
  const observe = await bridge.handle(requestOf('observe', observation(), 'req-obs'))
  assertClosedSuccess(observe, 'req-obs')
  assert.equal(observe.result.outcome, 'applied')
  assert.equal(kernel.calls.at(-1).port, 'ingestObservation')
  const view = await bridge.handle(requestOf('get_context_view', viewRequest([resource()]), 'req-view'))
  assertClosedSuccess(view, 'req-view')
  assert.equal(view.result.selection_receipt, 'complete_in_authorized_selection')
  assert.equal(kernel.calls.at(-1).port, 'readView')
  const unknown = await bridge.handle(requestOf('correct', observation(), 'req-correct'))
  assertClosedFailure(unknown, 'req-correct', 'OC_CONTRACT_UNKNOWN')
  assert.equal(kernel.calls.length, 2)
})

test('B01 version, request_id, unknown fields and malformed JSON are refused before kernel', async () => {
  const kernel = validatingKernel()
  const bridge = hostBridge(kernel)
  const badVersion = await bridge.handle({ ...requestOf('observe', observation(), 'req-ver'), version: 2 })
  assertClosedFailure(badVersion, 'req-ver', 'OC_VERSION_CONFLICT')
  const badId = await bridge.handle({ ...requestOf('observe', observation(), 'bad id'), request_id: 'bad id' })
  assertClosedFailure(badId, '', 'OC_CONTRACT_INVALID')
  const extra = await bridge.handle(requestOf('observe', observation(), 'req-extra', { extra: true }))
  assertClosedFailure(extra, 'req-extra', 'OC_CONTRACT_UNKNOWN')
  const malformed = await bridge.handle('{not-json')
  assertClosedFailure(malformed, '', 'OC_CONTRACT_INVALID')
  assert.equal(kernel.calls.length, 0)
  assert.throws(() => parseBridgeRequest(requestOf('rebuild', observation(), 'req-parse')))
})

test('B01 one request yields at most one correlated response', async () => {
  const kernel = validatingKernel()
  const bridge = hostBridge(kernel)
  const first = await bridge.handle(requestOf('observe', observation(), 'req-one'))
  const second = await bridge.handle(requestOf('observe', observation(), 'req-two'))
  assert.equal(first.request_id, 'req-one')
  assert.equal(second.request_id, 'req-two')
  assert.notEqual(first.request_id, second.request_id)
  assert.equal(Array.isArray(first), false)
})

test('B02 client cannot inject trust, scope, grants or DSN', async () => {
  const kernel = validatingKernel()
  const host = trust({ principal_id: 'principal:ops' })
  const bridge = hostBridge(kernel, host)
  const injections = [
    { trust: trust({ principal_id: 'principal:attacker' }) },
    { tenant_id: 'tenant:other' },
    { environment_id: 'env:prod' },
    { principal_id: 'principal:attacker' },
    { grants: [{ action: 'read' }] },
    { permissions: ['read'] },
    { dsn: 'postgresql://secret@127.0.0.1/db' },
    { credentials: { password: 'secret' } },
    { authority: { mode: 'allow' } },
  ]
  for (const [index, extra] of injections.entries()) {
    const response = await bridge.handle(requestOf('observe', observation(), `req-inj-${index}`, extra))
    assertClosedFailure(response, `req-inj-${index}`, 'OC_INJECTION_REFUSED')
  }
  const payloadTrust = await bridge.handle(requestOf('observe', { ...observation(), trust: trust() }, 'req-payload-trust'))
  assertClosedFailure(payloadTrust, 'req-payload-trust', 'OC_INJECTION_REFUSED')
  assert.equal(kernel.calls.length, 0)
})

test('B02 missing host trust or authority fail-closed and SimulatedAuthority is not a production fallback', async () => {
  assert.doesNotMatch(bridgeSource, /SimulatedAuthority/)
  assert.doesNotMatch(protocolSource, /SimulatedAuthority/)
  assert.match(labSource, /SimulatedAuthority/)
  assert.match(labSource, /--lab/)
  assert.throws(
    () => createOperationalContextBridge({ kernel: validatingKernel() }),
    error => error.code === 'OC_AUTHORITY_MISSING',
  )
  assert.throws(
    () => createOperationalContextBridge({
      kernel: { ingestObservation() {}, readView() {} },
      resolveTrust: async () => trust(),
    }),
    error => error.code === 'OC_AUTHORITY_MISSING',
  )
  assert.throws(
    () => createOperationalContextKernel({ pool: { connect() {} } }),
    /authorization port is required/,
  )
  const kernel = validatingKernel()
  const missingTrust = createOperationalContextBridge({
    kernel,
    async resolveTrust() { return null },
  })
  const response = await missingTrust.handle(requestOf('observe', observation(), 'req-no-trust'))
  assertClosedFailure(response, 'req-no-trust', 'OC_AUTHORITY_MISSING')
  const unavailable = createOperationalContextBridge({
    kernel,
    async resolveTrust() {
      const error = new Error('authority unavailable')
      error.code = 'OC_AUTHORITY_UNAVAILABLE'
      throw error
    },
  })
  const down = await unavailable.handle(requestOf('get_context_view', viewRequest([resource()]), 'req-down'))
  assertClosedFailure(down, 'req-down', 'OC_AUTHORITY_UNAVAILABLE')
  assert.equal(kernel.calls.length, 0)
})

test('B03 observe delegates to ingestObservation without a parallel semantic', async () => {
  const kernel = validatingKernel()
  const host = trust()
  const payload = observation({ delivery_id: 'delivery:bridge-b03' })
  const bridge = hostBridge(kernel, host)
  const response = await bridge.handle(requestOf('observe', payload, 'req-b03'))
  assertClosedSuccess(response, 'req-b03')
  assert.equal(response.result.outcome, 'applied')
  assert.equal(kernel.calls.length, 1)
  assert.equal(kernel.calls[0].port, 'ingestObservation')
  assert.equal(kernel.calls[0].trust, host)
  assert.equal(kernel.calls[0].payload, payload)
  const duplicate = await bridge.handle(requestOf('observe', payload, 'req-b03-dup'))
  assert.equal(duplicate.ok, true)
  assert.equal(kernel.calls[1].port, 'ingestObservation')
})

test('B04 get_context_view delegates to readView and preserves receipts', async () => {
  const kernel = validatingKernel({
    async read(_host, payload) {
      validateViewRequest(payload)
      return {
        contract: OC_CONTRACTS.view,
        view_ref: 'ocv_partial',
        instant: '2026-09-18T09:05:00.000Z',
        selection_receipt: 'partial',
        resources: [],
        associations: [],
        reserves: [{ code: 'AUTHORIZED_SELECTION_ONLY' }],
        bounds: { max_resources: 20, relation_depth: payload.relation_depth, max_observations_examined: 200, truncated: true },
      }
    },
  })
  const bridge = hostBridge(kernel)
  const payload = viewRequest([resource()], { relation_depth: 1, properties: ['enabled'] })
  const response = await bridge.handle(requestOf('get_context_view', payload, 'req-b04'))
  assertClosedSuccess(response, 'req-b04')
  assert.equal(response.result.selection_receipt, 'partial')
  assert.equal(kernel.calls[0].port, 'readView')
  assert.equal(kernel.calls[0].payload, payload)
  const denied = createOperationalContextBridge({
    kernel: validatingKernel({
      async read() {
        const error = new Error('generic refusal')
        error.code = 'OC_UNAUTHORIZED'
        throw error
      },
    }),
    async resolveTrust() { return trust() },
  })
  const refusal = await denied.handle(requestOf('get_context_view', payload, 'req-b04-deny'))
  assertClosedFailure(refusal, 'req-b04-deny', 'OC_UNAUTHORIZED')
})

test('B07 transport bounds fail closed without silent complete truncation', async () => {
  const kernel = validatingKernel()
  const bridge = hostBridge(kernel)
  const huge = await bridge.handle(`${'x'.repeat(OC_BRIDGE_BOUNDS.max_request_utf8_bytes + 8)}`)
  assertClosedFailure(huge, '', 'OC_BOUND_EXCEEDED')
  const oversizeObs = await bridge.handle(requestOf('observe', observation({
    delivery_id: 'delivery:oversize',
    result: { kind: 'measured', value_type: 'string', value: 'x'.repeat(70_000) },
  }), 'req-obs-bound'))
  assertClosedSuccess(oversizeObs, 'req-obs-bound')
  assert.equal(oversizeObs.result.outcome, 'rejected')
  assert.equal(oversizeObs.result.code, 'OC_BOUND_EXCEEDED')
  const tooMany = Array.from({ length: 21 }, (_, index) => resource({ source_id: `wf-${index}` }))
  const resources = await bridge.handle(requestOf('get_context_view', viewRequest(tooMany), 'req-res-bound'))
  assert.equal(resources.ok, false)
  assert.equal(resources.request_id, 'req-res-bound')
  assert.ok(['OC_BOUND_EXCEEDED', 'OC_CONTRACT_INVALID'].includes(resources.error.code))
  const depth = await bridge.handle(requestOf('get_context_view', viewRequest([resource()], { relation_depth: 2 }), 'req-depth'))
  assert.equal(depth.ok, false)
  assert.equal(depth.request_id, 'req-depth')
  assert.ok(['OC_BOUND_EXCEEDED', 'OC_CONTRACT_INVALID'].includes(depth.error.code))
  const fat = createOperationalContextBridge({
    kernel: validatingKernel({
      async read() {
        return { blob: 'y'.repeat(OC_BRIDGE_BOUNDS.max_response_utf8_bytes + 32) }
      },
    }),
    async resolveTrust() { return trust() },
  })
  const fatView = await fat.handle(requestOf('get_context_view', viewRequest([resource()]), 'req-fat'))
  assertClosedFailure(fatView, 'req-fat', 'OC_BOUND_EXCEEDED')
  assert.notEqual(fatView.result?.selection_receipt, 'complete_in_authorized_selection')
  const leaky = createOperationalContextBridge({
    kernel: validatingKernel({
      async ingest() {
        throw new Error('failed at /workspace/src/operational-context/kernel.mjs postgresql://secret@127.0.0.1/db')
      },
    }),
    async resolveTrust() { return trust() },
  })
  const leaked = await leaky.handle(requestOf('observe', observation(), 'req-leak'))
  assertClosedFailure(leaked, 'req-leak', 'OC_UNAVAILABLE')
  assert.doesNotMatch(JSON.stringify(leaked), /postgresql:\/\/|\/workspace\/|secret@/)
})

test('B07 error envelopes publish allowlisted messages and never leak host paths', async () => {
  const probes = [
    { id: 'req-path-tmp', leak: 'failed at /tmp/secret', code: 'OC_UNAVAILABLE' },
    { id: 'req-path-run', leak: 'connect unix:/run/private.sock', code: 'OC_UNAUTHORIZED' },
    { id: 'req-path-mnt', leak: 'open /mnt/data/internal', code: 'OC_AUTHORITY_UNAVAILABLE' },
    { id: 'req-path-data', leak: 'read /data/oc/internal/cache', code: 'OC_REFUSED' },
    { id: 'req-dsn', leak: 'postgresql://secret@127.0.0.1/db', code: 'OC_UNAVAILABLE' },
    {
      id: 'req-stack',
      leak: 'Error: boom\n    at Kernel.readView (/workspace/src/operational-context/kernel.mjs:488:5)',
      code: 'OC_UNAVAILABLE',
    },
  ]
  for (const probe of probes) {
    const bridge = createOperationalContextBridge({
      kernel: validatingKernel({
        async read() {
          const error = new Error(probe.leak)
          error.code = probe.code
          throw error
        },
      }),
      async resolveTrust() { return trust() },
    })
    const response = await bridge.handle(requestOf('get_context_view', viewRequest([resource()]), probe.id))
    assertClosedFailure(response, probe.id, probe.code)
    assert.equal(response.error.message, OC_BRIDGE_PUBLIC_MESSAGES[probe.code])
    assert.notEqual(response.error.message, probe.leak)
    assert.doesNotMatch(
      JSON.stringify(response),
      /\/tmp\/secret|\/run\/private\.sock|\/mnt\/data\/internal|\/data\/oc\/internal|postgresql:\/\/|at Kernel\.readView|\/workspace\//,
    )
  }
  assert.equal(Object.keys(OC_BRIDGE_PUBLIC_MESSAGES).length, 13)
})

test('B02/B08 lab harness refuses to start without the explicit lab flag', async () => {
  const child = spawn(process.execPath, [labPath], { stdio: ['ignore', 'pipe', 'pipe'] })
  const stderr = []
  child.stderr.on('data', chunk => stderr.push(chunk))
  const code = await new Promise(resolve => child.on('close', resolve))
  assert.equal(code, 2)
  assert.match(Buffer.concat(stderr).toString('utf8'), /--lab/)
  assert.doesNotMatch(bridgeSource, /createServer|listen\(|net\.Server|http\.|mcp|systemd/)
  assert.doesNotMatch(labSource, /createServer|listen\(|net\.Server|mcp/)
  assert.match(indexSource, /createOperationalContextBridge/)
})
