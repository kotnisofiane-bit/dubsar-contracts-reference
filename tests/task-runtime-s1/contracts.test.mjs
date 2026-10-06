import assert from 'node:assert/strict'
import { createPublicKey, verify } from 'node:crypto'
import fs from 'node:fs'
import test from 'node:test'
import { canonicalJson, domainSeparatedHash } from '../../src/canonical-json.mjs'
import { assertContract, hashContract, hashTaskProfile } from '../../src/contracts.mjs'
import { Ed25519TaskLeaseVerifier } from '../../src/task-manager/ed25519-task-lease-verifier.mjs'
import {
  S1ContractError, S1_DOMAINS, SYNTHETIC_REQUEST_BYTES, SYNTHETIC_REQUEST_DIGEST,
  assertS1ClosedProfile, assertS1EgressReceipt, assertS1LeaseBinding, assertS1Policy,
  assertS1ReferencesClosed, assertS1TaskLease, bindS1TaskAuthorization,
  closedS1Policy, createS1ClosedProfile, hashS1EgressReceipt, hashS1Policy,
  hashS1Profile, hashS1TaskLease, syntheticS1Request,
} from '../../src/task-runtime-s1/contracts.mjs'
import {
  assertS1Envelope, encodeS1LeaseSegment, parseS1SignedTaskLease,
} from '../../src/task-runtime-s1/signed-envelope.mjs'

const read = path => JSON.parse(fs.readFileSync(new URL('../../' + path, import.meta.url), 'utf8'))
const vector = read('fixtures/task-runtime-s1/valid-vector.json')
const goldens = read('fixtures/task-runtime-s1/hash-vectors.json')
const alterations = read('fixtures/task-runtime-s1/alterations.json').vectors
const clone = value => structuredClone(value)
const context = () => ({ lease: clone(vector.lease), closed_profile: clone(vector.closed_profile),
  policy_digest: vector.trust.core_policy_digest })
const refusal = (action, code) => assert.throws(action,
  error => error instanceof S1ContractError && error.code === code)
const differentDigest = 'sha256:' + 'f'.repeat(64)

function replace(base, path, value) {
  const result = clone(base)
  const keys = path.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))
  let parent = result
  for (const key of keys.slice(0, -1)) parent = parent[key]
  assert.ok(Object.hasOwn(parent, keys.at(-1)), 'alterations replace an existing leaf')
  assert.notDeepEqual(parent[keys.at(-1)], value)
  parent[keys.at(-1)] = clone(value)
  return result
}
function differences(left, right, path = '') {
  if (left !== null && right !== null && typeof left === 'object' && typeof right === 'object') {
    return [...new Set([...Object.keys(left), ...Object.keys(right)])]
      .flatMap(key => differences(left[key], right[key], path + '/' + key))
  }
  return Object.is(left, right) ? [] : [path]
}

test('complete S1 vector binds Core, Task Manager, profile, mission, tenant and evidence', () => {
  assert.equal(vector.qualification, 'CONTRACT_ONLY_MODEL_ONLY')
  assert.equal(assertS1ClosedProfile(vector.closed_profile), vector.closed_profile)
  assert.equal(assertS1LeaseBinding(vector.lease, vector.closed_profile), vector.lease)
  assert.deepEqual(vector.lease.task, bindS1TaskAuthorization(vector.closed_profile))
  assert.equal(vector.lease.authority, 'DUBSAR_CORE')
  assert.equal(vector.lease.audience, 'dubsar-task-manager')
  assert.equal(vector.lease.replay_protection.single_use, true)
  assert.equal(assertS1EgressReceipt(vector.receipt, context()), vector.receipt)
  assert.deepEqual(vector.envelope.payload.lease, vector.lease)
})

test('complete signed vector has a valid Ed25519 signature with only a public fixture key', () => {
  const parsed = parseS1SignedTaskLease(vector.envelope.compact)
  assert.deepEqual(parsed.header, vector.envelope.header)
  assert.deepEqual(parsed.payload, vector.envelope.payload)
  assert.equal(parsed.header.kid, vector.trust.core_kid)
  assert.deepEqual(Object.keys(vector.trust.core_public_jwk).sort(), ['crv', 'kty', 'x'])
  const publicKey = createPublicKey({ key: vector.trust.core_public_jwk, format: 'jwk' })
  assert.equal(verify(null, parsed.signingInput, publicKey, parsed.signature), true)
})

test('wire parser deliberately does not admit, trust a key or verify a signature', () => {
  const parts = vector.envelope.compact.split('.')
  const signature = Buffer.from(parts[2], 'base64url')
  signature[0] ^= 1
  const parsed = parseS1SignedTaskLease(parts.slice(0, 2).join('.') + '.' + signature.toString('base64url'))
  const publicKey = createPublicKey({ key: vector.trust.core_public_jwk, format: 'jwk' })
  assert.equal(verify(null, parsed.signingInput, publicKey, parsed.signature), false)
})

test('independent fixed hash vectors match the product canonicalization in every S1 domain', () => {
  const values = { request: syntheticS1Request(), policy: closedS1Policy(),
    profile: vector.closed_profile, lease: vector.lease, receipt: vector.receipt }
  const hashes = { request: SYNTHETIC_REQUEST_DIGEST, policy: hashS1Policy(values.policy),
    profile: hashS1Profile(values.profile), lease: hashS1TaskLease(values.lease),
    receipt: hashS1EgressReceipt(values.receipt, context()) }
  for (const [name, value] of Object.entries(values)) {
    assert.equal(goldens.vectors[name].domain, S1_DOMAINS[name])
    assert.equal(Buffer.byteLength(canonicalJson(value)), goldens.vectors[name].canonical_bytes)
    assert.equal(hashes[name], goldens.vectors[name].digest, name)
    assert.equal(domainSeparatedHash(S1_DOMAINS[name], value), hashes[name])
  }
  assert.equal(canonicalJson(vector.envelope.header), goldens.header_canonical)
  assert.equal(canonicalJson(syntheticS1Request()), goldens.request_canonical)
  assert.equal(SYNTHETIC_REQUEST_BYTES, 179)
})

test('independent receipt goldens cover declared-model and out-of-window refusal fixtures', () => {
  for (const [name, receipt] of Object.entries(vector.receipt_examples)) {
    assert.equal(hashS1EgressReceipt(receipt, context()), goldens.receipt_examples[name].digest, name)
    assert.equal(Buffer.byteLength(canonicalJson(receipt)), goldens.receipt_examples[name].canonical_bytes)
    assert.equal(receipt.enforcement.proof_acquired, false)
    assert.equal(receipt.enforcement.policy_applied, false)
  }
})

test('key insertion order does not alter digests; array order and domains remain significant', () => {
  const reversed = Object.fromEntries(Object.entries(closedS1Policy()).reverse())
  assert.equal(hashS1Policy(reversed), hashS1Policy(closedS1Policy()))
  assert.notEqual(domainSeparatedHash(S1_DOMAINS.lease, vector.closed_profile), hashS1Profile(vector.closed_profile))
  const profile = clone(vector.closed_profile)
  profile.allowed_operations.reverse()
  refusal(() => hashS1Profile(profile), 'S1_PROFILE_INVALID')
})

test('all schema references resolve locally, including frozen v1 common definitions', () => {
  assert.ok(assertS1ReferencesClosed().length > 0)
})

for (const alteration of alterations) {
  test('isolated alteration: ' + alteration.id + ' -> ' + alteration.expected_code, () => {
    const bases = { policy: closedS1Policy(), header: vector.envelope.header,
      lease: vector.lease, receipt: vector.receipt }
    const original = bases[alteration.target]
    const altered = replace(original, alteration.path, alteration.value)
    assert.deepEqual(differences(original, altered), [alteration.path])
    const actions = { policy: () => assertS1Policy(altered),
      header: () => assertS1Envelope(altered, vector.envelope.payload),
      lease: () => assertS1TaskLease(altered),
      receipt: () => assertS1EgressReceipt(altered, context()) }
    refusal(actions[alteration.target], alteration.expected_code)
  })
}

test('closed profile accepts only three trusted pins; caller URLs, routes and limits fail closed', () => {
  const config = { runtime_lock: vector.closed_profile.runtime_lock,
    input_digest: vector.closed_profile.input_digest, enforcer_digest: vector.closed_profile.network.enforcer_digest }
  assert.deepEqual(createS1ClosedProfile(config), vector.closed_profile)
  for (const key of ['url', 'destination', 'route', 'bounds', 'command', 'credentials']) {
    refusal(() => createS1ClosedProfile({ ...config, [key]: 'caller-value' }), 'S1_PROFILE_CONFIG_INVALID')
  }
  for (const [path, value] of [
    ['/limits/cpu_millicores', 501], ['/identity/uid', 65533],
    ['/filesystem/mounts/0/size_bytes', 2097153], ['/capabilities/add/0', 'NET_ADMIN'],
    ['/commands/pilot', 'curl https://example.org'], ['/allowed_outputs/0', '/workspace/out/raw.txt'],
  ]) refusal(() => assertS1ClosedProfile(replace(vector.closed_profile, path, value)), 'S1_PROFILE_INVALID')
})

test('lease bindings require the locally trusted profile and exact input/runtime/enforcer digests', () => {
  refusal(() => assertS1LeaseBinding(vector.lease), 'S1_CLOSED_PROFILE_REQUIRED')
  for (const path of ['/task/input_digest', '/task/profile_digest', '/task/runtime_lock_digest',
    '/task/network/enforcer_digest']) {
    refusal(() => assertS1LeaseBinding(replace(vector.lease, path, differentDigest), vector.closed_profile),
      'S1_LEASE_PROFILE_MISMATCH')
  }
  const profile = clone(vector.closed_profile)
  profile.image = differentDigest
  refusal(() => assertS1ClosedProfile(profile), 'S1_PROFILE_INVALID')
})

test('S1 isolation, operation list and resource fields are fixed even before digest binding', () => {
  for (const [path, value] of [
    ['/task/limits/pids', 257], ['/task/limits/ttl_seconds', 61], ['/task/identity/gid', 65533],
    ['/task/filesystem/rootfs_read_only', false], ['/task/capabilities/add/0', 'NET_ADMIN'],
    ['/task/allowed_operations/0', 'execute'], ['/task/effect', 'write'],
    ['/authority', 'OTHER_AUTHORITY'], ['/audience', 'dubsar-action-broker'], ['/nonce', 'short'],
  ]) refusal(() => assertS1TaskLease(replace(vector.lease, path, value)), 'S1_LEASE_INVALID')
})

test('lease and envelope timestamps are coherent, second-aligned and bounded at 300 seconds', () => {
  const longLease = replace(vector.lease, '/expires_at', '2026-10-04T16:05:00.000Z')
  assertS1TaskLease(longLease)
  for (const [path, value] of [
    ['/issued_at', '2026-10-04T16:00:01.000Z'], ['/issued_at', '2026-10-04T15:59:54.000Z'],
    ['/not_before', '2026-10-04T16:00:00.001Z'], ['/expires_at', '2026-10-04T16:00:00.000Z'],
  ]) refusal(() => assertS1TaskLease(replace(vector.lease, path, value)), 'S1_LEASE_TEMPORAL_INVALID')
  refusal(() => assertS1Envelope(vector.envelope.header,
    replace(vector.envelope.payload, '/iat', vector.envelope.payload.iat - 1)), 'S1_ENVELOPE_TEMPORAL_INVALID')
  refusal(() => assertS1TaskLease(replace(vector.lease, '/expires_at', '2026-10-04T16:00:59.000Z')),
    'S1_LEASE_INVARIANT_INVALID')
})

test('compact envelope rejects noncanonical JSON, malformed signatures, extensions and a wrong lease hash', () => {
  const parts = vector.envelope.compact.split('.')
  const noncanonical = Buffer.from(JSON.stringify(vector.envelope.header, null, 2)).toString('base64url')
  for (const compact of [noncanonical + '.' + parts[1] + '.' + parts[2],
    parts[0] + '.' + parts[1] + '.' + Buffer.alloc(63).toString('base64url'),
    vector.envelope.compact + '=', '', null, 'x'.repeat(32769)]) {
    refusal(() => parseS1SignedTaskLease(compact), 'S1_ENVELOPE_FORMAT_INVALID')
  }
  refusal(() => assertS1Envelope({ ...vector.envelope.header, extra: true }, vector.envelope.payload),
    'S1_ENVELOPE_VERSION_INVALID')
  refusal(() => assertS1Envelope(vector.envelope.header, { ...vector.envelope.payload, extra: true }),
    'S1_ENVELOPE_PAYLOAD_INVALID')
  refusal(() => assertS1Envelope(vector.envelope.header,
    replace(vector.envelope.payload, '/lease_digest', differentDigest)), 'S1_ENVELOPE_DIGEST_MISMATCH')
  refusal(() => assertS1Envelope(vector.envelope.header,
    replace(vector.envelope.payload, '/policy_digest', 123)), 'S1_ENVELOPE_PAYLOAD_INVALID')
  assert.equal(encodeS1LeaseSegment(vector.envelope.header), parts[0])
})

test('Core decision digest remains distinct from requested and effective network policy digests', () => {
  assert.equal(vector.receipt.policy_digest, vector.envelope.payload.policy_digest)
  assert.notEqual(vector.receipt.policy_digest, vector.receipt.requested_policy_digest)
  assert.equal(vector.receipt.requested_policy_digest, vector.receipt.effective_policy_digest)
  refusal(() => assertS1EgressReceipt(vector.receipt, { ...context(), policy_digest: differentDigest }),
    'S1_RECEIPT_BINDING_MISMATCH')
})

test('receipt context is explicit and every identity and digest is correlated', () => {
  refusal(() => assertS1EgressReceipt(vector.receipt), 'S1_RECEIPT_CONTEXT_REQUIRED')
  for (const field of ['lease_id', 'task_id', 'action_id', 'tenant_id', 'mission_id', 'evidence_correlation_id']) {
    refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/' + field, vector.receipt[field] + '_other'), context()),
      'S1_RECEIPT_BINDING_MISMATCH')
  }
  for (const field of ['lease_digest', 'profile_digest', 'runtime_lock_digest']) {
    refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/' + field, differentDigest), context()),
      'S1_RECEIPT_BINDING_MISMATCH')
  }
  refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/effective_policy_digest', differentDigest), context()),
    'S1_EFFECTIVE_POLICY_DIGEST_MISMATCH')
})

test('model receipt never represents a forward or an applied network policy', () => {
  assert.equal(vector.receipt.enforcement.policy_applied, false)
  assert.equal(vector.receipt.enforcement.proof_acquired, false)
  assert.equal(vector.receipt.enforcement.observations_status, 'NONE')
  assert.deepEqual(vector.receipt.enforcement.declared_observations, [])
  assert.equal(vector.receipt.operation.forwarded, false)
  refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/operation/result', 'SUCCEEDED'), context()),
    'S1_RECEIPT_RESULT_INVALID')
  refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/operation/forwarded', true), context()),
    'S1_ENFORCEMENT_PROOF_UNAVAILABLE')
})

function declaredReceipt() {
  return clone(vector.receipt_examples.synthetic_declared)
}

test('synthetic declarations can be structurally valid without acquiring any enforcement proof', () => {
  const receipt = declaredReceipt()
  assertS1EgressReceipt(receipt, context())
  assert.equal(receipt.enforcement.observations_status, 'STRUCTURALLY_VALID')
  assert.equal(receipt.enforcement.proof_acquired, false)
  assert.equal(receipt.enforcement.policy_applied, false)
  assert.equal(receipt.operation.result, 'SIMULATED')
  assert.equal(receipt.operation.forwarded, false)
  for (const proof of [[], receipt.enforcement.declared_observations.slice(1), [null, null, null, null]]) {
    const altered = clone(receipt)
    altered.enforcement.declared_observations = proof
    refusal(() => assertS1EgressReceipt(altered, context()), 'S1_ENFORCEMENT_NOT_PROVEN')
  }
  for (const [path, value] of [
    ['/enforcement/declared_observations/0/source', 'QUALIFIER'],
    ['/enforcement/declared_observations/0/lease_digest', differentDigest],
    ['/enforcement/declared_observations/0/effective_policy_digest', differentDigest],
    ['/enforcement/declared_observations/0/sandbox_id', 'sandbox_other_probe_001'],
    ['/enforcement/declared_observations/0/session_id', 'egress_other_probe_001'],
  ]) refusal(() => assertS1EgressReceipt(replace(receipt, path, value), context()),
    'S1_ENFORCEMENT_BINDING_MISMATCH')
  refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/declared_observations/0/observed_at',
    '2026-10-04T16:00:07.001Z'), context()), 'S1_ENFORCEMENT_TIME_INVALID')
  refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/declared_observations/0/observed_at',
    '2026-10-04T16:00:04.999Z'), context()), 'S1_ENFORCEMENT_TIME_INVALID')
})

test('a proof claim is refused even with four well-formed declarations or caller-supplied trust flags', () => {
  for (const receipt of [vector.receipt, declaredReceipt()]) {
    refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/proof_acquired', true), context()),
      'S1_ENFORCEMENT_PROOF_UNAVAILABLE')
    refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/policy_applied', true), context()),
      'S1_ENFORCEMENT_NOT_PROVEN')
    refusal(() => assertS1EgressReceipt(receipt, { ...context(), trusted_verification: true }),
      'S1_RECEIPT_CONTEXT_REQUIRED')
  }
  refusal(() => assertS1EgressReceipt(replace(declaredReceipt(), '/enforcement/level', 'RUNTIME_OBSERVED'), context()),
    'S1_ENFORCEMENT_NOT_PROVEN')
})

test('a structural-validity claim cannot conceal malformed or miscorrelated declarations', () => {
  const receipt = declaredReceipt()
  refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/observations_status', 'NONE'), context()),
    'S1_ENFORCEMENT_NOT_PROVEN')
  refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/declared_observations/0/kind', {}), context()),
    'S1_ENFORCEMENT_NOT_PROVEN')
  refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/declared_observations/0/evidence_digest', 'missing'), context()),
    'S1_RECEIPT_INVALID')
})

function deniedReceipt(recordedAt = vector.receipt.recorded_at) {
  const receipt = clone(vector.receipt_examples.denied_expired)
  receipt.recorded_at = recordedAt
  return receipt
}

test('missing enforcement fails closed with a denied outcome and no effective policy', () => {
  const receipt = deniedReceipt()
  assertS1EgressReceipt(receipt, context())
  refusal(() => assertS1EgressReceipt(replace(receipt, '/enforcement/policy_applied', true), context()),
    'S1_ENFORCEMENT_NOT_PROVEN')
  refusal(() => assertS1EgressReceipt(replace(receipt, '/operation/attempts', 1), context()),
    'S1_RECEIPT_RESULT_INVALID')
})

test('receipt window is the exact intersection of lease, sandbox TTL and the 30-second grant', () => {
  for (const [path, value] of [
    ['/window/sandbox_created_at', '2026-10-04T15:59:59.000Z'],
    ['/window/expires_at', '2026-10-04T16:00:37.000Z'],
    ['/operation/finished_at', '2026-10-04T16:00:07.101Z'],
    ['/operation/started_at', '2026-10-04T16:00:05.999Z'],
  ]) refusal(() => assertS1EgressReceipt(replace(vector.receipt, path, value), context()),
    'S1_RECEIPT_TEMPORAL_INVALID')
  const lease = replace(vector.lease, '/expires_at', '2026-10-04T16:05:00.000Z')
  const receipt = clone(vector.receipt)
  receipt.lease_digest = hashS1TaskLease(lease)
  receipt.window.not_before = '2026-10-04T16:01:04.000Z'
  receipt.window.expires_at = '2026-10-04T16:01:05.000Z'
  receipt.operation.started_at = '2026-10-04T16:01:04.000Z'
  receipt.operation.finished_at = '2026-10-04T16:01:04.100Z'
  receipt.recorded_at = receipt.operation.finished_at
  assertS1EgressReceipt(receipt, { ...context(), lease })
  const leaseClipped = clone(vector.receipt)
  leaseClipped.window.not_before = '2026-10-04T16:00:59.000Z'
  leaseClipped.window.expires_at = vector.lease.expires_at
  leaseClipped.operation.started_at = '2026-10-04T16:00:59.000Z'
  leaseClipped.operation.finished_at = '2026-10-04T16:00:59.100Z'
  leaseClipped.recorded_at = leaseClipped.operation.finished_at
  assertS1EgressReceipt(leaseClipped, context())
})

test('an attempted operation after revocation is still refused', () => {
  for (const revokedAt of ['2026-10-04T16:00:05.500Z', '2026-10-04T16:00:06.900Z',
    '2026-10-04T16:00:07.000Z']) {
    const receipt = declaredReceipt()
    receipt.window.revoked_at = revokedAt
    refusal(() => assertS1EgressReceipt(receipt, context()), 'S1_RECEIPT_REVOCATION_INVALID')
    receipt.operation.forwarded = true
    refusal(() => assertS1EgressReceipt(receipt, context()), 'S1_RECEIPT_REVOCATION_INVALID')
  }
})

test('DENIED at or after grant and lease expiration records no attempt, transmission or effect', () => {
  for (const recordedAt of ['2026-10-04T16:00:36.000Z', '2026-10-04T16:00:37.000Z',
    '2026-10-04T16:01:01.000Z']) {
    const receipt = deniedReceipt(recordedAt)
    assertS1EgressReceipt(receipt, context())
    assert.equal(receipt.operation.attempts, 0)
    assert.equal(receipt.operation.forwarded, false)
    assert.equal(receipt.operation.request_bytes, 0)
    assert.equal(receipt.operation.response_bytes, 0)
    assert.equal(receipt.operation.started_at, null)
    assert.equal(receipt.operation.finished_at, null)
    assert.equal(receipt.operation.duration_ms, null)
    assert.equal(receipt.operation.gateway_receipt_ref, null)
    assert.equal(receipt.enforcement.proof_acquired, false)
  }
})

test('DENIED after pre-activation revocation uses the refusal time without claiming activation', () => {
  for (const revokedAt of ['2026-10-04T16:00:03.000Z', '2026-10-04T16:00:05.500Z']) {
    const receipt = clone(vector.receipt_examples.denied_revoked_before_activation)
    receipt.window.revoked_at = revokedAt
    assertS1EgressReceipt(receipt, context())
    assert.ok(receipt.window.revoked_at < receipt.recorded_at)
    assert.ok(receipt.recorded_at < receipt.window.not_before)
    assert.equal(receipt.operation.attempts, 0)
    assert.equal(receipt.operation.forwarded, false)
    assert.equal(receipt.operation.request_bytes, 0)
    assert.equal(receipt.operation.started_at, null)
    assert.equal(Object.hasOwn(receipt.window, 'activated_at'), false)
  }
})

test('an out-of-window DENIED cannot conceal any operation, payload, response or Gateway effect', () => {
  for (const receipt of [vector.receipt_examples.denied_expired,
    vector.receipt_examples.denied_revoked_before_activation]) {
    for (const [path, value] of [
      ['/operation/attempts', 1], ['/operation/forwarded', true], ['/operation/request_bytes', 1],
      ['/operation/response_bytes', 1], ['/operation/response_digest', differentDigest],
      ['/operation/generation_tokens', 1], ['/operation/gateway_receipt_ref', 'gateway-receipt_s1_probe_001'],
      ['/operation/started_at', receipt.recorded_at], ['/operation/finished_at', receipt.recorded_at],
      ['/operation/duration_ms', 0],
    ]) refusal(() => assertS1EgressReceipt(replace(receipt, path, value), context()),
      'S1_RECEIPT_RESULT_INVALID')
  }
})

test('late recording never widens the authorization window or permits an expired attempt or forward', () => {
  const receipt = clone(vector.receipt)
  receipt.recorded_at = '2026-10-04T16:01:01.000Z'
  assertS1EgressReceipt(receipt, context())
  const expired = clone(receipt)
  expired.operation.started_at = expired.window.expires_at
  expired.operation.finished_at = '2026-10-04T16:00:36.100Z'
  refusal(() => assertS1EgressReceipt(expired, context()), 'S1_RECEIPT_TEMPORAL_INVALID')
  expired.operation.forwarded = true
  refusal(() => assertS1EgressReceipt(expired, context()), 'S1_RECEIPT_TEMPORAL_INVALID')
  refusal(() => assertS1EgressReceipt(replace(deniedReceipt(), '/window/expires_at',
    '2026-10-04T16:00:37.000Z'), context()), 'S1_RECEIPT_TEMPORAL_INVALID')
})

test('recording and revocation cannot claim events before creation or in the future of the receipt', () => {
  refusal(() => assertS1EgressReceipt(replace(deniedReceipt(), '/recorded_at',
    '2026-10-04T16:00:04.999Z'), context()), 'S1_RECEIPT_TEMPORAL_INVALID')
  refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/recorded_at',
    '2026-10-04T16:00:07.099Z'), context()), 'S1_RECEIPT_TEMPORAL_INVALID')
  refusal(() => assertS1EgressReceipt(replace(deniedReceipt(), '/window/revoked_at',
    '2026-10-04T16:00:07.101Z'), context()), 'S1_RECEIPT_TEMPORAL_INVALID')
  refusal(() => assertS1EgressReceipt(replace(deniedReceipt(), '/window/revoked_at',
    '2026-10-04T15:59:59.999Z'), context()), 'S1_RECEIPT_TEMPORAL_INVALID')
})

test('attempt, byte and token budgets cannot be widened or treated as unobserved success', () => {
  for (const [path, value] of [
    ['/operation/attempts', 2], ['/operation/request_bytes', 4097], ['/operation/response_bytes', 16385],
    ['/operation/generation_tokens', 129], ['/operation/duration_ms', 2001],
  ]) refusal(() => assertS1EgressReceipt(replace(vector.receipt, path, value), context()), 'S1_RECEIPT_INVALID')
  refusal(() => assertS1EgressReceipt(replace(vector.receipt, '/operation/request_bytes', 180), context()),
    'S1_RECEIPT_BUDGET_INVALID')
  refusal(() => assertS1EgressReceipt(replace(declaredReceipt(), '/operation/generation_tokens', null), context()),
    'S1_RECEIPT_RESULT_INVALID')
})

test('synthetic references cannot produce runtime outcomes or a real forward without trust verification', () => {
  for (const result of ['SUCCEEDED', 'FAILED', 'INDETERMINATE']) {
    refusal(() => assertS1EgressReceipt(replace(declaredReceipt(), '/operation/result', result), context()),
      'S1_ENFORCEMENT_PROOF_UNAVAILABLE')
  }
  refusal(() => assertS1EgressReceipt(replace(declaredReceipt(), '/operation/forwarded', true), context()),
    'S1_ENFORCEMENT_PROOF_UNAVAILABLE')
})

test('receipt is closed: secrets, headers and raw payloads have no place in its format', () => {
  for (const field of ['credential', 'token', 'secret', 'headers', 'request', 'response']) {
    refusal(() => assertS1EgressReceipt({ ...vector.receipt, [field]: 'forbidden' }, context()),
      'S1_RECEIPT_INVALID')
    const receipt = clone(vector.receipt)
    receipt.operation[field] = 'forbidden'
    refusal(() => assertS1EgressReceipt(receipt, context()), 'S1_RECEIPT_INVALID')
  }
  for (const field of ['operation', 'window']) {
    refusal(() => assertS1EgressReceipt({ ...vector.receipt, [field]: null }, context()), 'S1_RECEIPT_INVALID')
  }
})

test('S0/v1 frozen profile remains valid and v1 admission explicitly refuses the S1 version', () => {
  const s0Lease = read('fixtures/v1/task-lease/valid.json')
  const s0Profile = read('fixtures/v1/task-lease/closed-profile.json')
  assertContract('task-lease', s0Lease)
  assert.equal(hashTaskProfile(s0Profile), s0Lease.task.profile_digest)
  assert.equal(s0Lease.task.network.policy, 'egress_none')
  assert.throws(() => hashContract('task-lease', vector.lease))
  const verifier = new Ed25519TaskLeaseVerifier({ keyRing: { resolve: () => {
    assert.fail('a v2 envelope must be rejected before resolving a v1 trust key')
  } } })
  assert.throws(() => verifier.verifySigned({ signedTaskLease: vector.envelope.compact,
    now: '2026-10-04T16:00:07.000Z' }), error => error.code === 'TASK_LEASE_ALGORITHM_INVALID')
})
