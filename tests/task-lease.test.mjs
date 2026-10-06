import assert from 'node:assert/strict'
import { createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import fs from 'node:fs'
import test from 'node:test'
import {
  CONTRACT_KINDS,
  CONTRACT_SET,
  assertContract,
  bindTaskAuthorization,
  consumeTaskLease,
  hashContract,
  hashTaskProfile,
  taskLeaseAllows,
  validateContract,
} from '../src/contracts.mjs'
import { Ed25519TaskLeaseAuthority } from '../src/core/ed25519-task-lease-authority.mjs'
import {
  TASK_LEASE_AUDIENCE,
  TASK_LEASE_ISSUER,
  TASK_LEASE_SCHEMA,
  TASK_LEASE_TYPE,
  encodeTaskLeaseSegment,
  parseSignedTaskLease,
} from '../src/core/signed-task-lease-format.mjs'
import {
  Ed25519TaskLeaseVerifier,
  TaskManagerPublicKeyRing,
  assertOperationAllowed,
} from '../src/task-manager/ed25519-task-lease-verifier.mjs'
import { InMemoryTaskLeaseReplayStore } from '../src/task-manager/in-memory-task-lease-replay-store.mjs'

const NOW = '2026-08-14T10:00:30.000Z'
const KID = 'core-key_task_lease_demo_001'
const POLICY_DIGEST = 'sha256:2222222222222222222222222222222222222222222222222222222222222222'

test('task-lease is the eighth canonical contract, owned by Core and consumed by the Task Manager', () => {
  assert.equal(CONTRACT_KINDS.length, 8)
  assert.ok(CONTRACT_KINDS.includes('task-lease'))
  const entry = CONTRACT_SET.contracts.find(contract => contract.name === 'task-lease')
  assert.deepEqual(entry, {
    name: 'task-lease',
    schema_path: 'schemas/v1/task-lease.schema.json',
    domain_separator: 'dubsar.contract.task-lease.v1',
    canonical_owner: 'GOVERNANCE_CORE',
    consumer: 'TASK_MANAGER',
  })
  assert.deepEqual(validateContract('task-lease', fixture('valid')), [])
  const invalidErrors = validateContract('task-lease', fixture('invalid'))
  assert.ok(invalidErrors.some(error => /additional property image/.test(error)), 'requester image field is refused')
  assert.ok(invalidErrors.some(error => /uid: number below minimum/.test(error)), 'root identity is refused')
})

test('task lease shares the execution-lease envelope and binds the S0 isolation profile by digest', () => {
  const lease = fixture('valid')
  const closed = closedProfile()
  const executionLease = JSON.parse(fs.readFileSync(new URL('../fixtures/v1/execution-lease/valid.json', import.meta.url), 'utf8'))
  for (const field of ['lease_id', 'authority', 'issued_at', 'not_before', 'expires_at', 'nonce', 'replay_protection']) {
    assert.ok(Object.hasOwn(lease, field) && Object.hasOwn(executionLease, field), field)
  }
  assert.equal(lease.authority, 'DUBSAR_CORE')
  assert.equal(lease.audience, TASK_LEASE_AUDIENCE)
  assert.equal(lease.replay_protection.single_use, true)
  assert.equal(lease.task.effect, 'none')
  assert.equal(lease.task.profile_id, 'dubsar.fixture.patch.v0')
  assert.equal(lease.task.filesystem.rootfs_read_only, true)
  assert.deepEqual(lease.task.capabilities.drop, ['ALL'])
  assert.equal(lease.task.network.policy, 'egress_none')
  assert.ok(lease.task.identity.uid >= 1000 && lease.task.identity.gid >= 1000)
  assert.equal(lease.task.profile_digest, hashTaskProfile(closed))
  assert.deepEqual(lease.task, bindTaskAuthorization(closed))
  assert.equal(Object.hasOwn(lease.task, 'image'), false)
  assert.equal(Object.hasOwn(lease.task, 'commands'), false)
})

test('semantic invariants fail closed on widened or inconsistent task profiles', () => {
  for (const [label, mutate, pattern] of [
    ['sandbox ttl longer than the lease', lease => { lease.task.limits.ttl_seconds = 120 }, /ttl exceeds the lease validity/],
    ['command timeout longer than the ttl', lease => { lease.task.limits.command_timeout_ms = 61000 }, /command timeout exceeds/],
    ['unsorted operations', lease => { lease.task.allowed_operations = ['create', 'collect'] }, /allowed operations must be sorted/],
    ['duplicate mount path', lease => { lease.task.filesystem.mounts[1].path = '/run' }, /mount paths must be unique/],
    ['mounts exceeding the disk limit', lease => { lease.task.limits.disk_bytes = 1 }, /mounted bytes exceed/],
    ['unsorted capabilities', lease => { lease.task.capabilities.add = ['KILL', 'CHOWN'] }, /added capabilities must be sorted/],
    ['validity above 300 seconds', lease => { lease.expires_at = '2026-08-14T10:06:00.000Z' }, /exceeds 300 seconds/],
    ['privileged capability', lease => { lease.task.capabilities.add = ['SYS_ADMIN'] }, /not in enum/],
    ['empty mount flags', lease => { lease.task.filesystem.mounts[0].flags = [] }, /array shorter than minItems/],
    ['proc mount', lease => { lease.task.filesystem.mounts[0].path = '/proc' }, /not admitted|not in enum/],
    ['etc descendant mount', lease => { lease.task.filesystem.mounts[0].path = '/etc/ssh' }, /not admitted|not in enum/],
    ['usr descendant mount', lease => { lease.task.filesystem.mounts[0].path = '/usr/local' }, /not admitted|not in enum/],
    ['var descendant mount', lease => { lease.task.filesystem.mounts[0].path = '/var/lib' }, /not admitted|not in enum/],
    ['lib64 symlink alias', lease => { lease.task.filesystem.mounts[0].path = '/lib64' }, /not admitted|not in enum/],
    ['run prefix neighbor', lease => { lease.task.filesystem.mounts[0].path = '/runtime' }, /not admitted|not in enum/],
    ['parent traversal mount', lease => { lease.task.filesystem.mounts[0].path = '/run/../proc' }, /not in enum|not canonical|not admitted/],
    ['trailing parent mount', lease => { lease.task.filesystem.mounts[0].path = '/a/../' }, /not in enum|not canonical|not admitted/],
    ['double-slash traversal mount', lease => { lease.task.filesystem.mounts[0].path = '/run//../dev' }, /not in enum|not canonical|not admitted/],
    ['nested parent to sys', lease => { lease.task.filesystem.mounts[0].path = '/safe/../../sys' }, /not in enum|not canonical|not admitted/],
  ]) {
    const lease = fixture('valid')
    mutate(lease)
    assert.throws(() => assertContract('task-lease', lease), pattern, label)
  }
  for (const [label, mutate] of [
    ['writable rootfs', lease => { lease.task.filesystem.rootfs_read_only = false }],
    ['kept capabilities', lease => { lease.task.capabilities.drop = [] }],
    ['open egress', lease => { lease.task.network.policy = 'egress_all' }],
    ['real effect', lease => { lease.task.effect = 'write' }],
    ['unknown operation', lease => { lease.task.allowed_operations = ['create', 'exec_host'] }],
    ['bind mount', lease => { lease.task.filesystem.mounts[0].kind = 'bind' }],
    ['unknown envelope field', lease => { lease.image = 'ghcr.io/example/task:latest' }],
    ['missing replay protection', lease => { delete lease.replay_protection }],
    ['net admin', lease => { lease.task.capabilities.add = ['NET_ADMIN'] }],
  ]) {
    const lease = fixture('valid')
    mutate(lease)
    assert.notEqual(validateContract('task-lease', lease).length, 0, label)
  }
})

test('path traversal, non-canonical mounts and dotted output names fail closed', () => {
  for (const mountPath of [
    '/run/../proc', '/a/../', '/run//../dev', '/safe/../../sys', '/run/./tmp', '/proc/self',
    '/etc/ssh', '/usr/local', '/var/lib', '/bin/sh', '/home/user', '/lib64', '/runtime', '/tmp2', '/run/user',
  ]) {
    const lease = fixture('valid')
    lease.task.filesystem.mounts[0].path = mountPath
    assert.notEqual(validateContract('task-lease', lease).length, 0, mountPath)
    const profile = closedProfile()
    profile.filesystem.mounts[0].path = mountPath
    assert.throws(() => hashTaskProfile(profile), /not canonical|not admitted/, mountPath)
  }
  assert.deepEqual(validateContract('task-lease', fixture('valid')), [])
  assert.match(hashTaskProfile(closedProfile()), /^sha256:[a-f0-9]{64}$/)
  const dottedOutput = closedProfile()
  dottedOutput.allowed_outputs = ['/workspace/out/..']
  assert.throws(() => hashTaskProfile(dottedOutput), /outputs are invalid/)
  const hiddenOutput = closedProfile()
  hiddenOutput.allowed_outputs = ['/workspace/out/.hidden']
  assert.throws(() => hashTaskProfile(hiddenOutput), /outputs are invalid/)
})

test('task lease is identity-bound, profile-exact, expiring and single-use via a replay store', async () => {
  const lease = fixture('valid')
  const expected = expectationFor(lease)
  const store = new InMemoryTaskLeaseReplayStore()
  assert.equal(await consumeTaskLease(lease, expected, store, NOW), true)
  await assert.rejects(() => consumeTaskLease(lease, expected, store, '2026-08-14T10:00:31.000Z'), /replay/)

  const otherManager = expectationFor(lease)
  otherManager.task_manager.instance_id = 'instance_task_manager_s0_002'
  await assert.rejects(() => consumeTaskLease(lease, otherManager, new InMemoryTaskLeaseReplayStore(), NOW), /instance/)
  const otherTask = expectationFor(lease)
  otherTask.task_id = 'task_s0_fixture_patch_002'
  await assert.rejects(() => consumeTaskLease(lease, otherTask, new InMemoryTaskLeaseReplayStore(), NOW), /task lease task/)
  const otherTenant = expectationFor(lease)
  otherTenant.tenant_id = 'tenant_other_lab_001'
  await assert.rejects(() => consumeTaskLease(lease, otherTenant, new InMemoryTaskLeaseReplayStore(), NOW), /tenant/)

  const widenedLease = fixture('valid')
  widenedLease.task.limits.pids = 512
  await assert.rejects(() => consumeTaskLease(widenedLease, expected, new InMemoryTaskLeaseReplayStore(), NOW), /closed profile/)
  const otherInput = fixture('valid')
  otherInput.task.input_digest = 'sha256:18f6c871f4126f7a7def815ecbce35ee92c7b6083c755b52e94625548b9a16fc'
  await assert.rejects(() => consumeTaskLease(otherInput, expected, new InMemoryTaskLeaseReplayStore(), NOW), /closed profile/)

  const spoofedTask = expectationFor(lease)
  spoofedTask.task = structuredClone(widenedLease.task)
  assert.equal(await consumeTaskLease(lease, spoofedTask, new InMemoryTaskLeaseReplayStore(), NOW), true)

  await assert.rejects(() => consumeTaskLease(lease, { ...expected, closedProfile: undefined }, new InMemoryTaskLeaseReplayStore(), NOW), /closed profile is required/)
  await assert.rejects(() => consumeTaskLease(lease, expected, new InMemoryTaskLeaseReplayStore(), '2026-08-14T09:59:59.000Z'), /not yet valid/)
  await assert.rejects(() => consumeTaskLease(lease, expected, new InMemoryTaskLeaseReplayStore(), '2026-08-14T10:01:00.000Z'), /expired/)
  await assert.rejects(() => consumeTaskLease(lease, expected, new Set(), NOW), /replay store is required/)
  await assert.rejects(() => consumeTaskLease(lease, expected, undefined, NOW), /replay store is required/)
})

test('allowed operations are exact and any other operation is forbidden', async () => {
  const lease = fixture('valid')
  assert.equal(taskLeaseAllows(lease, 'create'), true)
  assert.equal(taskLeaseAllows(lease, 'exec_host'), false)
  assert.equal(taskLeaseAllows(lease, undefined), false)
  const narrowed = fixture('valid')
  narrowed.task.allowed_operations = ['inspect']
  assert.equal(taskLeaseAllows(narrowed, 'create'), false)
  assert.equal(assertOperationAllowed(narrowed, 'inspect'), true)
  await rejectsCode(() => assertOperationAllowed(narrowed, 'create'), 'TASK_LEASE_OPERATION_FORBIDDEN')
})

test('Core issues a signed task lease that the Task Manager verifies, admits once and correlates', async () => {
  const setupResult = setup()
  const signed = setupResult.authority.issue(setupResult.input)
  const verification = setupResult.verifier.verifySigned({ signedTaskLease: signed, now: NOW })
  assert.equal(verification.kid, KID)
  assert.equal(verification.policyDigest, POLICY_DIGEST)
  assert.equal(verification.leaseDigest, hashContract('task-lease', verification.lease))
  assert.equal(verification.lease.audience, TASK_LEASE_AUDIENCE)
  assert.deepEqual(verification.lease.task, bindTaskAuthorization(setupResult.input.closedProfile))
  assert.deepEqual(verification.lease.task_manager, setupResult.input.taskManagerIdentity)

  const parsed = parseSignedTaskLease(signed)
  assert.equal(parsed.header.typ, TASK_LEASE_TYPE)
  assert.equal(parsed.payload.schema, TASK_LEASE_SCHEMA)
  assert.equal(parsed.payload.issuer, TASK_LEASE_ISSUER)

  const store = new InMemoryTaskLeaseReplayStore()
  const expected = expectationFor(verification.lease)
  assert.equal((await setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected,
    replayStore: store,
    now: NOW,
  })).leaseDigest, verification.leaseDigest)
  await rejectsCode(() => setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected,
    replayStore: store,
    now: NOW,
  }), 'TASK_LEASE_REPLAY_DETECTED')
  await rejectsCode(() => setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected,
    now: NOW,
  }), 'TASK_LEASE_REPLAY_STORE_REQUIRED')
  await rejectsCode(() => setupResult.verifier.admit({
    signedTaskLease: signed,
    expected,
    replayStore: new InMemoryTaskLeaseReplayStore(),
    now: NOW,
  }), 'TASK_LEASE_CLOSED_PROFILE_REQUIRED')

  const widenedExpected = expectationFor(verification.lease)
  widenedExpected.task.limits.memory_bytes = 268435456
  assert.equal((await setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected: widenedExpected,
    replayStore: new InMemoryTaskLeaseReplayStore(),
    now: NOW,
  })).leaseDigest, verification.leaseDigest)

  const wrongProfile = closedProfile()
  wrongProfile.limits.pids = 512
  await rejectsCode(() => setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: wrongProfile,
    expected: expectationFor(verification.lease),
    replayStore: new InMemoryTaskLeaseReplayStore(),
    now: NOW,
  }), 'TASK_LEASE_PROFILE_MISMATCH')
  const otherManager = expectationFor(verification.lease)
  otherManager.task_manager.workload_id = 'workload_task_manager_s0_999'
  await rejectsCode(() => setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected: otherManager,
    replayStore: new InMemoryTaskLeaseReplayStore(),
    now: NOW,
  }), 'TASK_LEASE_BINDING_MISMATCH')
})

test('tampered signatures, foreign algorithms, non-canonical signatures and digest mismatches fail closed', async () => {
  const setupResult = setup()
  const signed = setupResult.authority.issue(setupResult.input)
  const segments = signed.split('.')
  segments[2] = `${segments[2][0] === 'A' ? 'B' : 'A'}${segments[2].slice(1)}`
  await rejectsCode(() => setupResult.verifier.verify({ signedTaskLease: segments.join('.'), now: NOW }), 'TASK_LEASE_SIGNATURE_INVALID')

  const padded = signed.split('.')
  const originalSig = padded[2]
  const originalBytes = Buffer.from(originalSig, 'base64url')
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const nonCanonical = [...alphabet]
    .map(char => originalSig.slice(0, -1) + char)
    .find(candidate => candidate !== originalSig
      && Buffer.from(candidate, 'base64url').equals(originalBytes)
      && originalBytes.toString('base64url') !== candidate)
  assert.ok(nonCanonical, 'fixture signature must have a non-canonical last-character encoding')
  assert.throws(() => parseSignedTaskLease([...padded.slice(0, 2), nonCanonical].join('.')), /signature is not canonical/)
  await rejectsCode(() => setupResult.verifier.verify({ signedTaskLease: [...padded.slice(0, 2), nonCanonical].join('.'), now: NOW }), 'TASK_LEASE_FORMAT_INVALID')

  const parsed = parseSignedTaskLease(signed)
  await rejectsCode(() => setupResult.verifier.verify({
    signedTaskLease: signEnvelope({ header: { ...parsed.header, alg: 'ES256' }, payload: parsed.payload, signingKey: setupResult.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_ALGORITHM_INVALID')
  await rejectsCode(() => setupResult.verifier.verify({
    signedTaskLease: signEnvelope({ header: { ...parsed.header, typ: 'DUBSAR-CAPABILITY+JSON' }, payload: parsed.payload, signingKey: setupResult.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_ALGORITHM_INVALID')

  const widenedLease = structuredClone(parsed.payload)
  widenedLease.lease.task.limits.pids = 4096
  await rejectsCode(() => setupResult.verifier.verify({
    signedTaskLease: signEnvelope({ header: parsed.header, payload: widenedLease, signingKey: setupResult.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_DIGEST_MISMATCH')

  const unknownField = structuredClone(parsed.payload)
  unknownField.lease.task.image = 'ghcr.io/example/task:latest'
  await rejectsCode(() => setupResult.verifier.verify({
    signedTaskLease: signEnvelope({ header: parsed.header, payload: unknownField, signingKey: setupResult.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_INVALID')

  const extraPayloadKey = { ...structuredClone(parsed.payload), note: 'x' }
  await rejectsCode(() => setupResult.verifier.verify({
    signedTaskLease: signEnvelope({ header: parsed.header, payload: extraPayloadKey, signingKey: setupResult.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_FORMAT_INVALID')
  await rejectsCode(() => setupResult.verifier.verify({ signedTaskLease: 'not.a', now: NOW }), 'TASK_LEASE_FORMAT_INVALID')
})

test('issuer, audience and temporal envelope are checked independently of the signature', async () => {
  const issuerCase = setup()
  const issuerParsed = parseSignedTaskLease(issuerCase.authority.issue(issuerCase.input))
  issuerParsed.payload.issuer = 'other-core'
  await rejectsCode(() => issuerCase.verifier.verify({
    signedTaskLease: signEnvelope({ header: issuerParsed.header, payload: issuerParsed.payload, signingKey: issuerCase.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_ISSUER_INVALID')

  const audienceCase = setup()
  const audienceParsed = parseSignedTaskLease(audienceCase.authority.issue(audienceCase.input))
  audienceParsed.payload.lease.audience = 'dubsar-action-broker'
  audienceParsed.payload.lease_digest = 'sha256:3333333333333333333333333333333333333333333333333333333333333333'
  await rejectsCode(() => audienceCase.verifier.verify({
    signedTaskLease: signEnvelope({ header: audienceParsed.header, payload: audienceParsed.payload, signingKey: audienceCase.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_INVALID')

  const expiredCase = setup()
  const expiredSigned = expiredCase.authority.issue(expiredCase.input)
  await rejectsCode(() => expiredCase.verifier.verify({ signedTaskLease: expiredSigned, now: '2026-08-14T10:01:00.000Z' }), 'TASK_LEASE_EXPIRED')
  await rejectsCode(() => expiredCase.verifier.verify({ signedTaskLease: expiredSigned, now: '2026-08-14T09:59:59.000Z' }), 'TASK_LEASE_NOT_YET_VALID')

  const skewCase = setup()
  const skewParsed = parseSignedTaskLease(skewCase.authority.issue(skewCase.input))
  skewParsed.payload.nbf += 5
  skewParsed.payload.exp += 5
  skewParsed.payload.lease.not_before = new Date(skewParsed.payload.nbf * 1000).toISOString()
  skewParsed.payload.lease.expires_at = new Date(skewParsed.payload.exp * 1000).toISOString()
  skewParsed.payload.lease_digest = hashContract('task-lease', skewParsed.payload.lease)
  await rejectsCode(() => skewCase.verifier.verify({
    signedTaskLease: signEnvelope({ header: skewParsed.header, payload: skewParsed.payload, signingKey: skewCase.privateKey }),
    now: '2026-08-14T10:00:02.000Z',
  }), 'TASK_LEASE_NOT_YET_VALID')

  const driftCase = setup()
  const driftParsed = parseSignedTaskLease(driftCase.authority.issue(driftCase.input))
  driftParsed.payload.exp += 1
  await rejectsCode(() => driftCase.verifier.verify({
    signedTaskLease: signEnvelope({ header: driftParsed.header, payload: driftParsed.payload, signingKey: driftCase.privateKey }),
    now: NOW,
  }), 'TASK_LEASE_TEMPORAL_INVALID')
})

test('unknown, revoked, rotated and not-yet-active Core keys fail or succeed exactly as configured', async () => {
  const first = setup()
  const secondPair = generateKeyPairSync('ed25519')
  const secondAuthority = new Ed25519TaskLeaseAuthority({
    signingKey: secondPair.privateKey,
    kid: 'core-key_task_lease_demo_002',
    clock: { now: () => NOW },
  })
  const secondSigned = secondAuthority.issue(first.input)
  await rejectsCode(() => first.verifier.verify({ signedTaskLease: secondSigned, now: NOW }), 'TASK_LEASE_KEY_UNKNOWN')
  first.keyRing.admit({ kid: 'core-key_task_lease_demo_002', publicKey: secondPair.publicKey })
  assert.equal(first.verifier.verify({ signedTaskLease: secondSigned, now: NOW }).task_id, first.input.taskId)
  first.keyRing.revoke(KID)
  await rejectsCode(() => first.verifier.verify({ signedTaskLease: first.authority.issue(first.input), now: NOW }), 'TASK_LEASE_KEY_REVOKED')
  assert.throws(() => new TaskManagerPublicKeyRing({ keys: [{ kid: 'core-key_private_refused_001', publicKey: secondPair.privateKey }] }),
    /TASK_MANAGER_ED25519_PUBLIC_KEY_REQUIRED/)

  const delayed = generateKeyPairSync('ed25519')
  const delayedRing = new TaskManagerPublicKeyRing({
    keys: [{ kid: KID, publicKey: delayed.publicKey, notBefore: '2026-08-14T10:00:20.000Z' }],
  })
  const delayedAuthority = new Ed25519TaskLeaseAuthority({
    signingKey: delayed.privateKey,
    kid: KID,
    clock: { now: () => '2026-08-14T10:00:00.000Z' },
  })
  const delayedSigned = delayedAuthority.issue(first.input)
  const delayedVerifier = new Ed25519TaskLeaseVerifier({ keyRing: delayedRing })
  await rejectsCode(() => delayedVerifier.verify({ signedTaskLease: delayedSigned, now: NOW }), 'TASK_LEASE_KEY_INACTIVE')

  const retiring = generateKeyPairSync('ed25519')
  const retiringRing = new TaskManagerPublicKeyRing({
    keys: [{ kid: KID, publicKey: retiring.publicKey, notAfter: '2026-08-14T10:00:15.000Z' }],
  })
  const retiringAuthority = new Ed25519TaskLeaseAuthority({
    signingKey: retiring.privateKey,
    kid: KID,
    clock: { now: () => '2026-08-14T10:00:00.000Z' },
  })
  const retiringSigned = retiringAuthority.issue(first.input)
  const retiringVerifier = new Ed25519TaskLeaseVerifier({ keyRing: retiringRing })
  assert.equal(retiringVerifier.verify({ signedTaskLease: retiringSigned, now: NOW }).task_id, first.input.taskId)
})

test('Core refuses invalid windows, requester-shaped profiles and identifier reuse', () => {
  const setupResult = setup()
  assert.throws(() => setupResult.authority.issue({ ...setupResult.input, validitySeconds: 301 }), /CORE_TASK_LEASE_VALIDITY_INVALID/)
  assert.throws(() => setupResult.authority.issue({ ...setupResult.input, validitySeconds: 30 }), /CORE_TASK_LEASE_INVALID: .*ttl exceeds/)
  assert.throws(() => setupResult.authority.issue({ ...setupResult.input, policyDigest: 'sha256:short' }), /CORE_POLICY_DIGEST_INVALID/)
  assert.throws(() => setupResult.authority.issue({ ...setupResult.input, closedProfile: undefined }), /CORE_CLOSED_PROFILE_REQUIRED/)
  const widened = structuredClone(setupResult.input)
  widened.task.network.policy = 'egress_all'
  assert.throws(() => setupResult.authority.issue(widened), /CORE_TASK_PROFILE_MISMATCH/)
  const rooted = structuredClone(setupResult.input)
  rooted.task.identity.uid = 0
  assert.throws(() => setupResult.authority.issue(rooted), /CORE_TASK_PROFILE_MISMATCH/)
  const privileged = structuredClone(setupResult.input)
  privileged.closedProfile.image = 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
  assert.throws(() => setupResult.authority.issue(privileged), /CORE_CLOSED_PROFILE_INVALID/)

  const fixed = new Ed25519TaskLeaseAuthority({
    signingKey: setupResult.privateKey,
    kid: KID,
    clock: { now: () => NOW },
    nonceFactory: () => 'nonce_fixedfixedfixedfixedfixedfixedfixed',
  })
  fixed.issue(setupResult.input)
  assert.throws(() => fixed.issue(setupResult.input), /CORE_TASK_LEASE_IDENTIFIER_REUSE_REFUSED/)
})

test('published conformance vector verifies with its public key only and refuses replay', async () => {
  const vector = JSON.parse(fs.readFileSync(new URL('../fixtures/v1/task-lease/signed-vector.json', import.meta.url), 'utf8'))
  const publicKey = createPublicKey({ key: vector.public_key_jwk, format: 'jwk' })
  const verifier = new Ed25519TaskLeaseVerifier({ keyRing: new TaskManagerPublicKeyRing({ keys: [{ kid: vector.kid, publicKey }] }) })
  const verification = verifier.verifySigned({ signedTaskLease: vector.signed_task_lease, now: vector.verify_at })
  assert.deepEqual(verification.lease, fixture('valid'))
  assert.equal(verification.leaseDigest, vector.lease_digest)
  assert.equal(verification.leaseDigest, hashContract('task-lease', fixture('valid')))
  assert.equal(verification.policyDigest, vector.policy_digest)
  assert.deepEqual(parseSignedTaskLease(vector.signed_task_lease).header, vector.header)
  await rejectsCode(() => verifier.verify({ signedTaskLease: vector.signed_task_lease, now: vector.expired_at }), 'TASK_LEASE_EXPIRED')
  assert.equal(Object.hasOwn(vector.public_key_jwk, 'd'), false, 'vector publishes no private scalar')

  const store = new InMemoryTaskLeaseReplayStore()
  const expected = expectationFor(verification.lease)
  assert.equal((await verifier.admit({
    signedTaskLease: vector.signed_task_lease,
    closedProfile: closedProfile(),
    expected,
    replayStore: store,
    now: vector.verify_at,
  })).leaseDigest, vector.lease_digest)
  await rejectsCode(() => verifier.admit({
    signedTaskLease: vector.signed_task_lease,
    closedProfile: closedProfile(),
    expected,
    replayStore: store,
    now: vector.verify_at,
  }), 'TASK_LEASE_REPLAY_DETECTED')
})

test('async replay stores are awaited and remain single-use', async () => {
  const setupResult = setup()
  const signed = setupResult.authority.issue(setupResult.input)
  const seen = new Set()
  const asyncStore = {
    async consumeOnce(identity) {
      await Promise.resolve()
      if (seen.has(identity)) return false
      seen.add(identity)
      return true
    },
  }
  const expected = expectationFor(setupResult.verifier.verify({ signedTaskLease: signed, now: NOW }))
  const verification = setupResult.verifier.verifySigned({ signedTaskLease: signed, now: NOW })
  assert.equal((await setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected,
    replayStore: asyncStore,
    now: NOW,
  })).leaseDigest, verification.leaseDigest)
  await rejectsCode(() => setupResult.verifier.admit({
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected,
    replayStore: asyncStore,
    now: NOW,
  }), 'TASK_LEASE_REPLAY_DETECTED')
})

test('invalid closed profiles do not map onto replay or expiry rejection codes', async () => {
  const setupResult = setup()
  const signed = setupResult.authority.issue(setupResult.input)
  const expected = expectationFor(setupResult.verifier.verify({ signedTaskLease: signed, now: NOW }))
  for (const mountPath of ['/replay', '/expired']) {
    const invalid = closedProfile()
    invalid.filesystem.mounts[0].path = mountPath
    invalid.filesystem.mounts[0].flags = ['nodev']
    await rejectsCode(() => setupResult.verifier.admit({
      signedTaskLease: signed,
      closedProfile: invalid,
      expected,
      replayStore: new InMemoryTaskLeaseReplayStore(),
      now: NOW,
    }), 'TASK_LEASE_CLOSED_PROFILE_INVALID')
  }
})

test('in-memory replay store remains single-use under concurrent admit', async () => {
  const setupResult = setup()
  const signed = setupResult.authority.issue(setupResult.input)
  const store = new InMemoryTaskLeaseReplayStore()
  const expected = expectationFor(setupResult.verifier.verify({ signedTaskLease: signed, now: NOW }))
  const args = {
    signedTaskLease: signed,
    closedProfile: setupResult.input.closedProfile,
    expected,
    replayStore: store,
    now: NOW,
  }
  const results = await Promise.allSettled([
    setupResult.verifier.admit(args),
    setupResult.verifier.admit(args),
  ])
  const fulfilled = results.filter(result => result.status === 'fulfilled')
  const rejected = results.filter(result => result.status === 'rejected')
  assert.equal(fulfilled.length, 1)
  assert.equal(rejected.length, 1)
  assert.equal(rejected[0].reason.code, 'TASK_LEASE_REPLAY_DETECTED')
})

test('TASK_MANAGER is named but never authoritative on the Broker external-action machine', () => {
  const transition = JSON.parse(fs.readFileSync(new URL('../fixtures/v1/state-transition/valid.json', import.meta.url), 'utf8'))
  const asTaskManager = (from, to) => ({
    ...structuredClone(transition),
    from_state: from,
    to_state: to,
    actor: { authority: 'TASK_MANAGER', identity_ref: 'task_manager_s0_001' },
  })
  const asBroker = (from, to) => ({
    ...structuredClone(transition),
    from_state: from,
    to_state: to,
    actor: { authority: 'BROKER', identity_ref: 'broker_ticketpilot_001' },
  })
  assert.match(validateContract('state-transition', asTaskManager('AUTHORIZED', 'IN_FLIGHT')).join(';'), /not authoritative/)
  assert.match(validateContract('state-transition', asTaskManager('IN_FLIGHT', 'SUCCEEDED')).join(';'), /not authoritative/)
  assert.match(validateContract('state-transition', asTaskManager('IN_FLIGHT', 'INDETERMINATE')).join(';'), /not authoritative/)
  assert.match(validateContract('state-transition', asTaskManager('RECEIVED', 'AUTHORIZED')).join(';'), /not authoritative/)
  assert.match(validateContract('state-transition', asTaskManager('INDETERMINATE', 'RECONCILED_SUCCEEDED')).join(';'), /not authoritative/)
  assert.deepEqual(validateContract('state-transition', asBroker('AUTHORIZED', 'IN_FLIGHT')), [])
  assert.deepEqual(validateContract('state-transition', transition), [], 'Core authorization fixture is unchanged')
})

test('tracked task-lease sources contain no durable private key material', () => {
  for (const relativePath of [
    '../src/core/ed25519-task-lease-authority.mjs',
    '../src/core/signed-task-lease-format.mjs',
    '../src/task-manager/ed25519-task-lease-verifier.mjs',
    '../src/task-manager/in-memory-task-lease-replay-store.mjs',
    '../fixtures/v1/task-lease/signed-vector.json',
  ]) {
    const source = fs.readFileSync(new URL(relativePath, import.meta.url), 'utf8')
    assert.doesNotMatch(source, /BEGIN [A-Z ]*PRIVATE KEY|createPrivateKey|"d":/, relativePath)
  }
})

function setup() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const keyRing = new TaskManagerPublicKeyRing({ keys: [{ kid: KID, publicKey }] })
  const lease = fixture('valid')
  return {
    privateKey,
    keyRing,
    verifier: new Ed25519TaskLeaseVerifier({ keyRing }),
    authority: new Ed25519TaskLeaseAuthority({ signingKey: privateKey, kid: KID, clock: { now: () => '2026-08-14T10:00:00.000Z' } }),
    input: {
      taskId: lease.task_id,
      actionId: lease.action_id,
      tenantId: lease.tenant_id,
      missionId: lease.mission_id,
      taskManagerIdentity: structuredClone(lease.task_manager),
      task: structuredClone(lease.task),
      closedProfile: closedProfile(),
      evidenceCorrelationId: lease.evidence_correlation_id,
      policyDigest: POLICY_DIGEST,
      validitySeconds: 60,
    },
  }
}

function expectationFor(lease) {
  return {
    task_id: lease.task_id,
    action_id: lease.action_id,
    tenant_id: lease.tenant_id,
    mission_id: lease.mission_id,
    task_manager: structuredClone(lease.task_manager),
    closedProfile: closedProfile(),
    task: structuredClone(lease.task),
  }
}

function closedProfile() {
  return JSON.parse(fs.readFileSync(new URL('../fixtures/v1/task-lease/closed-profile.json', import.meta.url), 'utf8'))
}

function signEnvelope({ header, payload, signingKey }) {
  const protectedSegment = encodeTaskLeaseSegment(header)
  const payloadSegment = encodeTaskLeaseSegment(payload)
  const signature = sign(null, Buffer.from(`${protectedSegment}.${payloadSegment}`, 'ascii'), signingKey)
  return `${protectedSegment}.${payloadSegment}.${signature.toString('base64url')}`
}

function fixture(verdict) {
  return JSON.parse(fs.readFileSync(new URL(`../fixtures/v1/task-lease/${verdict}.json`, import.meta.url), 'utf8'))
}

async function rejectsCode(operation, code) {
  let thrown
  try {
    await operation()
  } catch (error) {
    thrown = error
  }
  assert.ok(thrown, `Missing expected exception ${code}`)
  assert.equal(thrown.code, code)
  assert.equal(thrown.message, code)
}
