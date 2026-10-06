import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import fs from 'node:fs'
import test from 'node:test'
import { Ed25519CapabilityVerifier, StaticEd25519PublicKeyRing } from '../src/broker/ed25519-capability-verifier.mjs'
import { Ed25519CapabilityAuthority } from '../src/core/ed25519-capability-authority.mjs'
import { hashContract } from '../src/contracts.mjs'
import {
  CAPABILITY_ALGORITHM,
  CAPABILITY_AUDIENCE,
  CAPABILITY_ISSUER,
  CAPABILITY_SCHEMA,
  CAPABILITY_TYPE,
  encodeCapabilitySegment,
  parseSignedCapability,
} from '../src/core/signed-capability-format.mjs'

const NOW = '2026-08-14T10:00:30.000Z'
const IDENTITY = Object.freeze({
  workload_id: 'workload_worker_demo_001',
  instance_id: 'instance_worker_demo_001',
})

test('Core issues a strict Ed25519 capability that the Broker verifies', () => {
  const fixture = setup()
  const signedCapability = fixture.authority.issue(fixture.input)
  const verification = fixture.verifier.verifySigned({ signedCapability, now: NOW })
  const claims = verification.claims
  assert.equal(claims.issuer, CAPABILITY_ISSUER)
  assert.equal(claims.audience, CAPABILITY_AUDIENCE)
  assert.equal(claims.workflow_id, fixture.input.proposal.workflow_id)
  assert.equal(claims.approval_id, fixture.input.proposal.approval_id)
  assert.equal(claims.subject_workload_id, IDENTITY.workload_id)
  assert.deepEqual(verification.workloadIdentity, IDENTITY)
  assert.equal(verification.proposalDigest, hashContract('action-proposal', fixture.input.proposal))
  assert.equal(verification.approvalDigest, hashContract('approval-record', fixture.input.approval))
})

test('tampered signatures and non-EdDSA headers fail closed', () => {
  const fixture = setup()
  const signed = fixture.authority.issue(fixture.input)
  const tamperedSegments = signed.split('.')
  tamperedSegments[2] = `${tamperedSegments[2][0] === 'A' ? 'B' : 'A'}${tamperedSegments[2].slice(1)}`
  const tampered = tamperedSegments.join('.')
  rejectsCode(() => fixture.verifier.verify({ signedCapability: tampered, now: NOW }), 'BROKER_CAPABILITY_SIGNATURE_INVALID')

  const parsed = parseSignedCapability(signed)
  const wrongAlgorithm = signEnvelope({
    header: { ...parsed.header, alg: 'ES256' },
    payload: parsed.payload,
    signingKey: fixture.privateKey,
  })
  rejectsCode(() => fixture.verifier.verify({ signedCapability: wrongAlgorithm, now: NOW }), 'BROKER_CAPABILITY_ALGORITHM_INVALID')
})

test('issuer, audience and temporal envelope are checked independently of the signature', () => {
  for (const [field, value, code] of [
    ['issuer', 'other-core', 'BROKER_CAPABILITY_ISSUER_INVALID'],
    ['audience', 'other-broker', 'BROKER_CAPABILITY_AUDIENCE_INVALID'],
  ]) {
    const fixture = setup()
    const parsed = parseSignedCapability(fixture.authority.issue(fixture.input))
    parsed.payload.claims[field] = value
    const signed = signEnvelope({ header: parsed.header, payload: parsed.payload, signingKey: fixture.privateKey })
    rejectsCode(() => fixture.verifier.verify({ signedCapability: signed, now: NOW }), code)
  }

  const expired = setup({ now: '2026-08-14T10:02:30.000Z' })
  const expiredSigned = expired.authority.issue(expired.input)
  rejectsCode(() => expired.verifier.verify({ signedCapability: expiredSigned, now: '2026-08-14T10:03:31.000Z' }), 'BROKER_CAPABILITY_EXPIRED')

  const premature = setup()
  const parsed = parseSignedCapability(premature.authority.issue(premature.input))
  parsed.payload.nbf += 5
  parsed.payload.exp += 5
  parsed.payload.claims.not_before = new Date(parsed.payload.nbf * 1000).toISOString()
  parsed.payload.claims.expires_at = new Date(parsed.payload.exp * 1000).toISOString()
  const prematureSigned = signEnvelope({ header: parsed.header, payload: parsed.payload, signingKey: premature.privateKey })
  rejectsCode(() => premature.verifier.verify({ signedCapability: prematureSigned, now: NOW }), 'BROKER_CAPABILITY_NOT_YET_VALID')
})

test('unknown, revoked and rotated public keys fail or succeed exactly as configured', () => {
  const first = setup()
  const secondPair = generateKeyPairSync('ed25519')
  const secondAuthority = new Ed25519CapabilityAuthority({
    signingKey: secondPair.privateKey,
    kid: 'core-key_rotation_demo_002',
    clock: { now: () => NOW },
    jtiFactory: () => 'jti_rotation_demo_002_abcdefghijklmnopqr',
  })
  const secondSigned = secondAuthority.issue(first.input)
  rejectsCode(() => first.verifier.verify({ signedCapability: secondSigned, now: NOW }), 'BROKER_CAPABILITY_KEY_UNKNOWN')

  first.keyRing.admit({ kid: 'core-key_rotation_demo_002', publicKey: secondPair.publicKey })
  assert.equal(first.verifier.verify({ signedCapability: secondSigned, now: NOW }).jti, 'jti_rotation_demo_002_abcdefghijklmnopqr')

  first.keyRing.revoke('core-key_rotation_demo_001')
  rejectsCode(
    () => first.verifier.verify({ signedCapability: first.authority.issue(first.input), now: NOW }),
    'BROKER_CAPABILITY_KEY_REVOKED',
  )
})

test('tracked source contains no durable private key fixture', () => {
  const source = fs.readFileSync(new URL('../src/broker/ed25519-capability-verifier.mjs', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /BEGIN [A-Z ]*PRIVATE KEY|createPrivateKey/)
  const repository = fs.readFileSync(new URL('../src/core/ed25519-capability-authority.mjs', import.meta.url), 'utf8')
  assert.doesNotMatch(repository, /BEGIN [A-Z ]*PRIVATE KEY/)
})

test('Core refuses a repeated jti from an injected generator', () => {
  const fixture = setup()
  fixture.authority.issue(fixture.input)
  assert.throws(() => fixture.authority.issue(fixture.input), /CORE_JTI_REUSE_REFUSED/)
})

test('Broker key admission refuses private key material at its boundary', () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  assert.throws(() => new StaticEd25519PublicKeyRing({
    keys: [{ kid: 'core-key_private_refused_001', publicKey: privateKey }],
  }), /BROKER_ED25519_PUBLIC_KEY_REQUIRED/)
})

function setup({ now = NOW } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const keyRing = new StaticEd25519PublicKeyRing({
    keys: [{ kid: 'core-key_rotation_demo_001', publicKey }],
  })
  const authority = new Ed25519CapabilityAuthority({
    signingKey: privateKey,
    kid: 'core-key_rotation_demo_001',
    clock: { now: () => now },
    jtiFactory: () => 'jti_signed_capability_abcdefghijklmnopqrstuvwxyz',
  })
  return {
    authority,
    privateKey,
    keyRing,
    verifier: new Ed25519CapabilityVerifier({ keyRing }),
    input: {
      proposal: fixture('action-proposal'),
      workflow: fixture('workflow-ir'),
      approval: fixture('approval-record'),
      workloadIdentity: structuredClone(IDENTITY),
    },
  }
}

function signEnvelope({ header, payload, signingKey }) {
  const protectedSegment = encodeCapabilitySegment(header)
  const payloadSegment = encodeCapabilitySegment(payload)
  const signature = sign(null, Buffer.from(`${protectedSegment}.${payloadSegment}`, 'ascii'), signingKey)
  return `${protectedSegment}.${payloadSegment}.${signature.toString('base64url')}`
}

function fixture(kind) {
  return JSON.parse(fs.readFileSync(new URL(`../fixtures/v1/${kind}/valid.json`, import.meta.url), 'utf8'))
}

function rejectsCode(operation, code) {
  assert.throws(operation, error => error?.code === code && error?.message === code)
}
