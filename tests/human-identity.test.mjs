import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { canonicalBytes } from '../src/canonical-json.mjs'
import { HumanProofVerifier } from '../src/human-identity/proof.mjs'
import { HumanRegistry } from '../src/human-identity/registry.mjs'
import { PostgresExactActionRecords } from '../src/exact-action/postgres-records.mjs'

const keys = generateKeyPairSync('ed25519')
const now = 1786701630
const claims = { schema: 'dubsar.human-proof/1', issuer: 'issuer:test', audience: 'dubsar:exact', subject: 'subject:test',
  session: 'session:test', kind: 'human', issued_at: now - 10, expires_at: now + 50 }
const proof = c => ({ claims: c, signature: sign(null, canonicalBytes(c), keys.privateKey).toString('base64url') })
const verifier = () => new HumanProofVerifier({ issuer: claims.issuer, audience: claims.audience,
  publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }), clock: { now: () => new Date(now * 1000).toISOString() } })

test('A02 cross-context registry composition fails before any query', () => {
  const context = { tenant_ref: 'tenant:a', project_ref: 'project:a', mission: { namespace: 'test', id: 'mission:a' } }
  const registry = new HumanRegistry({ context, clock: { now: () => new Date().toISOString() }, environment: 'test' })
  assert.throws(() => new PostgresExactActionRecords({ pool: { connect() { throw new Error('no SQL') } },
    context: { ...context, tenant_ref: 'tenant:b' }, requireHuman: true, humanRegistry: registry }), /CONTEXT_MISMATCH/)
})

test('A02 real signed adapter proof establishes a bounded human session', () => {
  assert.deepEqual(verifier().authenticate(proof(claims)), claims)
})
test('A02 wrong issuer/audience/kind/window and untrusted fields are denied even when signed', () => {
  for (const patch of [{ issuer: 'other' }, { audience: 'other' }, { kind: 'workload' }, { issued_at: now + 1 },
    { expires_at: now }, { expires_at: now + 600 }, { extra: true }]) {
    assert.throws(() => verifier().authenticate(proof({ ...claims, ...patch })))
  }
})
test('A02 modified signature and claims cannot establish identity', () => {
  const value = proof(claims); value.claims = { ...claims, subject: 'attacker' }
  assert.throws(() => verifier().authenticate(value), /PROOF_DENIED/)
  assert.throws(() => verifier().authenticate({ ...proof(claims), signature: 'a'.repeat(86) }), /PROOF_DENIED/)
})
