import fs from 'node:fs'
import { generateKeyPairSync, sign, verify, randomUUID } from 'node:crypto'
import { canonicalBytes } from '../../src/canonical-json.mjs'
import { DocumentAuthority } from '../../src/document-access/authority.mjs'

export function identity() {
  const keys = generateKeyPairSync('ed25519')
  const state = { now: Date.now(), sourceEnabled: true }
  const claims = { schema: 'dubsar.human-proof/1', issuer: 'test:issuer', audience: 'dubsar:document-access',
    subject: 'test:subject', session: 'test:session', kind: 'human', issued_at: Math.floor(state.now / 1000) - 1,
    expires_at: Math.floor(state.now / 1000) + 120 }
  const proof = (patch = {}) => { const c = { ...claims, ...patch }; return { claims: c, signature: sign(null, canonicalBytes(c), keys.privateKey).toString('base64url') } }
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' })
  const clock = { now: () => new Date(state.now).toISOString() }
  // Synthetic source signs a fresh challenge. This is not the real Portal source.
  const verifySession = async c => {
    const challenge = randomUUID()
    const body = { challenge, session: c.session, subject: c.subject, current: state.sourceEnabled }
    const signature = sign(null, canonicalBytes(body), keys.privateKey)
    return verify(null, canonicalBytes(body), keys.publicKey, signature) && body.current && body.challenge === challenge
  }
  return { state, claims, proof, publicKey, clock, verifySession, issuer: claims.issuer }
}
export const context = { tenant_ref: 'tenant:a', context_ref: 'context:a' }
export const request = proof => ({ proof, context, request_ref: 'dossier:a', requested_resources: [{ corpus_ref: 'drive', document_ref: 'document:a' }] })

export async function setup() {
  const { default: pg } = await import('pg')
  const connectionString = process.env.DUBSAR_TEST_POSTGRES_URL
  if (!connectionString) throw new Error('disposable PostgreSQL required')
  const owner = new pg.Pool({ connectionString, connectionTimeoutMillis: 1000 })
  // Tests use a fresh dedicated database. Never erase an existing schema.
  await owner.query(fs.readFileSync(new URL('../../migrations/007_document_access.sql', import.meta.url), 'utf8'))
  const reader = new pg.Pool({ connectionString, options: '-c role=dubsar_document_reader', connectionTimeoutMillis: 1000 })
  const admin = new pg.Pool({ connectionString, options: '-c role=dubsar_document_admin', connectionTimeoutMillis: 1000 })
  const id = identity()
  const mutate = (kind, body, ctx = context) => admin.query('SELECT dubsar_document_access.mutate($1,$2,$3,$4)', [ctx.tenant_ref, ctx.context_ref, kind, body])
  const membership = { issuer: id.claims.issuer, external_subject: id.claims.subject, principal: 'principal:a', active_function: 'reader', enabled: true }
  const session = { session_ref: id.claims.session, issuer: id.claims.issuer, external_subject: id.claims.subject,
    active_function: 'reader', expires_at: new Date(id.claims.expires_at * 1000).toISOString(), revoked: false }
  const resource = { corpus_ref: 'drive', document_ref: 'document:a', resource_version: 'v1', enabled: true }
  const grant = { principal: membership.principal, active_function: membership.active_function, corpus_ref: 'drive', document_ref: 'document:a', enabled: true }
  await mutate('context', {})
  await mutate('membership', membership)
  await mutate('session', session)
  await mutate('corpus', { corpus_ref: 'drive', enabled: true })
  await mutate('resource', resource)
  await mutate('grant', grant)
  const make = (overrides = {}) => new DocumentAuthority({ pool: reader, context, ...id, ...overrides })
  return { ...id, owner, reader, admin, mutate, membership, session, resource, grant, make,
    authority: make(), close: () => Promise.all([owner.end(), reader.end(), admin.end()]) }
}

// Composition used only by Python qualification, with synthetic signed material.
export async function fromConfig(path) {
  const { default: pg } = await import('pg')
  const config = JSON.parse(fs.readFileSync(path, 'utf8'))
  const syntheticSource = identity()
  const pool = new pg.Pool({ connectionString: process.env.DUBSAR_TEST_POSTGRES_URL,
    options: '-c role=dubsar_document_reader', connectionTimeoutMillis: 1000 })
  const authority = new DocumentAuthority({ pool, context: config.context, issuer: config.issuer, publicKey: config.publicKey,
    clock: { now: () => new Date().toISOString() }, verifySession: async claims => {
      syntheticSource.state.sourceEnabled = JSON.parse(fs.readFileSync(path, 'utf8')).sourceEnabled === true
      return syntheticSource.verifySession(claims)
    } })
  return { authority, close: () => pool.end() }
}
