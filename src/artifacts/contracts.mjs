import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { SchemaRegistry } from '../schema-validator.mjs'
import { assertNoSecretMaterial } from '../contracts.mjs'

export const MAX_BYTES = 1048576
const registry = new SchemaRegistry(fileURLToPath(new URL('../../schemas/artifacts/v1/', import.meta.url)))
export const artifactError = code => Object.assign(new Error(code), { code })
export function opaque(value) { return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f]/.test(value) }
export function bytesDigest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}` }
export function assertArtifactRef(ref) {
  try { registry.assertValid('artifact-ref.schema.json', ref); assertNoSecretMaterial(ref); canonicalJson(ref) }
  catch { throw artifactError('ARTIFACT_REFERENCE_INVALID') }
  if (ref.corpus_id === null && ref.mission_id === null) throw artifactError('ARTIFACT_SCOPE_REQUIRED')
  if (ref.expires_at !== null && Date.parse(ref.expires_at) <= Date.parse(ref.created_at)) throw artifactError('ARTIFACT_EXPIRY_INVALID')
  if (ref.published_at !== null && (Date.parse(ref.published_at) < Date.parse(ref.created_at) || !opaque(ref.evidence_ref))) throw artifactError('ARTIFACT_PUBLICATION_INVALID')
  return ref
}
export function scopeKey(context) {
  if (!context || Object.keys(context).sort().join(',') !== 'corpus_id,exact_context,mission_id,tenant_id'
    || !opaque(context.tenant_id) || !(context.corpus_id === null || opaque(context.corpus_id))
    || !(context.mission_id === null || opaque(context.mission_id))
    || (context.corpus_id === null && context.mission_id === null)) throw artifactError('ARTIFACT_SCOPE_REQUIRED')
  if (context.exact_context !== null) {
    const e = context.exact_context
    if (!e || Object.keys(e).sort().join(',') !== 'mission,project_ref,tenant_ref'
      || !opaque(e.tenant_ref) || !opaque(e.project_ref) || !e.mission
      || Object.keys(e.mission).sort().join(',') !== 'id,namespace'
      || !opaque(e.mission.id) || !opaque(e.mission.namespace) || context.mission_id === null) throw artifactError('ARTIFACT_EXACT_CONTEXT_INVALID')
  }
  return canonicalJson(context)
}
export function assertBytes(ref, bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== ref.size_bytes || bytesDigest(bytes) !== ref.digest) throw artifactError('ARTIFACT_INTEGRITY_FAILED')
}
