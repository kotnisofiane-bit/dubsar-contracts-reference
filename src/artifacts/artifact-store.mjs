import { randomUUID } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { assertArtifactRef, assertBytes, bytesDigest, artifactError, scopeKey, opaque, MAX_BYTES } from './contracts.mjs'

export class ArtifactStore {
  #context; #metadata; #blobs; #policy; #evidence; #clock; #keyRef
  constructor({ context, metadata, blobs, policy, evidence, clock, keyRef }) {
    const scope = scopeKey(context)
    if (metadata?.scopeKey !== scope || blobs?.scopeKey !== scope || typeof metadata?.withLocked !== 'function'
      || typeof blobs?.read !== 'function' || typeof policy?.authorize !== 'function'
      || typeof evidence?.record !== 'function' || typeof clock?.now !== 'function' || !opaque(keyRef)) throw artifactError('ARTIFACT_PORTS_REQUIRED')
    this.#context = structuredClone(context); this.#metadata = metadata; this.#blobs = blobs
    this.#policy = policy; this.#evidence = evidence; this.#clock = clock; this.#keyRef = keyRef
  }
  assertExactContext(context) {
    if (canonicalJson(context) !== canonicalJson(this.#context.exact_context)) throw artifactError('ARTIFACT_EXACT_CONTEXT_MISMATCH')
  }
  #now() {
    const time = new Date(this.#clock.now())
    if (!Number.isFinite(time.getTime())) throw artifactError('ARTIFACT_CLOCK_INVALID')
    return time.toISOString()
  }
  async #authorize(operation, ref) {
    assertArtifactRef(ref)
    if (ref.tenant_id !== this.#context.tenant_id || ref.mission_id !== this.#context.mission_id || ref.corpus_id !== this.#context.corpus_id) throw artifactError('ARTIFACT_SCOPE_MISMATCH')
    if (ref.expires_at !== null && Date.parse(this.#now()) >= Date.parse(ref.expires_at)) throw artifactError('ARTIFACT_EXPIRED')
    if (await this.#policy.authorize({ operation, context: structuredClone(this.#context), reference: structuredClone(ref) }) !== true) throw artifactError('ARTIFACT_POLICY_DENIED')
  }
  async publish({ idempotencyKey, bytes, metadata }) {
    if (!opaque(idempotencyKey) || !Buffer.isBuffer(bytes) || bytes.length > MAX_BYTES) throw artifactError('ARTIFACT_INPUT_INVALID')
    bytes = Buffer.from(bytes); metadata = structuredClone(metadata)
    const { artifact_type, media_type, producer, origin, classification, expires_at, retention_policy } = metadata
    if (Object.keys(metadata).sort().join(',') !== 'artifact_type,classification,expires_at,media_type,origin,producer,retention_policy') throw artifactError('ARTIFACT_INPUT_INVALID')
    const ref = { schema_version: 'dubsar.artifact-ref/1', artifact_id: `artifact:${randomUUID()}`,
      tenant_id: this.#context.tenant_id, corpus_id: this.#context.corpus_id, mission_id: this.#context.mission_id,
      artifact_type, media_type, size_bytes: bytes.length, digest: bytesDigest(bytes), location: `blob:${randomUUID()}`,
      producer, origin, classification, created_at: this.#now(), published_at: null, expires_at,
      retention_policy, deletion_state: 'ACTIVE', deleted_at: null, evidence_ref: null }
    await this.#authorize('publish', ref)
    const request = { metadata, digest: ref.digest, size: ref.size_bytes, key_ref: this.#keyRef }
    const id = await this.#metadata.reserve(idempotencyKey, request, ref, this.#keyRef)
    return this.#metadata.withLocked(id, async (row, setState) => {
      await this.#authorize('publish', row.reference)
      if (row.state === 'QUARANTINED') throw artifactError('ARTIFACT_QUARANTINED')
      if (row.state === 'PUBLISHED') {
        assertBytes(row.reference, await this.#blobs.read(row.reference, row.key_ref))
        return row.reference
      }
      await this.#blobs.install(row.reference, bytes, row.key_ref)
      return this.#finish(row, setState)
    })
  }
  async #finish(row, setState) {
    assertBytes(row.reference, await this.#blobs.read(row.reference, row.key_ref))
    const r = row.reference
    let evidence
    try {
      evidence = await this.#evidence.record({ event_id: `artifact-publish:${r.artifact_id}`, tenant_id: r.tenant_id,
        artifact_id: r.artifact_id, digest: r.digest, size_bytes: r.size_bytes })
    } catch { throw artifactError('ARTIFACT_EVIDENCE_UNAVAILABLE') }
    if (!opaque(evidence?.evidence_ref) || evidence.tenant_id !== r.tenant_id || evidence.artifact_id !== r.artifact_id || evidence.digest !== r.digest) throw artifactError('ARTIFACT_EVIDENCE_INVALID')
    if (r.evidence_ref !== null && r.evidence_ref !== evidence.evidence_ref) throw artifactError('ARTIFACT_EVIDENCE_INVALID')
    const published = { ...r, published_at: r.published_at ?? this.#now(), evidence_ref: r.evidence_ref ?? evidence.evidence_ref, deletion_state: 'ACTIVE' }
    await this.#authorize('publish', published)
    await setState('PUBLISHED', published)
    return published
  }
  async read(id) {
    if (typeof id !== 'string' || !/^artifact:[a-f0-9-]{36}$/.test(id)) throw artifactError('ARTIFACT_REFERENCE_INVALID')
    return this.#metadata.withLocked(id, async row => {
    if (row.state !== 'PUBLISHED' || row.reference.deletion_state !== 'ACTIVE' || row.reference.published_at === null) throw artifactError('ARTIFACT_NOT_PUBLISHED')
    await this.#authorize('read', row.reference)
    const bytes = await this.#blobs.read(row.reference, row.key_ref)
    assertBytes(row.reference, bytes)
    await this.#authorize('read', row.reference)
    return { reference: structuredClone(row.reference), bytes }
    })
  }
  async reconcile(id) {
    return this.#metadata.withLocked(id, async (row, setState) => {
      await this.#authorize('reconcile', row.reference)
      if (row.state === 'QUARANTINED') throw artifactError('ARTIFACT_QUARANTINED')
      try { assertBytes(row.reference, await this.#blobs.read(row.reference, row.key_ref)) } catch (error) {
        const state = ['ARTIFACT_OBJECT_MISSING', 'ARTIFACT_OBJECT_UNAVAILABLE', 'ARTIFACT_KEY_UNAVAILABLE'].includes(error.code) ? 'INDETERMINATE' : 'QUARANTINED'
        await setState(state, { ...row.reference, deletion_state: state })
        return { state, artifact_id: id }
      }
      if (row.state === 'PUBLISHED') return { state: 'PUBLISHED', artifact_id: id }
      await this.#finish(row, setState)
      return { state: 'PUBLISHED', artifact_id: id }
    })
  }
  async inspectOrphans(limit = 100) {
    // Scoped inventory only. Findings are reported; no object is deleted.
    if (await this.#policy.authorize({ operation: 'inventory', context: structuredClone(this.#context), reference: null }) !== true) throw artifactError('ARTIFACT_POLICY_DENIED')
    const orphans = []
    for (const location of await this.#blobs.inventory(limit)) if (!await this.#metadata.knownLocation(location)) orphans.push({ location, state: 'UNREFERENCED' })
    return { orphans, limit, complete: false }
  }
}
