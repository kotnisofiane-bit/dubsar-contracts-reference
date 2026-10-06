import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { randomBytes, createHash } from 'node:crypto'
import { canonicalJson, canonicalBytes } from '../src/canonical-json.mjs'
import { hashPayload } from '../src/contracts.mjs'
import { ArtifactStore } from '../src/artifacts/artifact-store.mjs'
import { LocalEncryptedBlobs } from '../src/artifacts/local-encrypted-blobs.mjs'
import { ExactArtifactReader } from '../src/exact-action/artifact-reader.mjs'
import { assertArtifactRef, scopeKey, artifactError } from '../src/artifacts/contracts.mjs'

// Transactional double only: PostgreSQL proof lives in tests/postgres/.
class MemoryMetadata {
  rows = new Map(); tail = Promise.resolve()
  constructor(context) { this.scopeKey = scopeKey(context) }
  async reserve(key, request, reference, key_ref) {
    const row = [...this.rows.values()].find(r => r.key === key)
    if (row) {
      if (canonicalJson(row.request) !== canonicalJson(request)) throw artifactError('ARTIFACT_IMMUTABLE_CONFLICT')
      return row.artifact_id
    }
    this.rows.set(reference.artifact_id, structuredClone({ artifact_id: reference.artifact_id, reference, key_ref, request, key, state: 'STAGING' }))
    return reference.artifact_id
  }
  withLocked(id, fn) {
    const task = this.tail.then(async () => {
      const row = structuredClone(this.rows.get(id))
      if (!row) throw artifactError('ARTIFACT_NOT_FOUND')
      const result = await fn(row, async (state, reference) => Object.assign(row, { state, reference }))
      this.rows.set(id, row)
      return result
    })
    this.tail = task.catch(() => {})
    return task
  }
  async knownLocation(location) { return [...this.rows.values()].some(r => r.reference.location === location) }
}

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dubsar-artifact-test-'))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const context = { tenant_id: 'tenant:fixture', corpus_id: null, mission_id: 'mission:fixture',
    exact_context: { tenant_ref: 'tenant_contract_demo_001', project_ref: 'project_contract_demo_001', mission: { namespace: 'scribe-backend', id: 'mis_1234567890abcdef' } } }
  const key = randomBytes(32), keys = { get: async () => key }
  const blobs = await LocalEncryptedBlobs.open({ root, context, keys })
  const metadata = new MemoryMetadata(context), state = { now: '2026-08-14T10:00:30.000Z', available: true, allowed: true }
  const evidence = { async record(event) {
    if (!state.available) throw new Error('offline')
    return { ...event, evidence_ref: `evidence:${event.artifact_id}` }
  } }
  const options = { context, metadata, blobs, policy: { authorize: async () => state.allowed }, evidence,
    clock: { now: () => state.now }, keyRef: 'key:ephemeral-test' }
  const store = new ArtifactStore(options)
  const input = (id = 'same', value = { text: 'exact approved plaintext' }) => ({ idempotencyKey: id, bytes: canonicalBytes(value), metadata: {
    artifact_type: 'action.payload', media_type: 'application/json', producer: { component: 'test', contract_version: '1' },
    origin: { source_ref: null, parent_artifact_ids: [] }, classification: 'internal', expires_at: '2026-08-14T11:00:00.000Z',
    retention_policy: { policy_id: 'policy:test-v1', hold: false },
  } })
  const file = ref => path.join(root, createHash('sha256').update(scopeKey(context)).digest('hex'), 'objects', ref.location.slice(5), 'content')
  return { root, context, key, keys, blobs, metadata, state, options, store, input, file }
}

test('B01 ArtifactRef is closed and complete; byte digest is not the business hash', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  assertArtifactRef(ref)
  assert.notEqual(ref.digest, hashPayload({ text: 'exact approved plaintext' }))
  for (const mutate of [r => { r.schema_version = '2' }, r => { r.size_bytes = -1 }, r => { r.location = '../outside' },
    r => { delete r.producer }, r => { r.extra = true }]) {
    const bad = structuredClone(ref); mutate(bad)
    assert.throws(() => assertArtifactRef(bad))
  }
})

test('B02 encrypted objects reopen with the same bytes; JSON bridge preserves the value', async t => {
  const f = await fixture(t), input = f.input(), ref = await f.store.publish(input)
  const ciphertext = await fs.readFile(f.file(ref))
  assert.equal(ciphertext.includes(input.bytes), false)
  assert.equal(ciphertext.includes(f.key), false)
  const reopened = await LocalEncryptedBlobs.open({ root: f.root, context: f.context, keys: f.keys })
  const store = new ArtifactStore({ ...f.options, blobs: reopened })
  assert.deepEqual((await store.read(ref.artifact_id)).bytes, input.bytes)
  assert.deepEqual(await new ExactArtifactReader({ store, exactContext: f.context.exact_context }).read(ref.artifact_id), JSON.parse(input.bytes))
})

test('B03 concurrent idempotent publishers preserve one identity and reject changed content', async t => {
  const f = await fixture(t)
  const results = await Promise.all([f.store.publish(f.input()), new ArtifactStore(f.options).publish(f.input())])
  assert.deepEqual(results[0], results[1])
  await assert.rejects(f.store.publish(f.input('same', { text: 'changed' })), /IMMUTABLE_CONFLICT/)
  assert.equal(f.metadata.rows.size, 1)
  assert.equal((await f.blobs.inventory()).length, 1)
})

test('B04 Evidence outage leaves object unreadable; reconcile completes idempotently', async t => {
  const f = await fixture(t)
  f.state.available = false
  await assert.rejects(f.store.publish(f.input()), /EVIDENCE_UNAVAILABLE/)
  const [id] = f.metadata.rows.keys()
  await assert.rejects(f.store.read(id), /NOT_PUBLISHED/)
  f.state.available = true
  assert.equal((await f.store.reconcile(id)).state, 'PUBLISHED')
  assert.equal((await f.store.reconcile(id)).state, 'PUBLISHED')
  assert.deepEqual((await f.store.read(id)).bytes, f.input().bytes)
})

test('B04 missing staged bytes remain explicit until the producer retries', async t => {
  const f = await fixture(t)
  const failing = new ArtifactStore({ ...f.options, blobs: { scopeKey: f.blobs.scopeKey, read: (...args) => f.blobs.read(...args),
    install: async () => { throw artifactError('ARTIFACT_OBJECT_UNAVAILABLE') } } })
  await assert.rejects(failing.publish(f.input()))
  const [id] = f.metadata.rows.keys()
  assert.equal((await f.store.reconcile(id)).state, 'INDETERMINATE')
  await assert.rejects(f.store.read(id), /NOT_PUBLISHED/)
  assert.equal((await f.store.publish(f.input())).artifact_id, id)
})

test('B05 corrupted bytes are refused and quarantine cannot be implicitly released', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  const bytes = await fs.readFile(f.file(ref)); bytes[bytes.length - 1] ^= 1
  await fs.writeFile(f.file(ref), bytes)
  await assert.rejects(f.store.read(ref.artifact_id), /INTEGRITY_FAILED/)
  assert.equal((await f.store.reconcile(ref.artifact_id)).state, 'QUARANTINED')
  await assert.rejects(f.store.publish(f.input()), /QUARANTINED/)
})

test('B05 wrong key, expiry and denied policy fail closed', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  const blobs = await LocalEncryptedBlobs.open({ root: f.root, context: f.context, keys: { get: async () => randomBytes(32) } })
  await assert.rejects(new ArtifactStore({ ...f.options, blobs }).read(ref.artifact_id), /INTEGRITY_FAILED/)
  f.state.allowed = false
  await assert.rejects(f.store.read(ref.artifact_id), /POLICY_DENIED/)
  f.state.allowed = true; f.state.now = ref.expires_at
  await assert.rejects(f.store.read(ref.artifact_id), /EXPIRED/)
})

test('B05 explicit exact identity mapping and store scopes cannot be mixed', async t => {
  const f = await fixture(t)
  assert.throws(() => new ExactArtifactReader({ store: f.store, exactContext: { ...f.context.exact_context, tenant_ref: 'other' } }), /CONTEXT_MISMATCH/)
  assert.throws(() => new ArtifactStore({ ...f.options, context: { ...f.context, tenant_id: 'other' } }), /PORTS_REQUIRED/)
})

test('B06 path traversal and linked object directories are refused', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  await assert.rejects(f.blobs.read({ ...ref, location: 'blob:../../outside' }, 'key:test'), /REFERENCE_INVALID/)
  const object = path.dirname(f.file(ref)), moved = `${object}-moved`
  await fs.rename(object, moved)
  await fs.symlink(moved, object, process.platform === 'win32' ? 'junction' : 'dir')
  await assert.rejects(f.store.read(ref.artifact_id), /UNSAFE_PATH/)
})

test('B06 substitution of another valid ciphertext fails authenticated binding', async t => {
  const f = await fixture(t), one = await f.store.publish(f.input('one')), two = await f.store.publish(f.input('two'))
  await fs.copyFile(f.file(two), f.file(one))
  await assert.rejects(f.store.read(one.artifact_id), /INTEGRITY_FAILED/)
})

test('B09 scoped orphan report does not delete unknown objects', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  f.metadata.rows.clear()
  assert.deepEqual((await f.store.inspectOrphans()).orphans, [{ location: ref.location, state: 'UNREFERENCED' }])
  assert.ok(await fs.stat(f.file(ref)))
})

test('B04 transient key outage is recoverable without changing first publication', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  const original = f.keys.get
  f.keys.get = async () => { throw new Error('temporary key service outage') }
  assert.equal((await f.store.reconcile(ref.artifact_id)).state, 'INDETERMINATE')
  await assert.rejects(f.store.read(ref.artifact_id), /NOT_PUBLISHED/)
  f.keys.get = original; f.state.now = '2026-08-14T10:01:30.000Z'
  assert.equal((await f.store.reconcile(ref.artifact_id)).state, 'PUBLISHED')
  assert.deepEqual((await f.store.read(ref.artifact_id)).reference, ref)
})

test('B04 restoration preserves initial timestamp and evidence across INDETERMINATE', async t => {
  const f = await fixture(t), ref = await f.store.publish(f.input())
  const bytes = await fs.readFile(f.file(ref))
  await fs.unlink(f.file(ref))
  assert.equal((await f.store.reconcile(ref.artifact_id)).state, 'INDETERMINATE')
  await fs.writeFile(f.file(ref), bytes)
  f.state.now = '2026-08-14T10:01:30.000Z'
  assert.equal((await f.store.reconcile(ref.artifact_id)).state, 'PUBLISHED')
  assert.deepEqual((await f.store.read(ref.artifact_id)).reference, ref)
})
