import fs from 'node:fs/promises'
import { constants } from 'node:fs'
import path from 'node:path'
import { createCipheriv, createDecipheriv, randomBytes, randomUUID, createHash } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { assertArtifactRef, assertBytes, artifactError, scopeKey, MAX_BYTES } from './contracts.mjs'

const magic = Buffer.from('DAR1')
const normalize = p => process.platform === 'win32' ? p.toLowerCase() : p
// The root and its ancestors must be administrator-owned, not writable by clients.
// lstat/realpath/O_NOFOLLOW detect links; Node does not provide portable openat2.
export class LocalEncryptedBlobs {
  #root; #partition; #keys; #identity
  scopeKey
  constructor({ root, context, keys }) {
    if (!path.isAbsolute(root) || typeof keys?.get !== 'function') throw artifactError('ARTIFACT_BLOB_CONFIGURATION_INVALID')
    this.scopeKey = scopeKey(context)
    this.#root = path.resolve(root)
    this.#partition = path.join(this.#root, createHash('sha256').update(this.scopeKey).digest('hex'))
    this.#keys = keys
  }
  static async open(options) {
    const store = new LocalEncryptedBlobs(options)
    const stat = await store.#directory(store.#root)
    store.#identity = { dev: stat.dev, ino: stat.ino }
    for (const dir of [store.#partition, path.join(store.#partition, 'objects'), path.join(store.#partition, 'staging')]) {
      await fs.mkdir(dir, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error })
      await store.#directory(dir)
      await store.#syncDirectory(path.dirname(dir))
    }
    return store
  }
  async #directory(dir) {
    const stat = await fs.lstat(dir)
    if (!stat.isDirectory() || stat.isSymbolicLink() || normalize(await fs.realpath(dir)) !== normalize(path.resolve(dir))) throw artifactError('ARTIFACT_UNSAFE_PATH')
    return stat
  }
  async #check() {
    const stat = await this.#directory(this.#root)
    if (stat.dev !== this.#identity.dev || stat.ino !== this.#identity.ino) throw artifactError('ARTIFACT_ROOT_CHANGED')
    await this.#directory(this.#partition)
    await this.#directory(path.join(this.#partition, 'objects'))
    await this.#directory(path.join(this.#partition, 'staging'))
  }
  #object(ref) {
    assertArtifactRef(ref)
    return path.join(this.#partition, 'objects', ref.location.slice(5))
  }
  #aad(ref) {
    return Buffer.from(canonicalJson({ scope: this.scopeKey, id: ref.artifact_id, location: ref.location,
      size: ref.size_bytes, digest: ref.digest }))
  }
  async #key(keyRef) {
    let key
    try { key = await this.#keys.get(keyRef) } catch { throw artifactError('ARTIFACT_KEY_UNAVAILABLE') }
    if (!Buffer.isBuffer(key) || key.length !== 32) throw artifactError('ARTIFACT_KEY_UNAVAILABLE')
    return Buffer.from(key)
  }
  async #syncDirectory(dir) {
    // Windows Node cannot fsync directories: process-crash tests are supported,
    // but only the Linux adapter receives filesystem durability qualification.
    if (process.platform === 'win32') return
    const handle = await fs.open(dir, constants.O_RDONLY | constants.O_NOFOLLOW)
    try { await handle.sync() } finally { await handle.close() }
  }
  async install(ref, bytes, keyRef) {
    assertArtifactRef(ref); assertBytes(ref, bytes)
    await this.#check()
    const object = this.#object(ref)
    const key = await this.#key(keyRef)
    let encrypted
    try {
      const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce)
      cipher.setAAD(this.#aad(ref))
      const content = Buffer.concat([cipher.update(bytes), cipher.final()])
      encrypted = Buffer.concat([magic, nonce, cipher.getAuthTag(), content])
    } finally { key.fill(0) }
    const staging = path.join(this.#partition, 'staging', randomUUID())
    await fs.mkdir(staging, { mode: 0o700 })
    const file = path.join(staging, 'content')
    try {
      const handle = await fs.open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600)
      try { await handle.writeFile(encrypted); await handle.sync() } finally { await handle.close() }
      await this.#syncDirectory(staging)
      await this.#check()
      try {
        // Destination contains 'content' and is never empty after publication;
        // directory rename cannot replace it on either supported platform.
        await fs.rename(staging, object)
      } catch (error) {
        if (!['EEXIST', 'ENOTEMPTY', 'EPERM'].includes(error.code)) throw error
        // Existing object is adopted only after full authenticated verification.
        assertBytes(ref, await this.read(ref, keyRef))
      }
      await this.#syncDirectory(path.dirname(object))
      await this.#syncDirectory(path.dirname(staging))
    } finally {
      // Only this generated staging file/directory, never recursive cleanup.
      await fs.unlink(file).catch(error => { if (error.code !== 'ENOENT') throw error })
      await fs.rmdir(staging).catch(error => { if (error.code !== 'ENOENT') throw error })
    }
  }
  async read(ref, keyRef) {
    assertArtifactRef(ref)
    await this.#check()
    const object = this.#object(ref)
    let handle, key
    try {
      await this.#directory(object)
      const file = path.join(object, 'content'), before = await fs.lstat(file)
      if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size !== ref.size_bytes + 32
        || before.size > MAX_BYTES + 32) throw artifactError('ARTIFACT_INTEGRITY_FAILED')
      handle = await fs.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
      const opened = await handle.stat()
      if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1 || opened.size !== before.size) throw artifactError('ARTIFACT_UNSAFE_PATH')
      const encrypted = await handle.readFile()
      if (encrypted.length !== ref.size_bytes + 32 || !encrypted.subarray(0, 4).equals(magic)) throw artifactError('ARTIFACT_INTEGRITY_FAILED')
      key = await this.#key(keyRef)
      const decipher = createDecipheriv('aes-256-gcm', key, encrypted.subarray(4, 16))
      decipher.setAAD(this.#aad(ref)); decipher.setAuthTag(encrypted.subarray(16, 32))
      const bytes = Buffer.concat([decipher.update(encrypted.subarray(32)), decipher.final()])
      assertBytes(ref, bytes)
      return bytes
    } catch (error) {
      if (error.code === 'ENOENT') throw artifactError('ARTIFACT_OBJECT_MISSING')
      if (['EIO', 'EACCES', 'EPERM', 'ENFILE', 'EMFILE', 'EBUSY'].includes(error.code)) throw artifactError('ARTIFACT_OBJECT_UNAVAILABLE')
      if (error.code?.startsWith('ARTIFACT_')) throw error
      throw artifactError('ARTIFACT_INTEGRITY_FAILED')
    } finally { key?.fill(0); await handle?.close() }
  }
  async inventory(limit = 100) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw artifactError('ARTIFACT_LIMIT_INVALID')
    await this.#check()
    const items = [], dir = await fs.opendir(path.join(this.#partition, 'objects'))
    for await (const entry of dir) {
      if (!/^[a-f0-9-]{36}$/.test(entry.name) || !entry.isDirectory() || entry.isSymbolicLink()) throw artifactError('ARTIFACT_UNSAFE_PATH')
      items.push(`blob:${entry.name}`)
      if (items.length === limit) break
    }
    return items
  }
}
