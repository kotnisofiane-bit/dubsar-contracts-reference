import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'public-source-manifest.json'), 'utf8'))
const allowlist = JSON.parse(fs.readFileSync(path.join(root, 'public-allowlist.json'), 'utf8'))
const digest = file => 'sha256:' + createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex')

const listed = new Set()
for (const entry of [...manifest.files, ...manifest.new_files]) {
  if (listed.has(entry.public_path)) throw new Error(`duplicate manifest entry: ${entry.public_path}`)
  listed.add(entry.public_path)
  if (entry.public_path === 'public-source-manifest.json') continue
  if (digest(entry.public_path) !== entry.public_digest) throw new Error(`digest mismatch: ${entry.public_path}`)
  if (entry.status === 'identical' && entry.source_digest !== entry.public_digest) throw new Error(`identical entry differs from source: ${entry.public_path}`)
}

const present = []
const walk = dir => {
  for (const item of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
    const rel = dir ? `${dir}/${item.name}` : item.name
    if (['.git', 'node_modules'].includes(rel)) continue
    if (item.isDirectory()) walk(rel)
    else present.push(rel)
  }
}
walk('')
const unlisted = present.filter(file => !listed.has(file))
const missing = [...listed].filter(file => !present.includes(file))
if (unlisted.length || missing.length) throw new Error(`tree/manifest mismatch: unlisted=${unlisted} missing=${missing}`)

const allowed = new Set(allowlist.files)
const outsideAllowlist = present.filter(file => !allowed.has(file))
if (outsideAllowlist.length || allowed.size !== present.length) throw new Error(`tree/allowlist mismatch: ${outsideAllowlist}`)

console.log(`public manifest: ${present.length} files verified (${manifest.counts.identical} identical, ${manifest.counts.adapted} adapted, ${manifest.counts.new_public} new)`)
