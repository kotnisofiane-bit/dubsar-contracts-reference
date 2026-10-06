import fs from 'node:fs'

export const fixture = name => JSON.parse(fs.readFileSync(new URL(`../../fixtures/judgment/v1/${name}`, import.meta.url), 'utf8'))

// RFC 6902 add/replace subset used by portable fixture vectors, never runtime input.
export function vectorInput(vector) {
  const input = fixture(vector.input_fixture)
  for (const patch of vector.input_patch) {
    if (!['add', 'replace'].includes(patch.op)) throw new Error('Unsupported fixture patch')
    const parts = patch.path.slice(1).split('/').map(key => key.replaceAll('~1', '/').replaceAll('~0', '~'))
    let target = input
    for (const key of parts.slice(0, -1)) target = target[key]
    const key = parts.at(-1)
    if (patch.op === 'replace' && !Object.hasOwn(target, key)) throw new Error('Missing fixture patch target')
    target[key] = structuredClone(patch.value)
  }
  return input
}

export function freeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value)) freeze(entry)
    Object.freeze(value)
  }
  return value
}
