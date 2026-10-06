import { fileURLToPath } from 'node:url'
import { SchemaRegistry } from '../schema-validator.mjs'
import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'

export const registry = new SchemaRegistry(fileURLToPath(new URL('../../schemas/document-access/v1/', import.meta.url)))
export const failure = code => Object.assign(new Error(code), { code })
export const deny = () => { throw failure('DOCUMENT_DENIED') }
export function validate(name, value) {
  try {
    if (Buffer.byteLength(canonicalJson(value)) > 65536) deny()
    registry.assertValid(`${name}.schema.json`, value)
  } catch { deny() }
  return structuredClone(value)
}
export function resources(values) {
  const sorted = structuredClone(values).sort((a, b) => canonicalJson(a) < canonicalJson(b) ? -1 : canonicalJson(a) > canonicalJson(b) ? 1 : 0)
  if (new Set(sorted.map(canonicalJson)).size !== sorted.length) deny()
  return sorted
}
export const digest = value => domainSeparatedHash('dubsar.document-scope.v1', value)
export function decision(value) {
  validate('decision', value)
  const { scope_digest, ...body } = value
  if (scope_digest !== digest(body)) deny()
  return structuredClone(value)
}
