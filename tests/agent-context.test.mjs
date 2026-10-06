import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  AGENT_CONTEXT_AUTHORITY,
  AGENT_CONTEXT_CONTENT_TRUST,
  AGENT_CONTEXT_FORMAT,
  AGENT_CONTEXT_TEXT_ROLE,
  AGENT_CONTEXT_TRUTH,
  agentContextDigest,
  validateAgentContextEnvelope,
} from '../src/agent-context/index.mjs'
import { SchemaRegistry } from '../src/schema-validator.mjs'

const validPath = new URL('../fixtures/agent-context/v1/valid.json', import.meta.url)
const invalidPath = new URL('../fixtures/agent-context/v1/invalid-authority.json', import.meta.url)
const vectorPath = new URL('../fixtures/agent-context/v1/digest-vector.json', import.meta.url)
const schemaPath = new URL('../schemas/agent-context/v1/agent-context.schema.json', import.meta.url)
const read = (url) => JSON.parse(fs.readFileSync(url, 'utf8'))
const schemaDirectory = path.dirname(fileURLToPath(schemaPath))
const registry = new SchemaRegistry(schemaDirectory)

test('agent-context v1 fixed semantics and closed schema are declared', () => {
  const schema = read(schemaPath)
  assert.equal(schema.additionalProperties, false)
  for (const field of ['format', 'authority', 'content_trust', 'text_role', 'truth', 'captured_at', 'context_digest', 'memory', 'my_work', 'operational_context', 'coverage', 'limits', 'bounds']) {
    assert.ok(schema.required.includes(field), field)
  }
  assert.equal(schema.properties.format.const, AGENT_CONTEXT_FORMAT)
  assert.equal(schema.properties.authority.const, AGENT_CONTEXT_AUTHORITY)
  assert.equal(schema.properties.content_trust.const, AGENT_CONTEXT_CONTENT_TRUST)
  assert.equal(schema.properties.text_role.const, AGENT_CONTEXT_TEXT_ROLE)
  assert.equal(schema.properties.truth.const, AGENT_CONTEXT_TRUTH)
})


test('agent-context schema accepts valid fixture and rejects authority or extra fields', () => {
  const valid = read(validPath)
  assert.deepEqual(registry.validate('agent-context.schema.json', valid), [])

  const invalidAuthority = structuredClone(valid)
  invalidAuthority.authority = 'human'
  assert.ok(registry.validate('agent-context.schema.json', invalidAuthority).length > 0)

  const extra = structuredClone(valid)
  extra.execute = true
  assert.ok(registry.validate('agent-context.schema.json', extra).length > 0)

  assert.ok(registry.assertAllReferencesClosed().length > 0)
})

test('agent-context v1 valid fixture has a reproducible semantic digest', () => {
  const value = read(validPath)
  const vector = read(vectorPath)
  const first = agentContextDigest(value)
  const second = agentContextDigest(structuredClone(value))
  assert.equal(first, second)
  assert.equal(first, vector.expected_digest)
  value.context_digest = first
  assert.deepEqual(validateAgentContextEnvelope(value), [])
})

test('agent-context digest changes on semantic source change but not measurement outputs', () => {
  const value = read(validPath)
  const initial = agentContextDigest(value)
  const measured = structuredClone(value)
  measured.context_digest = 'f'.repeat(64)
  measured.bounds.render_chars = 123
  measured.bounds.serialized_bytes = 456
  assert.equal(agentContextDigest(measured), initial)
  const changed = structuredClone(value)
  changed.memory.relations[0].statement = 'Changed source meaning.'
  assert.notEqual(agentContextDigest(changed), initial)
})

test('agent-context refuses authority other than none', () => {
  const invalid = read(invalidPath)
  assert.ok(validateAgentContextEnvelope(invalid).includes('authority'))
})
