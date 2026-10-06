import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import { canonicalJson } from '../../src/canonical-json.mjs'
import { agentContextDigest } from '../../src/agent-context/index.mjs'
import { hashAutomationContract } from '../../src/automation-integration/index.mjs'
import { observationFingerprint } from '../../src/operational-context/contracts.mjs'
import { bytesDigest } from '../../src/artifacts/contracts.mjs'
import { judgmentSchemas, judgmentBytesDigest, judgmentCanonicalDigest,
  validateJudgmentInput, validateJudgmentTrajectory } from '../../src/judgment/index.mjs'
import { fixture, freeze } from './helpers.mjs'

const readSource = path => JSON.parse(fs.readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8'))
const vectors = fixture('source-digest-interop.json').vectors
for (const vector of vectors) {
  test(`native source interop byte-identical: ${vector.vector_id}`, () => {
    const source = readSource(vector.source_fixture)
    const native = vector.vector_id === 'native_agent_context'
      ? agentContextDigest(source) : hashAutomationContract('event', source.event)
    assert.equal(native, source[vector.source_digest_field])
    assert.equal(native, vector.reference.digest)
    assert.deepEqual(Buffer.from(native, 'utf8'), Buffer.from(vector.reference.digest, 'utf8'))
    const input = fixture('historical-run-input.json')
    if (vector.vector_id === 'native_agent_context') {
      input.context.agent_context_digest = native
      input.context.origins.push({ origin_id: 'origin_agent_context', reference: { ...vector.reference, digest: native } })
    } else {
      input.context.elements[0].reference = { ...vector.reference, digest: native }
      input.context.origins[0].reference = { ...vector.reference, digest: native }
    }
    const before = canonicalJson(input)
    assert.deepEqual(validateJudgmentInput(freeze(input)), [])
    assert.equal(canonicalJson(input), before)

    for (const change of [
      reference => { reference.digest = `sha256:${native}` },
      reference => { reference.digest_scheme = 'sha256-bytes' },
      reference => { reference.digest_scheme = 'arbitrary-codec' },
    ]) {
      const altered = structuredClone(input)
      const reference = vector.vector_id === 'native_agent_context'
        ? altered.context.origins.at(-1).reference : altered.context.elements[0].reference
      change(reference)
      assert.deepEqual(validateJudgmentInput(altered), ['INPUT_SCHEMA'])
    }
    if (vector.vector_id === 'native_agent_context') {
      const altered = structuredClone(input)
      altered.context.agent_context_digest = `sha256:${native}`
      assert.deepEqual(validateJudgmentInput(altered), ['INPUT_SCHEMA'])
    }
  })
}

const pairs = [
  ['sha256-canonical-json-agent-context-v1', 'a'.repeat(64)],
  ['dubsar.automation.run-event.v1', 'a'.repeat(64)],
  ['memory-v2-content-digest', 'a'.repeat(64)],
  ['dubsar.oc.observation.v1', `sha256:${'a'.repeat(64)}`],
  ['sha256-bytes', `sha256:${'a'.repeat(64)}`],
]
for (const [scheme, digest] of pairs) {
  test(`closed source scheme/format pair: ${scheme}`, () => {
    const input = fixture('historical-run-input.json')
    const ref = input.context.origins[0].reference
    Object.assign(ref, { digest_scheme: scheme, digest })
    // Schema acceptance of the exact pair, independently of source-kind semantics.
    assert.deepEqual(judgmentSchemas.validate('input.schema.json', input), [])
    ref.digest = digest.startsWith('sha256:') ? digest.slice(7) : `sha256:${digest}`
    assert.ok(judgmentSchemas.validate('input.schema.json', input).length)
    ref.digest = digest.toUpperCase()
    assert.ok(judgmentSchemas.validate('input.schema.json', input).length)
    ref.digest = digest; ref.digest_scheme = 'unregistered-codec'
    assert.ok(judgmentSchemas.validate('input.schema.json', input).length)
    ref.digest_scheme = null
    assert.ok(judgmentSchemas.validate('input.schema.json', input).length)
    ref.digest = null; ref.digest_scheme = scheme
    assert.ok(judgmentSchemas.validate('input.schema.json', input).length)
    ref.digest_scheme = null
    assert.deepEqual(judgmentSchemas.validate('input.schema.json', input), [])
  })
}

test('another admitted bare-hex scheme cannot relabel an Automation source or its origin', () => {
  const input = fixture('historical-run-input.json')
  input.context.elements[0].reference.digest_scheme = 'memory-v2-content-digest'
  assert.ok(validateJudgmentInput(input).includes('SOURCE_DIGEST_SCHEME_MISMATCH'))
  assert.ok(validateJudgmentInput(input).includes('SOURCE_REFERENCE_DIGEST_MISMATCH'))
  input.context.origins[0].reference.digest_scheme = 'memory-v2-content-digest'
  assert.deepEqual(validateJudgmentInput(input), ['SOURCE_DIGEST_SCHEME_MISMATCH'])
  const memory = fixture('contradiction-input.json')
  memory.context.elements[0].reference.digest_scheme = 'dubsar.automation.run-event.v1'
  assert.ok(validateJudgmentInput(memory).includes('SOURCE_DIGEST_SCHEME_MISMATCH'))
})

test('acquired OC fingerprint and Evidence bytes retain their prefixed native representation', () => {
  const input = fixture('historical-oc-input.json')
  const observation = readSource('fixtures/operational-context/valid/observation.json')
  input.context.elements[1].reference.digest = observationFingerprint(observation)
  assert.deepEqual(validateJudgmentInput(input), [])
  input.context.elements[1].reference.digest_scheme = 'sha256-bytes'
  assert.ok(validateJudgmentInput(input).includes('SOURCE_DIGEST_SCHEME_MISMATCH'))
  const evidence = fixture('consultable-input.json')
  evidence.context.elements[1].reference.digest = bytesDigest(Buffer.from('Evidence fixture bytes', 'utf8'))
  assert.deepEqual(validateJudgmentInput(evidence), [])
})

test('Evidence requires its native bytes scheme when a digest is present, and permits null/null', () => {
  const input = fixture('consultable-input.json'), reference = input.context.elements[1].reference
  reference.digest = bytesDigest(Buffer.from('Evidence fixture bytes', 'utf8'))
  assert.deepEqual(validateJudgmentInput(input), [])
  reference.digest_scheme = 'dubsar.oc.observation.v1'
  assert.deepEqual(validateJudgmentInput(input), ['SOURCE_DIGEST_SCHEME_MISMATCH'])
  reference.digest = null; reference.digest_scheme = null
  assert.deepEqual(validateJudgmentInput(input), [])
})

test('inherited reference values cannot change inside an already captured technical turn', () => {
  const trace = fixture('trajectory-valid.json')
  trace.origins[0].reference.digest_scheme = 'memory-v2-content-digest'
  assert.ok(validateJudgmentTrajectory(trace).includes('TRACE_ORIGIN_CHANGED'))
})

test('Judgment technical digests remain prefixed and use exactly the acquired codec', () => {
  const trace = fixture('trajectory-valid.json'), input = JSON.parse(trace.input.sent_utf8)
  assert.equal(trace.input.sent_digest, judgmentBytesDigest(trace.input.sent_utf8))
  assert.equal(trace.input.canonical_digest, judgmentCanonicalDigest('input', input))
  assert.equal(trace.response.raw_digest, judgmentBytesDigest(trace.response.raw_utf8))
  for (const change of [
    t => { t.input.sent_digest = t.input.sent_digest.slice(7) },
    t => { t.input.canonical_digest = t.input.canonical_digest.slice(7) },
    t => { t.response.raw_digest = t.response.raw_digest.slice(7) },
    t => { t.previous_turn_digest = judgmentCanonicalDigest('trajectory', trace).slice(7) },
  ]) {
    const altered = structuredClone(trace); change(altered)
    assert.deepEqual(validateJudgmentTrajectory(altered), ['TRAJECTORY_SCHEMA'])
  }
  const chain = fixture('revision-trajectory.json').turns
  assert.equal(chain[1].previous_turn_digest, judgmentCanonicalDigest('trajectory', chain[0]))
})
