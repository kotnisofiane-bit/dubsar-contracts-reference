import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { CONTRACT_KINDS, schemaRegistry, validateContract } from '../src/contracts.mjs'
import { ACTION_STATES, STATE_MACHINE, allowedTransitionCount, isTransitionAllowed } from '../src/state-machine.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const fixturesRoot = path.join(root, 'fixtures', 'v1')
const references = schemaRegistry.assertAllReferencesClosed()

const fixtureResults = []
for (const kind of CONTRACT_KINDS) {
  const directory = path.join(fixturesRoot, kind)
  const valid = readJson(path.join(directory, 'valid.json'))
  const invalid = readJson(path.join(directory, 'invalid.json'))
  const validErrors = validateContract(kind, valid)
  const invalidErrors = validateContract(kind, invalid)
  if (validErrors.length > 0) throw new Error(`${kind} valid fixture rejected: ${validErrors.join('; ')}`)
  if (invalidErrors.length === 0) throw new Error(`${kind} invalid fixture was accepted`)
  fixtureResults.push({ kind, valid: 'accepted', invalid: 'rejected' })
}

const declaredStates = new Set(STATE_MACHINE.states)
if (declaredStates.size !== STATE_MACHINE.states.length || declaredStates.size !== ACTION_STATES.length) {
  throw new Error('state machine states are not unique')
}
for (const { from, to } of STATE_MACHINE.allowed_transitions) {
  if (!declaredStates.has(from) || !declaredStates.has(to) || !isTransitionAllowed(from, to)) {
    throw new Error('state machine contains an invalid transition')
  }
}
if (allowedTransitionCount() !== 11) throw new Error('state machine must declare exactly 11 transitions')

process.stdout.write(`${JSON.stringify({
  gate: 'dubsar-contract-plane-v1',
  canonical_contracts: CONTRACT_KINDS.length,
  schema_documents: schemaRegistry.schemaNames().length,
  resolved_references: references.length,
  fixtures: fixtureResults,
  states: ACTION_STATES.length,
  allowed_transitions: allowedTransitionCount(),
})}\n`)

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'))
}
