import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { CONTRACT_KINDS, hashContract, proposalPayloadDigest } from '../src/contracts.mjs'
import { canonicalJson, domainSeparatedHash } from '../src/canonical-json.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const manifestPath = path.join(root, 'CONTRACT_HASHES.json')

const canonicalPaths = [
  'contracts/v1/contract-set.json',
  'contracts/v1/execution-state-machine.json',
  'schemas/v1/action-proposal.schema.json',
  'schemas/v1/action-receipt.schema.json',
  'schemas/v1/approval-record.schema.json',
  'schemas/v1/capability-claims.schema.json',
  'schemas/v1/common.schema.json',
  'schemas/v1/execution-lease.schema.json',
  'schemas/v1/state-transition.schema.json',
  'schemas/v1/task-lease.schema.json',
  'schemas/v1/workflow-ir.schema.json',
  'fixtures/v1/task-lease/closed-profile.json',
  'fixtures/v1/task-lease/signed-vector.json',
]

const files = canonicalPaths.map(relativePath => ({
  path: relativePath,
  sha256: sha256File(path.join(root, ...relativePath.split('/'))),
}))

const fixtureContractDigests = CONTRACT_KINDS.map(kind => {
  const relativePath = `fixtures/v1/${kind}/valid.json`
  const value = readJson(path.join(root, ...relativePath.split('/')))
  return { kind, path: relativePath, digest: hashContract(kind, value) }
})

const proposal = readJson(path.join(root, 'fixtures', 'v1', 'action-proposal', 'valid.json'))
const bound = { files, fixture_contract_digests: fixtureContractDigests }
const generated = {
  schema: 'dubsar.contract-hashes.v1',
  contract_version: '1.0.0',
  files,
  fixture_contract_digests: fixtureContractDigests,
  payload_fixture_digest: proposalPayloadDigest(proposal),
  aggregate_digest: domainSeparatedHash('dubsar.contract-set-manifest.v1', bound),
}

if (process.argv.includes('--print')) {
  process.stdout.write(`${JSON.stringify(generated, null, 2)}\n`)
  process.exit(0)
}

const committed = readJson(manifestPath)
if (canonicalJson(committed) !== canonicalJson(generated)) {
  throw new Error('CONTRACT_HASHES.json does not match canonical files and fixtures')
}

process.stdout.write(`${JSON.stringify({
  gate: 'contract-hashes',
  files: files.length,
  contract_digests: fixtureContractDigests.length,
  aggregate_digest: generated.aggregate_digest,
})}\n`)

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'))
}

function sha256File(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')
}
