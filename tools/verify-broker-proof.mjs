import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalJson, domainSeparatedHash } from '../src/canonical-json.mjs'
import { ContractOnlyCapabilityVerifier } from '../src/broker/contract-only-capability-verifier.mjs'
import { DeterministicPilotExecutor } from '../src/broker/deterministic-pilot-executor.mjs'
import { InMemoryActionBroker } from '../src/broker/in-memory-action-broker.mjs'
import { hashContract, receiptEvidenceDigest } from '../src/contracts.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const brokerFiles = [
  'src/broker/broker-error.mjs',
  'src/broker/contract-only-capability-verifier.mjs',
  'src/broker/deterministic-pilot-executor.mjs',
  'src/broker/in-memory-action-broker.mjs',
  'src/broker/in-memory-action-state-store.mjs',
]
const request = {
  proposal: fixture('action-proposal'),
  capabilityClaims: fixture('capability-claims'),
  workflow: fixture('workflow-ir'),
  approval: fixture('approval-record'),
  previousEvidenceDigest: 'sha256:3333333333333333333333333333333333333333333333333333333333333333',
}
const executor = new DeterministicPilotExecutor()
const broker = new InMemoryActionBroker({
  clock: { now: () => '2026-08-14T10:00:30.000Z' },
  capabilityVerifier: new ContractOnlyCapabilityVerifier(),
  workloadIdentityProvider: {
    current: () => ({ workload_id: 'workload_worker_demo_001', instance_id: 'instance_worker_demo_001' }),
  },
  executor,
  brokerIdentity: { workload_id: 'workload_broker_demo_001', instance_id: 'instance_broker_demo_001' },
})
const receipt = await broker.submit(request)
const receiptBytes = `${JSON.stringify(receipt, null, 2)}\n`
const sourceFiles = brokerFiles.map(relativePath => ({
  path: relativePath,
  sha256: sha256(fs.readFileSync(path.join(root, ...relativePath.split('/')))),
}))
const contractHashes = readJson(path.join(root, 'CONTRACT_HASHES.json'))
const proof = {
  schema: 'dubsar.in-memory-broker-proof.v1',
  contract_version: '1.0.0',
  contract_set_aggregate_digest: contractHashes.aggregate_digest,
  source_files: sourceFiles,
  source_aggregate_digest: domainSeparatedHash('dubsar.in-memory-broker-source.v1', { files: sourceFiles }),
  pilot: {
    proposal_digest: hashContract('action-proposal', request.proposal),
    capability_digest: hashContract('capability-claims', request.capabilityClaims),
    receipt_contract_digest: hashContract('action-receipt', receipt),
    receipt_file_sha256: sha256(receiptBytes),
    evidence_event_digest: receiptEvidenceDigest(receipt),
    final_state: broker.getAction(request.proposal.proposal_id).state,
    transitions: broker.getAction(request.proposal.proposal_id).transitions.length,
    executions: executor.executionCount,
  },
  boundaries: {
    authority_verifier: 'contract_only_injected_non_cryptographic',
    evidence_plane: 'previous_digest_only_no_independent_plane',
    external_effects: 'none',
    storage: 'process_memory_only',
  },
}

if (process.argv.includes('--print')) {
  process.stdout.write(`${JSON.stringify({ receipt, proof }, null, 2)}\n`)
  process.exit(0)
}

const expectedReceipt = fs.readFileSync(path.join(root, 'fixtures', 'v1', 'broker', 'pilot-action-receipt.json'), 'utf8')
const expectedProof = readJson(path.join(root, 'BROKER_PROOF.json'))
if (expectedReceipt !== receiptBytes) throw new Error('pilot Action Receipt bytes do not match the deterministic execution')
if (canonicalJson(expectedProof) !== canonicalJson(proof)) throw new Error('BROKER_PROOF.json does not match current sources and execution')

process.stdout.write(`${JSON.stringify({
  gate: 'in-memory-broker-proof',
  final_state: proof.pilot.final_state,
  transitions: proof.pilot.transitions,
  executions: proof.pilot.executions,
  receipt_contract_digest: proof.pilot.receipt_contract_digest,
  source_aggregate_digest: proof.source_aggregate_digest,
})}\n`)

function fixture(kind) {
  return readJson(path.join(root, 'fixtures', 'v1', kind, 'valid.json'))
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'))
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}
