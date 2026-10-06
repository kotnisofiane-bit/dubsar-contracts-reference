import fs from 'node:fs'
import { createOperationalContextKernel, ocRegistry, validateClosed, OC_BOUNDS, OC_CONTRACTS } from '../../src/operational-context/index.mjs'

const kinds = ['observation', 'resource', 'trust', 'mapping', 'rule', 'view-request', 'association']
const references = ocRegistry.assertAllReferencesClosed()
const fixtures = []
for (const kind of kinds) {
  const valid = JSON.parse(fs.readFileSync(new URL(`../../fixtures/operational-context/valid/${kind}.json`, import.meta.url)))
  const invalid = JSON.parse(fs.readFileSync(new URL(`../../fixtures/operational-context/invalid/${kind}.json`, import.meta.url)))
  validateClosed(`${kind}.schema.json`, valid)
  let rejected = false
  try { validateClosed(`${kind}.schema.json`, invalid) } catch { rejected = true }
  if (!rejected) throw new Error(`${kind} invalid fixture was accepted`)
  fixtures.push({ kind, valid: 'accepted', invalid: 'rejected' })
}

const kernelExport = typeof createOperationalContextKernel
if (kernelExport !== 'function') throw new Error('kernel is not importable')

process.stdout.write(`${JSON.stringify({
  gate: 'operational-context-kernel-v0',
  import: 'src/operational-context/index.mjs',
  schema_documents: ocRegistry.schemaNames().length,
  resolved_references: references.length,
  fixtures,
  bounds: OC_BOUNDS,
  contracts: OC_CONTRACTS,
}, null, 2)}\n`)
