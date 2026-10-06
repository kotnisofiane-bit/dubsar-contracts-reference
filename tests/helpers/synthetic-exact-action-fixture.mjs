import fs from 'node:fs'
import assert from 'node:assert/strict'
import { setupExact } from './exact-action-fixture.mjs'
import { prepareExactAction, hashExact } from '../../src/exact-action/contracts.mjs'

const root = new URL('../../fixtures/qualification/synthetic-exact-action/', import.meta.url)
export const syntheticMessage = JSON.parse(fs.readFileSync(new URL('message.json', root)))
export const syntheticCases = JSON.parse(fs.readFileSync(new URL('cases.json', root))).cases
export const attachmentBytes = fs.readFileSync(new URL(syntheticMessage.attachment.asset, root))
export const alteredBytes = fs.readFileSync(new URL('fixture-note-altered.txt', root))

export const syntheticCase = caseId => {
  const found = syntheticCases.find(c => c.id === caseId)
  assert.ok(found, 'known synthetic case')
  return found
}

// Harness-only mapping onto the existing generic connector, tenant policy and
// qualification clock of setupExact; nothing authenticates a provider or a human.
export function setupSyntheticExact(caseId, options = {}) {
  syntheticCase(caseId)
  const f = setupExact(options)
  const m = syntheticMessage
  f.proposal.payload = {
    from: m.sender, to: [...m.to], cc: [...m.cc], bcc: [...m.bcc],
    subject: m.subject, text: m.body, html: null, thread_ref: m.thread_ref,
    attachments: [{ name: m.attachment.filename, content: attachmentBytes.toString('utf8'),
      content_type: m.attachment.media_type }],
  }
  f.binding.mission.id = 'mis_synthetic_' + caseId.toLowerCase() + '_00000001'
  reprepareSynthetic(f, 1)
  return f
}

// Re-preparation deliberately does NOT refresh the trusted decision.
export function reprepareSynthetic(f, revision) {
  const previous = f.prepared
  const next = prepareExactAction({ binding: f.binding, proposal: f.proposal, approval: f.approval,
    material: f.material, expectedEffect: 'Instrumented synthetic content capture; no provider call',
    artifactRef: 'artifact:synthetic:content:' + revision, displayRef: 'artifact:synthetic:display:' + revision,
    issuedAt: previous.issued_at, expiresAt: previous.expires_at })
  Object.assign(f.prepared, next.prepared)
  f.state.artifacts.set(next.prepared.artifact.ref, structuredClone(f.proposal.payload))
  f.state.artifacts.set(next.prepared.display.ref, next.display)
  if (revision === 1) {
    Object.assign(f.decision, { binding_digest: hashExact('binding', f.binding),
      prepared_digest: hashExact('prepared', f.prepared), display_digest: f.prepared.display.digest })
    f.state.record.principal.presented_digest = f.prepared.display.digest
  }
  return next
}

export function applySyntheticVariant(f, variant) {
  const p = f.proposal.payload
  const fields = { sender: 'from', body: 'text', subject: 'subject', to: 'to', cc: 'cc', bcc: 'bcc' }
  if (fields[variant.field]) p[fields[variant.field]] = structuredClone(variant.value)
  else if (variant.field === 'attachment.asset') p.attachments[0].content = alteredBytes.toString('utf8')
  else if (variant.field === 'attachment.filename') p.attachments[0].name = variant.value
  else if (variant.field === 'attachment.media_type') p.attachments[0].content_type = variant.value
  else throw new Error('Unsupported fixture variant')
}
