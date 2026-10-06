import { createHash } from 'node:crypto'
import { validateAgentAutomationResults } from './automation-results.mjs'

export const AGENT_CONTEXT_FORMAT = 'dubsar.agent-context/1'
export const AGENT_CONTEXT_AUTHORITY = 'none'
export const AGENT_CONTEXT_CONTENT_TRUST = 'advisory_data'
export const AGENT_CONTEXT_TEXT_ROLE = 'data'
export const AGENT_CONTEXT_TRUTH = 'not_selected'

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
    )
  }
  return value
}

export function agentContextDigestBasis(context) {
  const copy = structuredClone(context)
  delete copy.context_digest
  if (copy.bounds && typeof copy.bounds === 'object') {
    delete copy.bounds.serialized_bytes
    delete copy.bounds.render_chars
  }
  return canonical(copy)
}

export function agentContextDigest(context) {
  const body = JSON.stringify(agentContextDigestBasis(context))
  return createHash('sha256').update(body, 'utf8').digest('hex')
}

export function validateAgentContextEnvelope(context) {
  const errors = []
  if (!context || typeof context !== 'object' || Array.isArray(context)) return ['context must be an object']
  if (context.format !== AGENT_CONTEXT_FORMAT) errors.push('format')
  if (context.kind !== 'agent_context_view') errors.push('kind')
  if (context.authority !== AGENT_CONTEXT_AUTHORITY) errors.push('authority')
  if (Object.hasOwn(context, 'executable') && context.executable !== false) errors.push('executable')
  if (Object.hasOwn(context, 'automation_results')) errors.push(...validateAgentAutomationResults(context.automation_results))
  if (context.content_trust !== AGENT_CONTEXT_CONTENT_TRUST) errors.push('content_trust')
  if (context.text_role !== AGENT_CONTEXT_TEXT_ROLE) errors.push('text_role')
  if (context.truth !== AGENT_CONTEXT_TRUTH) errors.push('truth')
  if (!/^[0-9a-f]{64}$/u.test(context.context_digest ?? '')) errors.push('context_digest')
  if (!['complete', 'partial', 'unavailable'].includes(context.coverage?.status)) errors.push('coverage.status')
  if (context.coverage?.selection_method !== 'trusted_profile_readonly_ports') errors.push('coverage.selection_method')
  if (!Array.isArray(context.limits)) errors.push('limits')
  return errors
}
