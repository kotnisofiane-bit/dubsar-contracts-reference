import { ocError } from './errors.mjs'
import { validateTrust } from './contracts.mjs'

const ACTIONS = Object.freeze([
  'observe',
  'correct',
  'retract',
  'register_resource',
  'propose_association',
  'admit_association',
  'revoke_association',
  'admit_mapping',
  'revoke_mapping',
  'admit_rule',
  'revoke_rule',
  'admit_state_policy',
  'revoke_state_policy',
  'read',
  'rebuild',
])

function grantKey(grant) {
  return [
    grant.tenant_id,
    grant.environment_id,
    grant.principal_id,
    grant.action,
    grant.resource_local_ref ?? '*',
    grant.property ?? '*',
    grant.producer_id ?? '*',
  ].join('\u001f')
}

export class SimulatedAuthority {
  constructor() {
    this.grants = new Map()
    this.unavailable = false
    this.mode = 'simulated_lab_authority'
  }

  grant(input) {
    const grant = { ...input, enabled: input.enabled !== false }
    this.grants.set(grantKey(grant), grant)
    return grant
  }

  revoke(input) {
    const existing = this.grants.get(grantKey({ ...input, enabled: true }))
    if (existing) existing.enabled = false
    this.grant({ ...input, enabled: false })
  }

  setUnavailable(value) {
    this.unavailable = value === true
  }

  async authorize(request) {
    if (this.unavailable) throw ocError('OC_AUTHORITY_UNAVAILABLE', 'authority unavailable')
    if (!ACTIONS.includes(request.action)) throw ocError('OC_CONTRACT_UNKNOWN', 'unknown authorization action')
    validateTrust(request.trust)
    const matches = [...this.grants.values()].filter(grant => grant.enabled !== false
      && grant.tenant_id === request.trust.tenant_id
      && grant.environment_id === request.trust.environment_id
      && grant.principal_id === request.trust.principal_id
      && grant.action === request.action
      && (grant.resource_local_ref === undefined || grant.resource_local_ref === '*'
        || request.resource_local_ref === undefined
        || grant.resource_local_ref === request.resource_local_ref)
      && (grant.property === undefined || grant.property === '*'
        || request.property === undefined
        || grant.property === request.property)
      && (grant.producer_id === undefined || grant.producer_id === '*'
        || request.producer_id === undefined
        || grant.producer_id === request.producer_id))
    if (matches.length === 0) throw ocError('OC_UNAUTHORIZED', 'authorization denied')
    return { decision: 'allow', mode: this.mode }
  }

  async revalidate(request) {
    return this.authorize(request)
  }
}

export async function requireAuthority(authority, request) {
  if (authority === undefined || authority === null) {
    throw ocError('OC_AUTHORITY_MISSING', 'authorization port is required')
  }
  if (typeof authority.authorize !== 'function' || typeof authority.revalidate !== 'function') {
    throw ocError('OC_AUTHORITY_MISSING', 'authorization port is incomplete')
  }
  try {
    const result = await authority.authorize(request)
    if (result === true) return { decision: 'allow' }
    if (result?.decision === 'allow') return result
    throw ocError('OC_UNAUTHORIZED', 'authorization denied')
  } catch (error) {
    if (error?.code === 'OC_UNAUTHORIZED' || error?.code === 'OC_AUTHORITY_MISSING') throw error
    if (error?.code === 'OC_AUTHORITY_UNAVAILABLE') throw error
    throw ocError('OC_AUTHORITY_UNAVAILABLE', 'authorization port failed')
  }
}

export async function revalidateAuthority(authority, request) {
  if (authority === undefined || authority === null) {
    throw ocError('OC_AUTHORITY_MISSING', 'authorization port is required')
  }
  try {
    const result = await authority.revalidate(request)
    if (result === true) return { decision: 'allow' }
    if (result?.decision === 'allow') return result
    throw ocError('OC_UNAUTHORIZED', 'authorization denied')
  } catch (error) {
    if (error?.code === 'OC_UNAUTHORIZED' || error?.code === 'OC_AUTHORITY_MISSING') throw error
    throw ocError('OC_AUTHORITY_UNAVAILABLE', 'authorization port failed')
  }
}
