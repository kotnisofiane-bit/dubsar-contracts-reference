import { canonicalJson } from '../canonical-json.mjs'
import { sourceInstant, normalizeUtcDateTime, epochMs } from './time.mjs'

export const STATE_PROJECTION_CONTRACT = 'dubsar.operational-context.state-projection/1'
export const STATE_OBSERVATION_CONTRACT = 'dubsar.operational-context.observation/2'
export const SNAPSHOT_RESERVE = 'LAST_VERIFIED_SNAPSHOT_NOT_CONTINUOUS_MONITORING'

// Delivery/transport identifiers are not the identity of a measured snapshot.
// Everything affecting the assertion or its qualification IS part of that identity.
export function snapshotContent(document) {
  return canonicalJson({
    subject: document.subject,
    property: document.property,
    result: document.result,
    provenance: document.provenance,
    source_observed_at: document.source_observed_at,
    scope: document.scope,
    state_order: document.state_order,
    rule_ref: document.rule_ref,
    rule_version: document.rule_version,
    correction_of: document.correction_of ?? null,
    retraction_of: document.retraction_of ?? null,
    content_refs: document.content_refs ?? [],
  })
}

function reference(row) {
  return {
    observation_ref: row.local_ref,
    producer_id: row.producer_id,
    result_kind: row.document.result.kind,
    ...(Object.hasOwn(row.document.result, 'value') ? { value: row.document.result.value } : {}),
    state_order: row.document.state_order ?? null,
    source_observed_at: row.document.source_observed_at,
    received_at: row.received_at,
  }
}

export function matchesStateGeneration(row, binding) {
  const doc = row.document
  return binding != null && doc.contract === STATE_OBSERVATION_CONTRACT
    && row.producer_id === binding.producer_id && row.source_instance_id === binding.source_instance_id
    && doc.state_order?.producer_epoch === binding.producer_epoch
    && doc.provenance?.mapping_ref === binding.mapping_ref && doc.provenance?.mapping_version === binding.mapping_version
    && doc.rule_ref === binding.rule_ref && doc.rule_version === binding.rule_version
}

// Pure projection over a caller-certified complete, authorized set of supports.
// An incomplete page can never establish an eligible head.
export function projectState({ observations, binding, mapping, rule, instant,
  resource_ref, property, complete = false, superseded_observation_refs = [] }) {
  const at = normalizeUtcDateTime(instant)
  const atMs = epochMs(at)
  const limits = new Set()
  const result = {
    contract: STATE_PROJECTION_CONTRACT,
    resource_ref, property, instant: at,
    binding_ref: binding?.binding_ref ?? null,
    binding_version: binding?.version ?? null,
    mapping_ref: binding?.mapping_ref ?? null,
    mapping_version: binding?.mapping_version ?? null,
    rule_ref: binding?.rule_ref ?? null,
    rule_version: binding?.rule_version ?? null,
    producer_epoch: binding?.producer_epoch ?? null,
    candidate: null, eligible: false, freshness: 'not_applicable',
    age_ms: null, freshness_max_age_ms: null,
    history: [], history_truncated: !complete, head_complete: complete,
    limits: [], reserves: [{ code: SNAPSHOT_RESERVE }],
  }
  const finish = () => ({ ...result, limits: [...limits].sort().map(code => ({ code })) })
  if (!complete) limits.add('STATE_SUPPORTS_INCOMPLETE')
  if (!binding || binding.status !== 'admitted'
      || binding.resource_local_ref !== resource_ref || binding.property !== property
      || epochMs(binding.effective_at) > atMs) {
    limits.add('STATE_BINDING_UNAVAILABLE')
    return finish()
  }
  if (!mapping || mapping.status !== 'admitted'
      || mapping.mapping_ref !== binding.mapping_ref || mapping.version !== binding.mapping_version
      || mapping.property !== property || mapping.temporal_mode !== 'ordered_snapshot'
      || mapping.producer_id !== binding.producer_id
      || mapping.source_instance_id !== binding.source_instance_id
      || mapping.value_type !== 'string') limits.add('MAPPING_UNAVAILABLE')
  if (!rule || rule.status !== 'admitted'
      || rule.rule_ref !== binding.rule_ref || rule.version !== binding.rule_version
      || !Number.isSafeInteger(rule.freshness_max_age_ms) || rule.freshness_max_age_ms < 0) {
    limits.add('RULE_UNAVAILABLE')
  } else result.freshness_max_age_ms = rule.freshness_max_age_ms

  const legacy = new Set(binding.legacy_observation_refs)
  // Certified by deterministic policy history at each support's received_at.
  // A tuple mismatch alone cannot establish that a generation was admitted.
  const superseded = new Set(superseded_observation_refs)
  const snapshots = []
  const seen = new Set()
  for (const row of observations) {
    if (seen.has(row.local_ref)) continue
    seen.add(row.local_ref)
    if (row.resource_local_ref !== resource_ref || row.property !== property
        || row.tenant_id !== binding.tenant_id || row.environment_id !== binding.environment_id) {
      limits.add('STATE_SCOPE_MISMATCH')
      continue
    }
    if (epochMs(row.received_at) > atMs) continue
    const doc = row.document
    if (legacy.has(row.local_ref)) {
      if (doc.contract !== 'dubsar.operational-context.observation/1') limits.add('STATE_LEGACY_MISMATCH')
      result.history.push({ ...reference(row), classification: 'legacy' })
      continue
    }
    const order = doc.state_order
    if (doc.contract === STATE_OBSERVATION_CONTRACT && !matchesStateGeneration(row, binding)
        && superseded.has(row.local_ref)) {
      result.history.push({ ...reference(row), classification: 'previous' })
      continue
    }
    if (doc.contract !== STATE_OBSERVATION_CONTRACT
        || row.producer_id !== binding.producer_id
        || row.source_instance_id !== binding.source_instance_id
        || order?.producer_epoch !== binding.producer_epoch) {
      limits.add('STATE_LINEAGE_UNRECOGNIZED')
      result.history.push({ ...reference(row), classification: 'unrecognized' })
      continue
    }
    if (!Number.isSafeInteger(order.sequence) || order.sequence < 1) {
      limits.add('STATE_ORDER_INVALID')
      result.history.push({ ...reference(row), classification: 'invalid_order' })
      continue
    }
    if (doc.correction_of || doc.retraction_of) limits.add('STATE_SUPPORT_MUTATED')
    if (doc.provenance.mapping_ref !== binding.mapping_ref
        || doc.provenance.mapping_version !== binding.mapping_version
        || doc.rule_ref !== binding.rule_ref || doc.rule_version !== binding.rule_version) {
      limits.add('STATE_POLICY_MISMATCH')
    }
    if (doc.result.kind !== 'measured' || doc.result.value_type !== 'string'
        || !/^[0-9a-f]{40}$/.test(doc.result.value) || doc.scope.complete !== true) {
      limits.add('STATE_SNAPSHOT_INVALID')
    }
    const source = sourceInstant(doc.source_observed_at)
    if (source.kind === 'unknown') limits.add('STATE_SOURCE_DATE_UNKNOWN')
    else if (source.epoch_ms > epochMs(row.received_at)) limits.add('STATE_SOURCE_DATE_FUTURE')
    snapshots.push(row)
  }
  snapshots.sort((a, b) => a.document.state_order.sequence - b.document.state_order.sequence
    || (a.local_ref < b.local_ref ? -1 : a.local_ref > b.local_ref ? 1 : 0))
  const groups = new Map()
  let lastSource = null
  for (const row of snapshots) {
    const sequence = row.document.state_order.sequence
    const fingerprint = snapshotContent(row.document)
    const previous = groups.get(sequence)
    if (previous && previous.fingerprint !== fingerprint) {
      limits.add('STATE_SEQUENCE_CONFLICT')
      previous.conflict = true
    }
    if (!previous) groups.set(sequence, { row, fingerprint, conflict: false })
    const source = sourceInstant(row.document.source_observed_at)
    if (source.kind === 'known') {
      if (lastSource !== null && source.epoch_ms < lastSource) limits.add('STATE_SOURCE_DATE_REGRESSION')
      lastSource = Math.max(lastSource ?? source.epoch_ms, source.epoch_ms)
    }
  }
  const head = [...groups.values()].at(-1)?.row
  if (!head) {
    limits.add('STATE_SNAPSHOT_UNAVAILABLE')
    return finish()
  }
  // An inconsistent stream cannot acquire a winner merely by appending another row.
  const incoherent = [...limits].some(code => code.startsWith('STATE_'))
  if (!incoherent) result.candidate = reference(head)
  for (const row of snapshots) {
    if (row.local_ref === result.candidate?.observation_ref) continue
    const group = groups.get(row.document.state_order.sequence)
    const classification = group.conflict ? 'sequence_conflict'
      : row.document.state_order.sequence === head.document.state_order.sequence
        ? result.candidate ? 'same_snapshot' : 'blocked_head'
        : 'previous'
    result.history.push({ ...reference(row), classification })
  }
  result.history.sort((a, b) => a.observation_ref < b.observation_ref ? -1 : 1)
  const source = sourceInstant(head.document.source_observed_at)
  if (source.kind === 'unknown') result.freshness = 'unknown_source_date'
  else {
    result.age_ms = atMs - source.epoch_ms
    result.freshness = !limits.has('RULE_UNAVAILABLE') && result.age_ms >= 0
      && result.age_ms <= rule.freshness_max_age_ms ? 'current' : 'stale'
  }
  result.eligible = limits.size === 0 && result.candidate !== null && result.freshness === 'current'
  return finish()
}
