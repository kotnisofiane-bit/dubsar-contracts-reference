import { canonicalJson } from '../canonical-json.mjs'
import { OC_CONTRACTS } from './bounds.mjs'
import { epochMs, normalizeUtcDateTime, sourceInstant } from './time.mjs'
import { qualificationFingerprint } from './contracts.mjs'

function periodsOverlap(left, right) {
  return !(left.end < right.start || right.end < left.start)
}

function measuredCanonical(result) {
  if (result.kind !== 'measured') return null
  return canonicalJson({ type: result.value_type, value: result.value })
}

function currentRows(observations) {
  const retracted = new Set(observations.filter(row => row.retraction_of).map(row => row.retraction_of))
  const assertions = new Map(observations.filter(row => !row.retraction_of).map(row => [row.local_ref, row]))
  const corrections = new Map()
  for (const row of assertions.values()) {
    if (!row.correction_of) continue
    const list = corrections.get(row.correction_of) ?? []
    list.push(row)
    corrections.set(row.correction_of, list)
  }
  // Retraction removes only its target assertion, not its live descendants.
  // Resolve every branch before comparing values; never resurrect a superseded
  // base merely because a correction's parent was retracted.
  function resolve(row, path = new Set()) {
    if (path.has(row.local_ref)) return []
    const next = new Set(path).add(row.local_ref)
    const descendants = (corrections.get(row.local_ref) ?? []).flatMap(kid => resolve(kid, next))
    return descendants.length ? descendants : retracted.has(row.local_ref) ? [] : [row]
  }
  const current = []
  for (const row of assertions.values()) {
    if (assertions.has(row.correction_of)) continue
    const leaves = resolve(row).sort((a, b) => a.local_ref < b.local_ref ? -1 : 1)
    const values = new Set(leaves.map(leaf => measuredCanonical(leaf.document.result) ?? leaf.fingerprint))
    if (values.size > 1) {
      current.push(...leaves.map(leaf => ({ ...leaf, divergent_corrections: true })))
    } else if (leaves.length) current.push(leaves[0])
  }
  current.sort((a, b) => a.local_ref < b.local_ref ? -1 : 1)
  return current
}

function sameResourceCluster(resourceRef, associations) {
  const cluster = new Set([resourceRef])
  for (const association of associations) {
    if (association.association_type !== 'same_resource' || association.status !== 'admitted') continue
    if (association.left_ref === resourceRef) cluster.add(association.right_ref)
    if (association.right_ref === resourceRef) cluster.add(association.left_ref)
  }
  return cluster
}

function mappingAllows(mapping, observation, resourceRef, associations) {
  if (!mapping || mapping.status !== 'admitted') return false
  if (mapping.property !== observation.property) return false
  const cluster = sameResourceCluster(resourceRef, associations)
  if (!cluster.has(observation.resource_local_ref)) return false
  const instances = new Set(mapping.comparable_source_instances)
  return instances.has(observation.source_instance_id)
}

function freshnessOf(observation, rule, instant) {
  const source = sourceInstant(observation.document.source_observed_at)
  if (source.kind === 'unknown') return 'unknown_source_date'
  const age = epochMs(instant) - source.epoch_ms
  if (!rule || rule.status !== 'admitted') return 'stale'
  if (age > rule.freshness_max_age_ms) return 'stale'
  return 'current'
}

function coverageOf(rows) {
  const kinds = new Set(rows.map(row => row.document.result.kind))
  if (kinds.size === 0) return 'empty'
  if (kinds.size > 1) return 'mixed'
  return [...kinds][0] === 'measured' ? 'measured' : [...kinds][0]
}

function uniqueFreshness(rows, rule, instant) {
  const set = new Set(rows.map(row => freshnessOf(row, rule, instant)))
  if (set.size === 0) return 'not_applicable'
  if (set.size > 1) return 'mixed'
  return [...set][0]
}

export function qualifyAt({
  observations,
  associations = [],
  mapping = null,
  rule = null,
  instant,
  resource_ref,
  property,
  complete = true,
}) {
  const normalizedInstant = normalizeUtcDateTime(instant)
  const current = currentRows(observations).filter(row => row.property === property)
  const limits = []
  if (current.some(row => row.divergent_corrections)) {
    limits.push({ code: 'DIVERGENT_CORRECTIONS' })
  }
  const mappingOk = mapping !== null && mapping.contract !== 'dubsar.operational-context.mapping/2'
    && mapping.status === 'admitted' && mapping.property === property
  const ruleOk = rule !== null && rule.status === 'admitted'
  if (!mappingOk) limits.push({ code: 'MAPPING_UNAVAILABLE' })
  if (!ruleOk) limits.push({ code: 'RULE_UNAVAILABLE' })

  const comparable = []
  const notComparable = []
  for (const row of current) {
    const period = row.document.scope.period
    const queryPeriod = observations.find(item => item.resource_local_ref === resource_ref)?.document?.scope?.period
    const overlap = queryPeriod ? periodsOverlap(period, queryPeriod) : true
    if (mappingOk && overlap && mappingAllows(mapping, row, resource_ref, associations)) comparable.push(row)
    else notComparable.push(row)
  }

  const local = current.filter(row => row.resource_local_ref === resource_ref)
  const values = [...comparable, ...local.filter(row => !comparable.includes(row))]
    .filter(row => row.document.result.kind === 'measured')
    .map(row => ({
      observation_ref: row.local_ref,
      producer_id: row.producer_id,
      result_kind: row.document.result.kind,
      value: row.document.result.value,
    }))
  const distinct = new Set(comparable
    .filter(row => row.document.result.kind === 'measured')
    .map(row => measuredCanonical(row.document.result)))

  let comparability = 'not_applicable'
  let agreement = 'none'
  if (current.some(row => row.divergent_corrections)) {
    agreement = 'divergent_corrections'
    comparability = mappingOk ? 'comparable' : 'not_applicable'
  } else if (comparable.length >= 2 && mappingOk) {
    comparability = 'comparable'
    if (distinct.size > 1) agreement = 'conflict'
    else if (distinct.size === 1) agreement = comparable.length === 1 ? 'single' : 'agree'
  } else if (notComparable.length > 0 && comparable.length > 0) {
    comparability = 'not_comparable'
    agreement = 'coexistence_not_comparable'
  } else if (comparable.length === 1 || local.length === 1) {
    comparability = mappingOk && comparable.length === 1 ? 'comparable' : 'not_applicable'
    agreement = 'single'
  } else if (notComparable.length >= 2) {
    comparability = 'not_comparable'
    agreement = 'coexistence_not_comparable'
  }

  const support = [...current].map(row => row.local_ref).sort()
  const document = {
    contract: OC_CONTRACTS.qualification,
    agreement,
    admissibility: mappingOk && ruleOk ? 'admissible' : 'limited',
    comparability,
    coverage: coverageOf(local.length > 0 ? local : current),
    freshness: uniqueFreshness(local.length > 0 ? local : current, rule, normalizedInstant),
    instant: normalizedInstant,
    limits,
    mapping_ref: mapping?.mapping_ref,
    mapping_version: mapping?.version,
    property,
    resource_ref,
    rule_ref: rule?.rule_ref,
    rule_version: rule?.version,
    status: 'current',
    support_refs: support,
    values,
  }
  if (document.mapping_ref === undefined) delete document.mapping_ref
  if (document.mapping_version === undefined) delete document.mapping_version
  if (document.rule_ref === undefined) delete document.rule_ref
  if (document.rule_version === undefined) delete document.rule_version
  if (!complete) {
    // A missing correction or retraction can change every apparent current
    // value. A bounded prefix is evidence of a partial collection, not a head.
    document.status = 'pending_recalculation'
    document.admissibility = 'limited'
    document.agreement = 'none'
    document.comparability = 'not_applicable'
    document.coverage = 'collection_partial'
    document.freshness = 'not_applicable'
    document.support_refs = []
    document.values = []
    document.limits.push({ code: 'SUPPORT_WINDOW_TRUNCATED' })
  }
  return { document, fingerprint: qualificationFingerprint(document) }
}

export function semanticQualification(document) {
  return {
    agreement: document.agreement,
    admissibility: document.admissibility,
    comparability: document.comparability,
    coverage: document.coverage,
    freshness: document.freshness,
    instant: document.instant,
    limits: document.limits,
    mapping_ref: document.mapping_ref ?? null,
    mapping_version: document.mapping_version ?? null,
    property: document.property,
    resource_ref: document.resource_ref,
    rule_ref: document.rule_ref ?? null,
    rule_version: document.rule_version ?? null,
    support_refs: document.support_refs,
    values: document.values ?? [],
  }
}
