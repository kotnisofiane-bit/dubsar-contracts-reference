import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import { SchemaRegistry } from '../schema-validator.mjs'

// Static local schemas only. Validation performs no port call, clock read or write.
export const judgmentSchemas = new SchemaRegistry(fileURLToPath(new URL('../../schemas/judgment/v1/', import.meta.url)))
export const JUDGMENT_MOVES = Object.freeze(['consult', 'conclude', 'clarify', 'revise', 'stop'])
export const JUDGMENT_STATUSES = Object.freeze(['supported', 'not_supported', 'undetermined', 'conflicted'])
export const JUDGMENT_BOUNDS = Object.freeze({ input_bytes: 32768, input_chars: 9000, memory_relations: 20, output_bytes: 8192, trajectory_bytes: 131072 })
const domains = Object.freeze({ input: 'dubsar.judgment.input.v1', output: 'dubsar.judgment.output.v1', trajectory: 'dubsar.judgment.trajectory.v1' })
const unique = values => [...new Set(values)]
const index = (values, key) => new Map(values.map(value => [value[key], value]))
const same = (a, b) => canonicalJson(a) === canonicalJson(b)

export function judgmentBytesDigest(utf8) {
  if (typeof utf8 !== 'string') throw new TypeError('UTF-8 text required')
  if (Buffer.from(utf8, 'utf8').toString('utf8') !== utf8) throw new TypeError('Lossless UTF-8 required')
  return `sha256:${createHash('sha256').update(utf8, 'utf8').digest('hex')}`
}

// Identity only: does not authenticate a source or select truth.
export function judgmentCanonicalDigest(kind, value) {
  if (!Object.hasOwn(domains, kind)) throw new TypeError('Unknown judgment contract')
  return domainSeparatedHash(domains[kind], value)
}

function shape(kind, value) {
  try {
    const encoded = canonicalJson(value)
    const maximum = kind === 'input' ? JUDGMENT_BOUNDS.input_bytes : kind === 'output' ? JUDGMENT_BOUNDS.output_bytes : JUDGMENT_BOUNDS.trajectory_bytes
    if (Buffer.byteLength(encoded, 'utf8') > maximum) return ['MAX_BYTES']
    if (kind === 'input' && [...encoded].length > JUDGMENT_BOUNDS.input_chars) return ['MAX_CHARS']
    return judgmentSchemas.validate(`${kind}.schema.json`, value).length ? [`${kind.toUpperCase()}_SCHEMA`] : []
  } catch { return ['INVALID_JSON_VALUE'] }
}

function referenceErrors(reference) {
  return (reference.digest === null) !== (reference.digest_scheme === null) ? ['DIGEST_SCHEME_REQUIRED'] : []
}

function elementErrors(element, origins, limits) {
  const errors = referenceErrors(element.reference)
  // A supported codec is not interchangeable with another source's codec,
  // even when both serialize to 64 bare hex characters.
  const nativeScheme = { automation_result: 'dubsar.automation.run-event.v1',
    memory_relation: 'memory-v2-content-digest', memory_history: 'memory-v2-content-digest',
    oc_observation: 'dubsar.oc.observation.v1', evidence: 'sha256-bytes' }[element.kind]
  if (element.reference.digest !== null && nativeScheme && element.reference.digest_scheme !== nativeScheme) errors.push('SOURCE_DIGEST_SCHEME_MISMATCH')
  if (element.origin_ids.some(id => !origins.has(id))) errors.push('UNKNOWN_ORIGIN')
  if (element.limit_ids.some(id => !limits.has(id))) errors.push('UNKNOWN_LIMIT')
  const hasLimit = code => element.limit_ids.some(id => limits.get(id)?.code === code)
  if (element.provenance_complete && (element.origin_ids.length === 0 || element.origin_ids.some(id => origins.get(id)?.reference.digest === null))) errors.push('PROVENANCE_INCOMPLETE')
  if (!element.provenance_complete && !hasLimit('PROVENANCE_INCOMPLETE')) errors.push('MISSING_PROVENANCE_LIMIT')
  if (element.content_verification === 'matched') {
    if (element.availability !== 'available' || element.text === null || element.reference.digest === null) errors.push('CONTENT_NOT_VERIFIED')
  } else {
    if (element.text !== null) errors.push('UNVERIFIED_CONTENT')
    if (element.content_verification === 'failed' && !hasLimit('VERIFICATION_FAILED')) errors.push('MISSING_VERIFICATION_LIMIT')
    if (element.availability === 'available' && element.content_verification === 'not_checked' && !hasLimit('REFERENCE_NOT_READ')) errors.push('MISSING_REFERENCE_LIMIT')
  }
  if (element.availability === 'missing' && !hasLimit('SOURCE_MISSING')) errors.push('MISSING_SOURCE_LIMIT')
  if (element.availability === 'unavailable' && !hasLimit('SOURCE_UNAVAILABLE')) errors.push('MISSING_SOURCE_LIMIT')
  if (element.freshness === 'stale' && !hasLimit('STALE')) errors.push('MISSING_FRESHNESS_LIMIT')
  if (element.freshness === 'unknown' && ['memory', 'operational_context'].includes(element.source) && !hasLimit('FRESHNESS_UNKNOWN')) errors.push('MISSING_FRESHNESS_LIMIT')
  if (element.temporal_scope === 'historical' && !hasLimit('HISTORICAL_ONLY')) errors.push('MISSING_HISTORICAL_LIMIT')
  const sourceForKind = { mission: 'my_work', accepted_context: 'my_work', automation_result: 'my_work', memory_relation: 'memory', memory_history: 'memory', oc_state: 'operational_context', oc_observation: 'operational_context', evidence: 'evidence' }
  if (sourceForKind[element.kind] !== element.source) errors.push('SOURCE_KIND_MISMATCH')
  if (element.source === 'my_work' && element.freshness !== 'unknown') errors.push('MY_WORK_FRESHNESS_UNSUPPORTED')
  if (element.kind === 'automation_result') {
    if (element.facts.automation === null || element.facts.oc !== null || element.temporal_scope !== 'historical') errors.push('AUTOMATION_SEMANTICS')
    if (!hasLimit('MISSION_CRITERIA_NOT_EVALUATED')) errors.push('MISSING_MISSION_LIMIT')
    if (element.facts.automation?.result === 'documented' && element.content_verification !== 'matched') errors.push('DOCUMENTATION_NOT_VERIFIED')
    if (element.facts.automation?.result === 'documented' && element.facts.automation.event_id === null) errors.push('EVENT_ID_REQUIRED')
    if (element.facts.automation?.result === 'missing' && element.facts.automation.event_id !== null) errors.push('MISSING_EVENT_HAS_ID')
    if (element.facts.automation?.result !== 'documented' && !hasLimit('RESULT_NOT_DOCUMENTED')) errors.push('MISSING_RESULT_LIMIT')
  } else if (element.facts.automation !== null) errors.push('FACT_KIND_MISMATCH')
  if (['oc_state', 'oc_observation'].includes(element.kind)) {
    if (element.facts.oc === null) errors.push('OC_FACTS_REQUIRED')
    if (element.kind === 'oc_observation' && element.temporal_scope !== 'historical') errors.push('HISTORY_NOT_CURRENT')
    if (element.kind === 'oc_state' && element.facts.oc?.value !== null && (element.freshness !== 'current' || element.temporal_scope !== 'current' || !element.facts.oc?.eligible || element.content_verification !== 'matched')) errors.push('OC_STATE_VALUE_NOT_QUALIFIED')
    if (element.temporal_scope === 'current' && (element.kind !== 'oc_state' || element.freshness !== 'current' || !element.facts.oc?.eligible || element.content_verification !== 'matched')) errors.push('CURRENT_STATE_NOT_QUALIFIED')
  } else if (element.facts.oc !== null) errors.push('FACT_KIND_MISMATCH')
  return errors
}

export function validateJudgmentInput(value) {
  const errors = shape('input', value)
  if (errors.length) return errors
  const { elements, origins, limits, omissions } = value.context
  for (const [items, key] of [[elements, 'element_id'], [origins, 'origin_id'], [limits, 'limit_id'], [value.claims, 'claim_id'], [value.missing_information, 'missing_id'], [value.consult_catalog.entries, 'consult_id']]) {
    if (new Set(items.map(item => item[key])).size !== items.length) errors.push('DUPLICATE_ID')
  }
  const elementMap = index(elements, 'element_id'), originMap = index(origins, 'origin_id'), limitMap = index(limits, 'limit_id')
  for (const origin of origins) errors.push(...referenceErrors(origin.reference))
  if (new Set(origins.map(origin => origin.reference.ref)).size !== origins.length) errors.push('ORIGIN_ALIAS')
  for (const element of elements) errors.push(...elementErrors(element, originMap, limitMap))
  // Repeated references to one exact record retain one native digest binding.
  const references = [...origins.map(origin => origin.reference), ...elements.map(element => element.reference)]
  const byRef = new Map()
  for (const reference of references) {
    const prior = byRef.get(reference.ref)
    if (prior && !same(prior, reference)) errors.push('SOURCE_REFERENCE_DIGEST_MISMATCH')
    byRef.set(reference.ref, reference)
  }
  if (elements.filter(element => element.kind === 'memory_relation').length > JUDGMENT_BOUNDS.memory_relations) errors.push('MEMORY_BOUND')
  for (const claim of value.claims) {
    if (claim.candidate_element_ids.some(id => !elementMap.has(id))) errors.push('UNKNOWN_ELEMENT')
    if (claim.required_limit_ids.some(id => !limitMap.has(id))) errors.push('UNKNOWN_LIMIT')
    if (claim.kind === 'current_state' && !claim.requirements.requires_current) errors.push('CURRENT_REQUIREMENT_REQUIRED')
    if (!claim.requirements.requires_verified_content) errors.push('VERIFIED_CONTENT_REQUIRED')
  }
  const seenReads = new Set()
  for (const entry of value.consult_catalog.entries) {
    const target = elementMap.get(entry.target_element_id)
    if (!target) errors.push('UNKNOWN_ELEMENT')
    else {
      const kind = { mission: 'mission', memory_relation: 'memory_relation', memory_history: 'memory_history', oc_observation: 'oc_observation', automation_e5: 'automation_result', evidence_content: 'evidence' }[entry.read_kind]
      if (target.kind !== kind) errors.push('CONSULT_KIND_MISMATCH')
      const readKey = `${entry.read_kind}|${target.reference.ref}`
      if (seenReads.has(readKey)) errors.push('DUPLICATE_CONSULT_TARGET')
      seenReads.add(readKey)
      if (entry.state === 'available' && target.content_verification === 'matched') errors.push('CONSULT_ALREADY_READ')
    }
    for (const estimate of [entry.cost_microusd, entry.latency_ms]) {
      if ((estimate.value === null) !== (estimate.method === 'unknown') || (estimate.method === 'unknown') !== (estimate.basis === 'unknown')) errors.push('ESTIMATE_METHOD_MISMATCH')
    }
  }
  const omitted = omissions.elements + omissions.claims + omissions.consults
  if (omissions.truncated !== (omitted > 0)) errors.push('TRUNCATION_COUNT_MISMATCH')
  if (omitted > 0 && !limits.some(limit => ['OMITTED', 'TRUNCATED'].includes(limit.code) && limit.mandatory)) errors.push('MISSING_OMISSION_LIMIT')
  return unique(errors)
}

// Conservative connected groups of declared upstream origins, not semantic independence.
export function independentOriginCount(elements) {
  const groups = []
  for (const element of elements) {
    if (!element.provenance_complete || !element.origin_ids.length) continue
    let group = new Set(element.origin_ids)
    for (let i = groups.length - 1; i >= 0; i--) {
      if ([...group].some(id => groups[i].has(id))) {
        group = new Set([...group, ...groups[i]])
        groups.splice(i, 1)
      }
    }
    groups.push(group)
  }
  return groups.length
}

export function validateJudgmentOutput(input, value) {
  if (validateJudgmentInput(input).length) return ['INPUT_INVALID']
  const errors = shape('output', value)
  if (errors.length) return errors
  const payload = value.payload
  const elements = index(input.context.elements, 'element_id'), limits = index(input.context.limits, 'limit_id'), claims = index(input.claims, 'claim_id')
  if (payload.limit_ids.some(id => !limits.has(id))) errors.push('UNKNOWN_LIMIT')
  const required = new Set(input.context.limits.filter(limit => limit.mandatory).map(limit => limit.limit_id))
  if (value.move === 'consult') {
    const entry = input.consult_catalog.entries.find(item => item.consult_id === payload.consult_id)
    for (const id of elements.get(entry?.target_element_id)?.limit_ids ?? []) required.add(id)
  }
  for (const id of payload.element_ids ?? []) {
    const element = elements.get(id)
    if (!element) errors.push('UNKNOWN_ELEMENT')
    else for (const limit of element.limit_ids) required.add(limit)
  }
  for (const id of payload.claim_ids ?? []) {
    const claim = claims.get(id)
    if (!claim) errors.push('UNKNOWN_CLAIM')
    else for (const limit of claim.required_limit_ids) required.add(limit)
  }
  if ([...required].some(id => !payload.limit_ids.includes(id))) errors.push('LIMIT_DROPPED')
  if (value.move === 'consult') {
    const entry = input.consult_catalog.entries.find(item => item.consult_id === payload.consult_id)
    if (!entry) errors.push('CONSULT_NOT_IN_CATALOG')
    else {
      if (entry.state === 'already_consulted') errors.push('CONSULT_REPEATED')
      if (entry.state === 'unavailable') errors.push('CONSULT_UNAVAILABLE')
      for (const [budget, estimate] of [[input.budget.cost_remaining_microusd, entry.cost_microusd], [input.budget.latency_remaining_ms, entry.latency_ms]]) {
        if (budget !== null && (estimate.value === null || estimate.value > budget)) errors.push('CONSULT_BUDGET_UNPROVABLE')
      }
    }
    if (input.budget.consults_remaining === 0 || input.budget.tokens_remaining === 0) errors.push('BUDGET_EXHAUSTED')
  }
  if (value.move === 'clarify') {
    const missing = index(input.missing_information, 'missing_id')
    if (payload.missing_ids.some(id => !missing.has(id))) errors.push('UNKNOWN_MISSING_INFORMATION')
  }
  if (['conclude', 'revise'].includes(value.move)) {
    const used = (payload.element_ids ?? []).map(id => elements.get(id)).filter(Boolean)
    if (payload.status === 'supported' || payload.status === 'not_supported') {
      if (!used.length) errors.push('UNJUSTIFIED_CONCLUSION')
      if (input.missing_information.some(item => item.blocking)) errors.push('CLARIFICATION_REQUIRED')
      for (const id of payload.claim_ids) {
        const claim = claims.get(id)
        if (!claim) continue
        const relevant = used.filter(element => claim.candidate_element_ids.includes(element.element_id))
        if (!relevant.length || used.some(element => !claim.candidate_element_ids.includes(element.element_id))) errors.push('CLAIM_SUPPORT_MISMATCH')
        if (relevant.some(element => element.availability !== 'available' || element.content_verification !== 'matched')) errors.push('CONTENT_NOT_VERIFIED')
        if (claim.requirements.requires_current && relevant.some(element => element.freshness !== 'current' || element.temporal_scope !== 'current' || !element.facts.oc?.eligible)) errors.push('CURRENT_STATE_NOT_QUALIFIED')
        if (independentOriginCount(relevant) < claim.requirements.min_independent_origins) errors.push('INSUFFICIENT_INDEPENDENT_ORIGINS')
        if (claim.kind === 'automation_result' && relevant.some(element => element.facts.automation?.result !== 'documented')) errors.push('AUTOMATION_RESULT_NOT_DOCUMENTED')
        if (claim.kind === 'mission_criteria') errors.push('MISSION_CRITERIA_NOT_EVALUATED')
      }
    } else {
      for (const id of payload.claim_ids) {
        const claim = claims.get(id)
        if (claim && used.some(element => !claim.candidate_element_ids.includes(element.element_id))) errors.push('CLAIM_SUPPORT_MISMATCH')
      }
    }
    if (payload.status === 'conflicted' && used.filter(element => element.content_verification === 'matched' && element.availability === 'available').length < 2) errors.push('CONFLICT_NOT_GROUNDED')
  }
  if (value.move === 'revise') {
    const previous = input.previous_judgment
    if (previous === null || previous.response_ref !== payload.previous_response_ref) errors.push('PREVIOUS_RESPONSE_MISMATCH')
    else {
      if (previous.status === payload.status) errors.push('JUDGMENT_UNCHANGED')
      if (!same([...previous.claim_ids].sort(), [...payload.claim_ids].sort())) errors.push('REVISION_CLAIM_CHANGED')
      if (payload.new_element_ids.some(id => previous.element_ids.includes(id) || !payload.element_ids.includes(id) || elements.get(id)?.content_verification !== 'matched')) errors.push('REVISION_ELEMENT_NOT_NEW')
      if (payload.new_element_ids.some(id => previous.element_ids.some(oldId => elements.has(oldId) && same(elements.get(id)?.reference ?? null, elements.get(oldId).reference)))) errors.push('REVISION_ELEMENT_NOT_NEW')
      const changes = { strengthened: ['undetermined:supported', 'not_supported:supported'], weakened: ['supported:undetermined', 'not_supported:undetermined'], contradiction_identified: ['supported:conflicted', 'not_supported:conflicted', 'undetermined:conflicted'], conflict_resolved: ['conflicted:supported', 'conflicted:not_supported', 'conflicted:undetermined'], withdrawn: ['supported:not_supported'] }
      if (!changes[payload.change].includes(`${previous.status}:${payload.status}`)) errors.push('REVISION_CHANGE_MISMATCH')
    }
  }
  if (value.move === 'stop') {
    if (payload.cause === 'budget_exhausted' && input.budget.consults_remaining > 0 && input.budget.tokens_remaining > 0 && input.budget.cost_remaining_microusd !== 0 && input.budget.latency_remaining_ms !== 0) errors.push('STOP_CAUSE_MISMATCH')
    if (payload.cause === 'source_absent' && input.context.elements.some(element => element.availability === 'available')) errors.push('STOP_CAUSE_MISMATCH')
    if (payload.cause === 'clarification_required' && !input.missing_information.some(item => item.blocking)) errors.push('STOP_CAUSE_MISMATCH')
    if (payload.cause === 'limit_reached' && !payload.limit_ids.length) errors.push('STOP_CAUSE_MISMATCH')
  }
  return unique(errors)
}

export function validateJudgmentTrajectory(value) {
  const errors = shape('trajectory', value)
  if (errors.length) return errors
  let input, output
  try { input = parseJudgmentJson(value.input.sent_utf8) } catch { return ['SENT_INPUT_JSON'] }
  if (validateJudgmentInput(input).length) return ['SENT_INPUT_INVALID']
  // One unambiguous serialization, including Unicode; no excluded self-digest field.
  if (canonicalJson(input) !== value.input.sent_utf8) errors.push('SENT_INPUT_NOT_CANONICAL')
  try {
    if (judgmentBytesDigest(value.input.sent_utf8) !== value.input.sent_digest) errors.push('SENT_INPUT_DIGEST_MISMATCH')
    if (judgmentBytesDigest(value.response.raw_utf8) !== value.response.raw_digest) errors.push('RAW_RESPONSE_DIGEST_MISMATCH')
  } catch { errors.push('INVALID_UTF8') }
  if (judgmentCanonicalDigest('input', input) !== value.input.canonical_digest) errors.push('CANONICAL_DIGEST_MISMATCH')
  let rejection
  try { output = parseJudgmentJson(value.response.raw_utf8); rejection = validateJudgmentOutput(input, output) } catch { rejection = ['OUTPUT_JSON'] }
  const validation = value.response.validation
  if (rejection.length) {
    if (validation.status !== 'rejected' || validation.output !== null || !same(validation.error_codes, rejection)) errors.push('REJECTION_MISMATCH')
  } else if (validation.status !== 'validated' || validation.error_codes.length || !same(output, validation.output)) errors.push('VALIDATED_OUTPUT_MISMATCH')
  const origins = index(value.origins, 'origin_id'), limits = index(value.limits, 'limit_id')
  if (origins.size !== value.origins.length || limits.size !== value.limits.length) errors.push('DUPLICATE_ID')
  for (const origin of input.context.origins) if (!same(origins.get(origin.origin_id) ?? null, origin)) errors.push('TRACE_ORIGIN_CHANGED')
  for (const limit of input.context.limits) if (!same(limits.get(limit.limit_id) ?? null, limit)) errors.push('TRACE_LIMIT_CHANGED')
  for (const origin of value.origins) errors.push(...referenceErrors(origin.reference))
  for (const consultation of value.consultations) {
    if (output?.move !== 'consult' || output.payload?.consult_id !== consultation.consult_id) errors.push('CONSULT_NOT_REQUESTED')
    const entry = input.consult_catalog.entries.find(item => item.consult_id === consultation.consult_id)
    if (consultation.limit_ids.some(id => !limits.has(id))) errors.push('UNKNOWN_LIMIT')
    if (rejection.length || !entry) {
      if (consultation.status !== 'denied' || consultation.result !== null) errors.push('REJECTED_CONSULT_READ')
      continue
    }
    if (consultation.status === 'read') {
      if (consultation.result === null) errors.push('READ_RESULT_REQUIRED')
      else {
        const target = input.context.elements.find(element => element.element_id === entry.target_element_id)
        const result = consultation.result
        if (result.element_id !== target.element_id || result.reference.ref !== target.reference.ref || result.kind !== target.kind || result.source !== target.source) errors.push('CONSULT_SUBSTITUTION')
        if (result.content_verification === 'matched' && target.reference.digest !== null && !same(result.reference, target.reference)) errors.push('CONSULT_DIGEST_CHANGED')
        errors.push(...elementErrors(result, origins, limits))
        if (result.limit_ids.some(id => !consultation.limit_ids.includes(id))) errors.push('LIMIT_DROPPED')
      }
    } else if (consultation.result !== null) errors.push('UNREAD_RESULT')
  }
  const { tokens, latency_ms: latency, cost } = value.usage
  if ((tokens.method === 'not_measured') !== (tokens.input === null && tokens.output === null) || (tokens.method !== 'not_measured' && (tokens.input === null || tokens.output === null))) errors.push('TOKENS_METHOD_MISMATCH')
  if ((latency.method === 'not_measured') !== (latency.value === null)) errors.push('LATENCY_METHOD_MISMATCH')
  if ((cost.method === 'not_measured') !== (cost.microusd === null) || (cost.method === 'token_price_estimate' && cost.pricing_ref === null)) errors.push('COST_METHOD_MISMATCH')
  errors.push(...referenceErrors(value.versions.prompt))
  if (value.versions.prompt.digest === null) errors.push('PROMPT_DIGEST_REQUIRED')
  if (value.human_feedback !== null) errors.push(...referenceErrors(value.human_feedback.reference))
  return unique(errors)
}

// Offline conformance only: validates a supplied chain, never fetches or appends it.
export function validateJudgmentTrajectoryChain(turns) {
  if (!Array.isArray(turns) || !turns.length || turns.length > 64) return ['TRAJECTORY_CHAIN_BOUND']
  const errors = [], turnIds = new Set(), responseIds = new Set()
  for (let i = 0; i < turns.length; i++) {
    const turn = turns[i], turnErrors = validateJudgmentTrajectory(turn)
    if (turnErrors.length) return unique(turnErrors)
    if (turnIds.has(turn.turn_id) || responseIds.has(turn.response.response_ref)) errors.push('DUPLICATE_TURN')
    turnIds.add(turn.turn_id); responseIds.add(turn.response.response_ref)
    if (i === 0) {
      if (turn.previous_turn_digest !== null || parseJudgmentJson(turn.input.sent_utf8).previous_judgment !== null) errors.push('CHAIN_START_NOT_ASSERTED')
      continue
    }
    const prior = turns[i - 1]
    for (const key of ['trajectory_id', 'request_id', 'session_ref']) if (turn[key] !== prior[key]) errors.push('CHAIN_BINDING_CHANGED')
    if (turn.previous_turn_digest !== judgmentCanonicalDigest('trajectory', prior)) errors.push('PREVIOUS_TURN_DIGEST_MISMATCH')
    const input = parseJudgmentJson(turn.input.sent_utf8), previousInput = parseJudgmentJson(prior.input.sent_utf8)
    if (!same(input.scope, previousInput.scope) || input.question !== previousInput.question) errors.push('JUDGMENT_SCOPE_CHANGED')
    const output = turn.response.validation.output, previous = prior.response.validation.output
    if (input.previous_judgment !== null) {
      const expected = previous && ['conclude', 'revise'].includes(previous.move) ? {
        response_ref: prior.response.response_ref, status: previous.payload.status,
        claim_ids: previous.payload.claim_ids, element_ids: previous.payload.element_ids,
      } : null
      if (!same(input.previous_judgment, expected)) errors.push('PREVIOUS_JUDGMENT_MISMATCH')
    }
    if (output?.move === 'revise') {
      const oldClaims = index(previousInput.claims, 'claim_id'), newClaims = index(input.claims, 'claim_id')
      const meaning = claim => claim && ({ claim_id: claim.claim_id, kind: claim.kind, statement: claim.statement, requirements: claim.requirements })
      for (const id of output.payload.claim_ids) if (!same(meaning(oldClaims.get(id)) ?? null, meaning(newClaims.get(id)) ?? null)) errors.push('REVISION_CLAIM_CHANGED')
      const oldElements = index(previousInput.context.elements, 'element_id'), newElements = index(input.context.elements, 'element_id')
      for (const id of output.payload.new_element_ids) if ((previous?.payload.element_ids ?? []).some(oldId => oldElements.has(oldId) && same(newElements.get(id)?.reference ?? null, oldElements.get(oldId).reference))) errors.push('REVISION_ELEMENT_NOT_NEW')
    }
  }
  return unique(errors)
}

// Pure strict JSON transport parser. No JSON5, executable content or duplicate keys.
export function parseJudgmentJson(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 32768) throw new TypeError('Bounded JSON text required')
  let cursor = 0
  const space = () => { while (/[\x20\t\r\n]/u.test(text[cursor] ?? '') && cursor < text.length) cursor++ }
  function string() {
    const start = cursor++
    while (cursor < text.length) {
      if (text[cursor] === '\\') { cursor += 2; continue }
      if (text[cursor++] === '"') return JSON.parse(text.slice(start, cursor))
    }
    throw new TypeError('Unterminated JSON string')
  }
  function walk(depth) {
    if (depth > 64) throw new TypeError('JSON depth exceeded')
    space()
    if (text[cursor] === '"') { string(); return }
    if (text[cursor] === '{' || text[cursor] === '[') {
      const object = text[cursor++] === '{', close = object ? '}' : ']', keys = new Set()
      space()
      if (text[cursor] === close) { cursor++; return }
      while (cursor < text.length) {
        if (object) {
          space()
          if (text[cursor] !== '"') throw new TypeError('JSON key required')
          const key = string()
          if (keys.has(key)) throw new TypeError('Duplicate JSON key')
          keys.add(key); space()
          if (text[cursor++] !== ':') throw new TypeError('JSON colon required')
        }
        walk(depth + 1); space()
        if (text[cursor] === close) { cursor++; return }
        if (text[cursor++] !== ',') throw new TypeError('JSON comma required')
      }
      throw new TypeError('Unterminated JSON container')
    }
    const start = cursor
    while (cursor < text.length && !/[\x20\t\r\n,\]}]/u.test(text[cursor])) cursor++
    if (cursor === start) throw new TypeError('JSON value required')
  }
  walk(0); space()
  if (cursor !== text.length) throw new TypeError('Trailing JSON content')
  return JSON.parse(text)
}
