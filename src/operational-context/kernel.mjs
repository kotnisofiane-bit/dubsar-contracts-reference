import { randomUUID } from 'node:crypto'
import { OC_BOUNDS, OC_CONTRACTS } from './bounds.mjs'
import { ocError } from './errors.mjs'
import { requireAuthority, revalidateAuthority } from './authority.mjs'
import {
  assertUtf8Bound,
  validateClosed,
  observationFingerprint,
  qualificationFingerprint,
  validateAssociation,
  validateMapping,
  validateStateBinding,
  validateObservation,
  validateResource,
  validateRule,
  validateTrust,
  validateViewRequest,
} from './contracts.mjs'
import { aggregateKey, assertSameScope, pairFingerprint, resourceIdentity } from './identity.mjs'
import { PostgresContextStore } from './postgres-store.mjs'
import { qualifyAt, semanticQualification } from './qualify.mjs'
import { nowIso, normalizeUtcDateTime } from './time.mjs'
import { SimulatedArtifactStoreReader } from './artifact-reader.mjs'
import { projectState } from './state-projection.mjs'
import { appendStatePolicy, lockStatePolicy, statePolicyAt, supersededStateSupports } from './state-policy-store.mjs'

function wrapOutcome(_code, error) {
  if ([
    'OC_UNAUTHORIZED', 'OC_AUTHORITY_MISSING', 'OC_REFUSED', 'OC_CONTRACT_INVALID',
    'OC_CONTRACT_UNKNOWN', 'OC_BOUND_EXCEEDED', 'OC_INJECTION_REFUSED',
  ].includes(error?.code)) {
    return { contract: OC_CONTRACTS.ingestResult, outcome: 'rejected', code: error.code, message: error.message }
  }
  if (error?.code === 'OC_AUTHORITY_UNAVAILABLE' || error?.code === 'OC_UNAVAILABLE') {
    return { contract: OC_CONTRACTS.ingestResult, outcome: 'unavailable', code: error.code }
  }
  if (error?.code === 'OC_INTEGRITY_CONFLICT') {
    return { contract: OC_CONTRACTS.ingestResult, outcome: 'integrity_conflict', code: error.code }
  }
  throw error
}

export class OperationalContextKernel {
  constructor({ pool, authority, clock, artifactReader, faults } = {}) {
    if (authority === undefined || authority === null) {
      throw ocError('OC_AUTHORITY_MISSING', 'authorization port is required')
    }
    this.store = new PostgresContextStore(pool)
    this.authority = authority
    this.clock = clock ?? { now: () => new Date().toISOString() }
    this.artifactReader = artifactReader ?? new SimulatedArtifactStoreReader()
    this.faults = faults ?? {}
  }

  async #auth(action, trust, extra = {}) {
    validateTrust(trust)
    return requireAuthority(this.authority, { action, trust, ...extra })
  }

  async registerResource(trust, resource) {
    validateTrust(trust)
    const resolved = validateResource(resource)
    assertSameScope(trust, resolved.identity)
    await this.#auth('register_resource', trust, { resource_local_ref: resolved.local_ref })
    return this.store.withTransaction(async client => {
      const stored = await this.store.upsertResource(client, resource, this.clock)
      return { local_ref: stored.local_ref, identity: stored.identity, fingerprint: stored.fingerprint }
    })
  }

  async resolveResource(trust, resource) {
    validateTrust(trust)
    const resolved = validateResource(resource)
    assertSameScope(trust, resolved.identity)
    await this.#auth('read', trust, { resource_local_ref: resolved.local_ref })
    return this.store.withClient(async client => {
      const found = await this.store.findResourceByIdentity(client, resource)
      if (!found) throw ocError('OC_UNAVAILABLE', 'resource resolution failed')
      return { local_ref: found.local_ref, identity: found.identity, fingerprint: found.fingerprint }
    })
  }

  async ingestObservation(trust, payload) {
    try {
      return await this.#ingest(trust, payload, 'observe')
    } catch (error) {
      return wrapOutcome(error.code, error)
    }
  }

  async correctObservation(trust, payload) {
    try {
      if (!payload?.correction_of) throw ocError('OC_CONTRACT_INVALID', 'correction_of is required')
      return await this.#ingest(trust, payload, 'correct')
    } catch (error) {
      return wrapOutcome(error.code, error)
    }
  }

  async retractObservation(trust, payload) {
    try {
      if (!payload?.retraction_of) throw ocError('OC_CONTRACT_INVALID', 'retraction_of is required')
      return await this.#ingest(trust, payload, 'retract')
    } catch (error) {
      return wrapOutcome(error.code, error)
    }
  }

  async #ingest(trust, payload, action) {
    validateTrust(trust)
    const observation = validateObservation(payload)
    if (action === 'observe' && (observation.correction_of !== undefined || observation.retraction_of !== undefined)) {
      throw ocError('OC_CONTRACT_INVALID', 'observe cannot correct or retract an assertion')
    }
    assertSameScope(trust, observation.subject)
    const resolved = resourceIdentity(observation.subject)
    await this.#auth(action, trust, {
      resource_local_ref: resolved.local_ref,
      property: observation.property,
      producer_id: observation.provenance.producer_id,
    })
    if (observation.content_refs?.length) {
      for (const ref of observation.content_refs) await this.artifactReader.resolve(ref)
    }
    const fingerprint = observationFingerprint(observation)
    const receivedAt = nowIso(this.clock)
    const key = aggregateKey(resolved.local_ref, observation.property)

    const phase1 = await this.store.withTransaction(async client => {
      await this.store.lockDelivery(client, trust.tenant_id, trust.environment_id, observation.delivery_id)
      const existing = await this.store.getByDelivery(client, trust.tenant_id, trust.environment_id, observation.delivery_id)
      if (existing) {
        if (existing.fingerprint === fingerprint) {
          return { outcome: 'duplicate_identical', observation_ref: existing.local_ref, applied: false }
        }
        throw ocError('OC_INTEGRITY_CONFLICT', 'delivery identity reused with different content')
      }
      if (typeof observation.measurement_id === 'string') {
        const measured = await this.store.getByMeasurement(
          client, trust.tenant_id, trust.environment_id, observation.measurement_id,
        )
        if (measured) {
          if (measured.fingerprint === fingerprint) {
            return { outcome: 'duplicate_identical', observation_ref: measured.local_ref, applied: false }
          }
          throw ocError('OC_INTEGRITY_CONFLICT', 'measurement identity reused with different content')
        }
      }
      if (observation.contract === 'dubsar.operational-context.observation/2') {
        await lockStatePolicy(client, trust)
        const { binding, mapping, rule } = await statePolicyAt(client, trust, resolved.local_ref, observation.property, receivedAt)
        if (!binding || binding.status !== 'admitted' || mapping?.status !== 'admitted' || rule?.status !== 'admitted'
            || binding.producer_epoch !== observation.state_order.producer_epoch
            || binding.producer_id !== observation.provenance.producer_id
            || binding.source_instance_id !== observation.subject.source_instance_id
            || binding.mapping_ref !== observation.provenance.mapping_ref
            || binding.mapping_version !== observation.provenance.mapping_version
            || binding.rule_ref !== observation.rule_ref || binding.rule_version !== observation.rule_version) {
          throw ocError('OC_REFUSED', 'ordered snapshot lineage or policy is not admitted')
        }
      }
      const resource = await this.store.upsertResource(client, observation.subject, this.clock)
      if (action === 'correct' || action === 'retract') {
        await this.#assertAntecedent(client, observation, action, trust)
      }
      if (typeof this.faults.beforeCommit === 'function') await this.faults.beforeCommit()
      const inserted = await this.store.insertObservation(client, {
        observation, resource, fingerprint, receivedAt,
      })
      if (inserted.conflict) {
        const raced = await this.store.getByDelivery(client, trust.tenant_id, trust.environment_id, observation.delivery_id)
        if (raced && raced.fingerprint === fingerprint) {
          return { outcome: 'duplicate_identical', observation_ref: raced.local_ref, applied: false }
        }
        if (typeof observation.measurement_id === 'string') {
          const measured = await this.store.getByMeasurement(
            client, trust.tenant_id, trust.environment_id, observation.measurement_id,
          )
          if (measured && measured.fingerprint === fingerprint) {
            return { outcome: 'duplicate_identical', observation_ref: measured.local_ref, applied: false }
          }
        }
        throw ocError('OC_INTEGRITY_CONFLICT', 'delivery or measurement identity conflict')
      }
      const aggregate = await this.store.invalidateAggregate(client, trust.tenant_id, trust.environment_id, key)
      return {
        outcome: 'applied',
        applied: true,
        observation_ref: inserted.local_ref,
        aggregate_version: Number(aggregate.version),
        qualification_status: 'pending_recalculation',
        resource_local_ref: resource.local_ref,
        property: observation.property,
        mapping_ref: observation.provenance.mapping_ref,
        mapping_version: observation.provenance.mapping_version,
        rule_ref: observation.rule_ref,
        rule_version: observation.rule_version,
      }
    })

    if (phase1.outcome !== 'applied') {
      if (typeof this.faults.afterCommitBeforeReply === 'function') await this.faults.afterCommitBeforeReply()
      return { contract: OC_CONTRACTS.ingestResult, ...phase1 }
    }

    if (typeof this.faults.beforeDerivativePublish === 'function') {
      await this.faults.beforeDerivativePublish()
    }

    try {
      await this.#publishLocalQualification(trust, phase1)
    } catch (error) {
      if (error?.code !== 'OC_STALE_DERIVATIVE') {
        /* observation remains; derivative stays pending */
      }
    }

    if (typeof this.faults.afterCommitBeforeReply === 'function') await this.faults.afterCommitBeforeReply()
    return { contract: OC_CONTRACTS.ingestResult, ...phase1 }
  }

  async #assertAntecedent(client, observation, action, trust) {
    const targetRef = action === 'correct' ? observation.correction_of : observation.retraction_of
    const antecedent = await this.store.getObservation(client, targetRef)
    if (!antecedent) throw ocError('OC_REFUSED', 'antecedent is not admitted')
    if (antecedent.tenant_id !== trust.tenant_id || antecedent.environment_id !== trust.environment_id) {
      throw ocError('OC_UNAUTHORIZED', 'antecedent is outside trust scope')
    }
    if (antecedent.resource_local_ref !== resourceIdentity(observation.subject).local_ref) {
      throw ocError('OC_REFUSED', 'antecedent resource mismatch')
    }
    if (antecedent.property !== observation.property) throw ocError('OC_REFUSED', 'antecedent property mismatch')
    if (antecedent.producer_id !== observation.provenance.producer_id && action === 'retract') {
      throw ocError('OC_UNAUTHORIZED', 'cannot retract another producer')
    }
    if (antecedent.producer_id !== observation.provenance.producer_id && action === 'correct') {
      throw ocError('OC_UNAUTHORIZED', 'cannot correct another producer')
    }
  }

  async #publishLocalQualification(trust, phase1) {
    const key = aggregateKey(phase1.resource_local_ref, phase1.property)
    await this.store.withTransaction(async client => {
      const fetched = await this.store.listObservationsForResources(
        client, trust.tenant_id, trust.environment_id, [phase1.resource_local_ref], [phase1.property],
        OC_BOUNDS.max_observations_examined + 1,
      )
      const observations = fetched.slice(0, OC_BOUNDS.max_observations_examined)
      const associations = await this.store.listAssociations(client, trust.tenant_id, trust.environment_id, [phase1.resource_local_ref])
      const mapping = phase1.mapping_ref
        ? await this.store.getMapping(client, trust, phase1.mapping_ref, phase1.mapping_version)
        : null
      const rule = phase1.rule_ref
        ? await this.store.getRule(client, trust, phase1.rule_ref, phase1.rule_version)
        : null
      const qualified = qualifyAt({
        observations,
        complete: fetched.length <= OC_BOUNDS.max_observations_examined,
        associations,
        mapping: mapping ? { ...mapping.document, status: mapping.status } : null,
        rule: rule ? { ...rule.document, status: rule.status } : null,
        instant: nowIso(this.clock),
        resource_ref: phase1.resource_local_ref,
        property: phase1.property,
      })
      await this.store.publishQualification(client, {
        tenantId: trust.tenant_id,
        environmentId: trust.environment_id,
        key,
        expectedVersion: phase1.aggregate_version,
        document: qualified.document,
        fingerprint: qualified.fingerprint,
        instant: qualified.document.instant,
        clock: this.clock,
      })
      await this.store.writeCache(
        client,
        key,
        trust.tenant_id,
        trust.environment_id,
        qualified.document,
        qualified.fingerprint,
        qualified.document.status,
        this.clock,
      )
    })
  }

  async proposeAssociation(trust, payload) {
    validateTrust(trust)
    const association = validateAssociation(payload)
    assertSameScope(trust, association.left)
    assertSameScope(trust, association.right)
    const left = resourceIdentity(association.left)
    const right = resourceIdentity(association.right)
    const pair = pairFingerprint(left.identity, right.identity, association.association_type)
    await this.#auth('propose_association', trust, { resource_local_ref: left.local_ref })
    return this.store.withTransaction(async client => {
      await this.store.lockPair(client, trust.tenant_id, trust.environment_id, pair)
      const existing = await this.store.getAssociationByPair(
        client, trust.tenant_id, trust.environment_id, association.association_type, pair,
      )
      if (existing) {
        return {
          outcome: 'duplicate_identical',
          local_ref: existing.local_ref,
          status: existing.status,
          version: Number(existing.version),
          pair_fingerprint: existing.pair_fingerprint,
        }
      }
      const leftRow = await this.store.upsertResource(client, association.left, this.clock)
      const rightRow = await this.store.upsertResource(client, association.right, this.clock)
      const inserted = await this.store.insertAssociation(client, {
        association, left: leftRow, right: rightRow, pair, clock: this.clock,
      })
      if (inserted.conflict) {
        const raced = await this.store.getAssociationByPair(
          client, trust.tenant_id, trust.environment_id, association.association_type, pair,
        )
        return {
          outcome: 'duplicate_identical',
          local_ref: raced.local_ref,
          status: raced.status,
          version: Number(raced.version),
          pair_fingerprint: raced.pair_fingerprint,
        }
      }
      return { outcome: 'applied', ...inserted }
    })
  }

  async admitAssociation(trust, { local_ref, expected_version }) {
    return this.#transitionAssociation(trust, local_ref, expected_version, 'admitted', 'admit_association')
  }

  async revokeAssociation(trust, { local_ref, expected_version }) {
    return this.#transitionAssociation(trust, local_ref, expected_version, 'revoked', 'revoke_association')
  }

  async #transitionAssociation(trust, localRef, expectedVersion, status, action) {
    validateTrust(trust)
    await this.#auth(action, trust, { resource_local_ref: localRef })
    return this.store.withTransaction(async client => {
      const row = await this.store.getAssociation(client, localRef)
      if (!row || row.tenant_id !== trust.tenant_id || row.environment_id !== trust.environment_id) {
        throw ocError('OC_UNAUTHORIZED', 'association is not readable')
      }
      await this.store.lockPair(client, row.tenant_id, row.environment_id, row.pair_fingerprint)
      const locked = await this.store.getAssociationByPair(client, row.tenant_id, row.environment_id, row.association_type, row.pair_fingerprint)
      const updated = await this.store.updateAssociationStatus(client, locked, expectedVersion, status, this.clock)
      await this.#invalidateAssociationEndpoints(client, trust, updated.left_ref, updated.right_ref)
      return {
        outcome: 'applied',
        local_ref: updated.local_ref,
        status: updated.status,
        version: Number(updated.version),
      }
    })
  }

  async admitMapping(trust, payload) {
    validateTrust(trust)
    const mapping = validateMapping(payload)
    await this.#auth('admit_mapping', trust)
    return this.#versionedAdmit(() => this.store.withTransaction(async client => {
      await lockStatePolicy(client, trust)
      const result = await this.store.upsertMapping(client, trust, mapping, 'admitted')
      await appendStatePolicy(client, trust, 'mapping', mapping, 'admitted', nowIso(this.clock))
      return result
    }))
  }

  async revokeMapping(trust, payload) {
    validateTrust(trust)
    const mapping = validateMapping(payload)
    await this.#auth('revoke_mapping', trust)
    return this.#versionedAdmit(() => this.store.withTransaction(async client => {
      await lockStatePolicy(client, trust)
      const stored = await this.store.upsertMapping(client, trust, mapping, 'revoked')
      await appendStatePolicy(client, trust, 'mapping', mapping, 'revoked', nowIso(this.clock))
      if (stored.outcome === 'applied') {
        await this.#invalidateMappingDependents(client, trust, mapping)
      }
      return stored
    }))
  }

  async admitRule(trust, payload) {
    validateTrust(trust)
    const rule = validateRule(payload)
    await this.#auth('admit_rule', trust)
    return this.#versionedAdmit(() => this.store.withTransaction(async client => {
      await lockStatePolicy(client, trust)
      const result = await this.store.upsertRule(client, trust, rule, 'admitted')
      await appendStatePolicy(client, trust, 'rule', rule, 'admitted', nowIso(this.clock))
      return result
    }))
  }

  async revokeRule(trust, payload) {
    validateTrust(trust)
    const rule = validateRule(payload)
    await this.#auth('revoke_rule', trust)
    return this.#versionedAdmit(() => this.store.withTransaction(async client => {
      await lockStatePolicy(client, trust)
      const stored = await this.store.upsertRule(client, trust, rule, 'revoked')
      await appendStatePolicy(client, trust, 'rule', rule, 'revoked', nowIso(this.clock))
      if (stored.outcome === 'applied') {
        await this.#invalidateMappingDependents(client, trust, { property: null, mapping_ref: null })
      }
      return stored
    }))
  }

  async admitStatePolicy(trust, payload) {
    validateTrust(trust)
    if (!payload || Object.keys(payload).sort().join(',') !== 'binding,mapping,rule') {
      throw ocError('OC_CONTRACT_INVALID', 'closed state policy bundle required')
    }
    const binding = validateStateBinding(payload.binding)
    const mapping = validateMapping(payload.mapping)
    const rule = validateRule(payload.rule)
    if (binding.tenant_id !== trust.tenant_id || binding.environment_id !== trust.environment_id
        || mapping.contract !== 'dubsar.operational-context.mapping/2'
        || mapping.mapping_ref !== binding.mapping_ref || mapping.version !== binding.mapping_version
        || mapping.property !== binding.property || mapping.producer_id !== binding.producer_id
        || mapping.source_instance_id !== binding.source_instance_id
        || rule.rule_ref !== binding.rule_ref || rule.version !== binding.rule_version) {
      throw ocError('OC_CONTRACT_INVALID', 'state policy scope mismatch')
    }
    await this.#auth('admit_state_policy', trust, {
      resource_local_ref: binding.resource_local_ref, property: binding.property,
      producer_id: binding.producer_id,
    })
    return this.#versionedAdmit(() => this.store.withTransaction(async client => {
      await lockStatePolicy(client, trust)
      const recordedAt = nowIso(this.clock)
      const latest = await client.query(`SELECT document FROM dubsar_context.state_policy_events
        WHERE tenant_id=$1 AND environment_id=$2 AND kind='binding' AND status='admitted'
          AND resource_local_ref=$3 AND property=$4 ORDER BY event_no DESC LIMIT 1`,
      [trust.tenant_id, trust.environment_id, binding.resource_local_ref, binding.property])
      const previous = latest.rows[0]?.document
      if (previous ? binding.supersedes.binding_ref !== previous.binding_ref
          || binding.supersedes.version !== previous.version
          || Date.parse(binding.effective_at) < Date.parse(previous.effective_at)
        : binding.supersedes.absence !== 'initial') {
        throw ocError('OC_INTEGRITY_CONFLICT', 'state binding transition does not name its predecessor')
      }
      const reused = await client.query(`SELECT 1 FROM dubsar_context.state_policy_events
        WHERE tenant_id=$1 AND environment_id=$2 AND kind='binding' AND policy_ref=$3 AND version=$4 LIMIT 1`,
      [trust.tenant_id, trust.environment_id, binding.binding_ref, binding.version])
      if (reused.rows.length) throw ocError('OC_INTEGRITY_CONFLICT', 'binding transition requires a new version')
      // A policy can become effective now or later, never before its admission.
      if (Date.parse(binding.effective_at) < Date.parse(recordedAt)) {
        throw ocError('OC_CONTRACT_INVALID', 'state binding cannot be backdated')
      }
      for (const ref of binding.legacy_observation_refs) {
        const found = await client.query(`SELECT document FROM dubsar_context.observations
          WHERE local_ref=$1 AND tenant_id=$2 AND environment_id=$3 AND resource_local_ref=$4 AND property=$5`,
        [ref, trust.tenant_id, trust.environment_id, binding.resource_local_ref, binding.property])
        if (found.rows.length !== 1 || found.rows[0].document.contract !== 'dubsar.operational-context.observation/1') {
          throw ocError('OC_CONTRACT_INVALID', 'legacy frontier must name existing v1 supports in scope')
        }
      }
      await this.store.upsertMapping(client, trust, mapping, 'admitted')
      await this.store.upsertRule(client, trust, rule, 'admitted')
      await appendStatePolicy(client, trust, 'mapping', mapping, 'admitted', recordedAt)
      await appendStatePolicy(client, trust, 'rule', rule, 'admitted', recordedAt)
      await appendStatePolicy(client, trust, 'binding', binding, 'admitted', recordedAt)
      return { outcome: 'applied', binding_ref: binding.binding_ref, version: binding.version, recorded_at: recordedAt }
    }))
  }

  async revokeStatePolicy(trust, payload) {
    validateTrust(trust)
    const binding = validateStateBinding(payload)
    if (binding.tenant_id !== trust.tenant_id || binding.environment_id !== trust.environment_id) {
      throw ocError('OC_CONTRACT_INVALID', 'state policy scope mismatch')
    }
    await this.#auth('revoke_state_policy', trust, {
      resource_local_ref: binding.resource_local_ref, property: binding.property, producer_id: binding.producer_id,
    })
    return this.#versionedAdmit(() => this.store.withTransaction(async client => {
      await lockStatePolicy(client, trust)
      await appendStatePolicy(client, trust, 'binding', binding, 'revoked', nowIso(this.clock))
      return { outcome: 'applied', binding_ref: binding.binding_ref, version: binding.version }
    }))
  }

  async #versionedAdmit(fn) {
    try {
      return await fn()
    } catch (error) {
      if (error?.code === 'OC_INTEGRITY_CONFLICT') {
        return { outcome: 'integrity_conflict', code: error.code, message: error.message }
      }
      throw error
    }
  }

  async #invalidateAssociationEndpoints(client, trust, leftRef, rightRef) {
    for (const ref of [leftRef, rightRef]) {
      const properties = await this.store.listDistinctProperties(
        client, trust.tenant_id, trust.environment_id, [ref],
      )
      const keys = new Set(await this.store.listAggregateKeysForResources(
        client, trust.tenant_id, trust.environment_id, [ref],
      ))
      for (const property of properties) keys.add(aggregateKey(ref, property))
      for (const key of keys) {
        await this.store.invalidateAggregate(client, trust.tenant_id, trust.environment_id, key)
      }
    }
  }

  async #invalidateMappingDependents(client, trust, mapping) {
    const observations = await this.store.listAllObservations(client, trust.tenant_id, trust.environment_id)
    const keys = new Set()
    for (const observation of observations) {
      if (mapping.property && observation.property !== mapping.property) continue
      keys.add(aggregateKey(observation.resource_local_ref, observation.property))
    }
    for (const key of keys) await this.store.invalidateAggregate(client, trust.tenant_id, trust.environment_id, key)
  }

  async qualify(trust, { resource, property, instant }) {
    validateTrust(trust)
    this.faults.rawSupportsExamined = 0
    const resolved = validateResource(resource)
    assertSameScope(trust, resolved.identity)
    await this.#auth('read', trust, { resource_local_ref: resolved.local_ref, property })
    const at = instant ? normalizeUtcDateTime(instant) : nowIso(this.clock)
    return this.store.withClient(async client => this.#qualifyResource(client, trust, resolved.local_ref, property, at, { enforceRead: true }))
  }

  async #qualifyResource(client, trust, resourceRef, property, instant, { enforceRead = false } = {}) {
    const key = aggregateKey(resourceRef, property)
    const current = await this.store.currentQualification(client, trust.tenant_id, trust.environment_id, key)
    let refs = await this.#cluster(client, trust, resourceRef)
    if (enforceRead) {
      const readable = []
      for (const ref of refs) {
        if (await this.#mayReadResource(trust, ref)) readable.push(ref)
      }
      refs = readable.length > 0 ? readable : [resourceRef]
    }
    const collected = enforceRead
      ? await this.#collectAuthorizedObservations(
        client, trust, refs, [property], OC_BOUNDS.max_observations_examined,
      )
      : null
    const fetched = collected ? null : await this.store.listObservationsForResources(
        client, trust.tenant_id, trust.environment_id,
        refs,
        [property],
        OC_BOUNDS.max_observations_examined + 1,
      )
    const observations = collected?.observations ?? fetched.slice(0, OC_BOUNDS.max_observations_examined)
    const complete = collected ? !collected.overflow : fetched.length <= OC_BOUNDS.max_observations_examined
    let associations = await this.store.listAssociations(client, trust.tenant_id, trust.environment_id, [resourceRef])
    if (enforceRead) {
      const visible = []
      for (const link of associations) {
        if (
          await this.#mayReadResource(trust, link.left_ref)
          && await this.#mayReadResource(trust, link.right_ref)
        ) visible.push(link)
      }
      associations = visible
    }
    const sample = observations.find(row => row.property === property)
    const mapping = sample
      ? await this.store.getMapping(client, trust, sample.mapping_ref, sample.mapping_version)
      : null
    const rule = sample?.rule_ref
      ? await this.store.getRule(client, trust, sample.rule_ref, sample.rule_version)
      : null
    const qualified = qualifyAt({
      observations,
      complete,
      associations,
      mapping: mapping ? { ...mapping.document, status: mapping.status } : null,
      rule: rule ? { ...rule.document, status: rule.status } : null,
      instant,
      resource_ref: resourceRef,
      property,
    })
    if (complete && current.status !== 'current') qualified.document.status = current.status === 'empty' ? 'current' : current.status
    qualified.fingerprint = qualificationFingerprint(qualified.document)
    return { ...qualified, semantic: semanticQualification(qualified.document), aggregate: current.aggregate }
  }

  async #cluster(client, trust, resourceRef) {
    const associations = await this.store.listAssociations(client, trust.tenant_id, trust.environment_id, [resourceRef])
    const cluster = new Set([resourceRef])
    for (const association of associations) {
      if (association.association_type !== 'same_resource' || association.status !== 'admitted') continue
      cluster.add(association.left_ref)
      cluster.add(association.right_ref)
    }
    return [...cluster]
  }

  async readView(trust, payload) {
    validateTrust(trust)
    this.faults.rawSupportsExamined = 0
    const request = validateViewRequest(payload)
    const { view, rendered } = await this.#prepareView(trust, request)
    for (const item of rendered) {
      await revalidateAuthority(this.authority, { action: 'read', trust, ...item })
    }
    assertUtf8Bound(view, OC_BOUNDS.max_response_utf8_bytes)
    if (view.contract === 'dubsar.operational-context.view/2') validateClosed('view-v2.schema.json', view)
    await this.store.withClient(client => this.store.insertViewReceipt(client, view))
    return view
  }

  #noteRawSupportExamined() {
    this.faults.rawSupportsExamined = (this.faults.rawSupportsExamined ?? 0) + 1
    if (typeof this.faults.onSupportExamined === 'function') this.faults.onSupportExamined()
  }

  async #collectAuthorizedObservations(client, trust, resourceRefs, propertyFilter, remaining) {
    if (remaining <= 0 || !Array.isArray(resourceRefs) || resourceRefs.length === 0) {
      return { observations: [], overflow: remaining <= 0, examined: 0 }
    }
    const fetched = await this.store.listObservationsPage(
      client,
      trust.tenant_id,
      trust.environment_id,
      resourceRefs,
      propertyFilter,
      { afterLocalRef: null, limit: remaining + 1 },
    )
    const overflow = fetched.length > remaining
    const window = overflow ? fetched.slice(0, remaining) : fetched
    const authorized = []
    for (const observation of window) {
      this.#noteRawSupportExamined()
      if (await this.#mayReadSupport(trust, observation)) authorized.push(observation)
    }
    return { observations: authorized, overflow, examined: window.length }
  }

  async #mayReadSupport(trust, observation) {
    try {
      await this.#auth('read', trust, {
        resource_local_ref: observation.resource_local_ref,
        property: observation.property,
        producer_id: observation.producer_id,
      })
      return true
    } catch (error) {
      if (error?.code === 'OC_UNAUTHORIZED' || error?.code === 'OC_AUTHORITY_MISSING') return false
      throw error
    }
  }

  async #mayReadResource(trust, resourceLocalRef) {
    try {
      await this.#auth('read', trust, { resource_local_ref: resourceLocalRef })
      return true
    } catch (error) {
      if (error?.code === 'OC_UNAUTHORIZED' || error?.code === 'OC_AUTHORITY_MISSING') return false
      throw error
    }
  }

  async #readableCluster(client, trust, resourceRef, relationDepth) {
    if (relationDepth !== 1) return [resourceRef]
    const cluster = await this.#cluster(client, trust, resourceRef)
    const readable = []
    for (const ref of cluster) {
      if (await this.#mayReadResource(trust, ref)) readable.push(ref)
    }
    return readable
  }

  async #prepareView(trust, request) {
    const instant = request.instant ?? nowIso(this.clock)
    const resolved = []
    const rendered = []
    for (const entry of request.resources) {
      const identity = entry.local_ref
        ? null
        : resourceIdentity(entry)
      if (identity) assertSameScope(trust, identity.identity)
      const localRef = entry.local_ref ?? identity.local_ref
      try {
        await this.#auth('read', trust, { resource_local_ref: localRef })
      } catch (error) {
        if (error?.code === 'OC_UNAUTHORIZED' || error?.code === 'OC_AUTHORITY_MISSING') {
          throw ocError('OC_UNAUTHORIZED', 'generic refusal')
        }
        throw error
      }
      resolved.push({ entry, localRef, identity })
      rendered.push({ resource_local_ref: localRef })
    }

    const view = await this.store.withTransaction(async client => {
      if (request.contract === 'dubsar.operational-context.view-request/2') await lockStatePolicy(client, trust)
      const resources = []
      const associationsOut = []
      let examined = 0
      let partial = false
      const seenAssoc = new Set()

      for (const item of resolved) {
        const found = item.identity
          ? await this.store.findResourceByIdentity(client, item.entry)
          : await this.store.getResourceInScope(client, trust, item.localRef)
        if (!found) {
          resources.push({ resolution: 'unknown', requested: item.localRef })
          partial = true
          continue
        }
        rendered.push({ resource_local_ref: found.local_ref })
        if (item.entry.type && found.identity.type && item.entry.type !== found.identity.type && item.entry.contract) {
          resources.push({ resolution: 'type_mismatch', local_ref: found.local_ref })
          partial = true
          continue
        }
        let refs = await this.#readableCluster(client, trust, found.local_ref, request.relation_depth)
        if (refs.length > OC_BOUNDS.max_resources_per_call) {
          refs = refs.slice(0, OC_BOUNDS.max_resources_per_call)
          partial = true
        }
        const remaining = OC_BOUNDS.max_observations_examined - examined
        if (remaining <= 0) {
          partial = true
          break
        }
        const collected = await this.#collectAuthorizedObservations(
          client, trust, refs, request.properties ?? null, remaining,
        )
        const authorizedObs = collected.observations
        if (collected.overflow) partial = true
        examined += collected.examined
        const properties = [...new Set(authorizedObs.map(row => row.property))]
        const visibleAssociations = []
        const linksForQualify = await this.store.listAssociations(
          client, trust.tenant_id, trust.environment_id, refs,
        )
        for (const link of linksForQualify) {
          if (link.status !== 'admitted') continue
          if (
            await this.#mayReadResource(trust, link.left_ref)
            && await this.#mayReadResource(trust, link.right_ref)
          ) {
            visibleAssociations.push(link)
          }
        }
        const qualifications = []
        for (const property of properties) {
          const rows = authorizedObs.filter(row => row.property === property)
          if (rows.length === 0) continue
          const qualified = qualifyAt({
            observations: rows,
            complete: !collected.overflow,
            associations: visibleAssociations,
            mapping: await this.#mapping(client, trust, rows[0]),
            rule: await this.#rule(client, trust, rows[0]),
            instant,
            resource_ref: found.local_ref,
            property,
          })
          const statePolicy = request.contract === 'dubsar.operational-context.view-request/2'
            ? await statePolicyAt(client, trust, found.local_ref, property, instant) : null
          const stateProjection = request.contract === 'dubsar.operational-context.view-request/2'
            ? projectState({
              observations: rows,
              ...statePolicy,
              superseded_observation_refs: await supersededStateSupports(client, trust, rows, statePolicy.binding, instant),
              instant, resource_ref: found.local_ref, property,
              complete: !collected.overflow && request.relation_depth === 0
                && collected.observations.length === collected.examined,
            }) : null
          qualifications.push({
            property,
            qualification: qualified.document,
            ...(stateProjection ? { state_projection: validateClosed('state-projection.schema.json', stateProjection) } : {}),
            observations: rows.map(row => ({
              observation_ref: row.local_ref,
              producer_id: row.producer_id,
              result: row.document.result,
              source_observed_at: row.source_observed_at,
              received_at: row.received_at,
            })),
          })
          rendered.push({ resource_local_ref: found.local_ref, property })
          for (const row of rows) {
            rendered.push({
              resource_local_ref: row.resource_local_ref,
              property: row.property,
              producer_id: row.producer_id,
            })
          }
        }
        resources.push({
          resolution: 'resolved',
          local_ref: found.local_ref,
          identity: found.identity,
          qualifications,
        })
        if (request.relation_depth === 1) {
          const links = await this.store.listAssociations(client, trust.tenant_id, trust.environment_id, [found.local_ref])
          for (const link of links) {
            if (seenAssoc.has(link.local_ref)) continue
            seenAssoc.add(link.local_ref)
            const other = link.left_ref === found.local_ref ? link.right_ref : link.left_ref
            if (!await this.#mayReadResource(trust, other)) continue
            associationsOut.push({
              local_ref: link.local_ref,
              association_type: link.association_type,
              status: link.status,
              version: Number(link.version),
              left_ref: link.left_ref,
              right_ref: link.right_ref,
            })
            rendered.push({ resource_local_ref: link.left_ref })
            rendered.push({ resource_local_ref: link.right_ref })
          }
        }
      }

      const emptyComplete = resources.length > 0 && resources.every(row => row.resolution === 'resolved' && (row.qualifications?.length ?? 0) === 0)
      const document = {
        contract: request.contract === 'dubsar.operational-context.view-request/2'
          ? 'dubsar.operational-context.view/2' : OC_CONTRACTS.view,
        view_ref: `ocv_${randomUUID().replaceAll('-', '')}`,
        tenant_id: trust.tenant_id,
        environment_id: trust.environment_id,
        reader_id: trust.principal_id,
        instant,
        created_at: nowIso(this.clock),
        selection_receipt: partial ? 'partial' : 'complete_in_authorized_selection',
        resources,
        associations: associationsOut,
        reserves: [{ code: 'AUTHORIZED_SELECTION_ONLY' }],
        bounds: {
          max_resources: OC_BOUNDS.max_resources_per_call,
          relation_depth: request.relation_depth,
          max_observations_examined: OC_BOUNDS.max_observations_examined,
          truncated: partial,
        },
      }
      if (emptyComplete) document.reserves.push({ code: 'EMPTY_AUTHORIZED_SELECTION' })
      if (typeof this.faults.duringPrepare === 'function') await this.faults.duringPrepare()
      return document
    })
    return { view, rendered }
  }

  async #mapping(client, trust, observation) {
    if (!observation.mapping_ref) return null
    const row = await this.store.getMapping(client, trust, observation.mapping_ref, observation.mapping_version)
    return row ? { ...row.document, status: row.status } : null
  }

  async #rule(client, trust, observation) {
    if (!observation.rule_ref) return null
    const row = await this.store.getRule(client, trust, observation.rule_ref, observation.rule_version)
    return row ? { ...row.document, status: row.status } : null
  }

  async rebuildDerivatives(trust, { instant } = {}) {
    validateTrust(trust)
    await this.#auth('rebuild', trust)
    const at = instant ? normalizeUtcDateTime(instant) : nowIso(this.clock)
    return this.store.withTransaction(async client => {
      await this.store.deleteCache(client, trust.tenant_id, trust.environment_id)
      const observations = await this.store.listAllObservations(client, trust.tenant_id, trust.environment_id)
      const keys = new Map()
      for (const observation of observations) {
        const key = aggregateKey(observation.resource_local_ref, observation.property)
        if (!keys.has(key)) keys.set(key, observation)
      }
      let rebuiltCount = 0
      for (const [key, sample] of keys) {
        const aggregate = await this.store.invalidateAggregate(client, trust.tenant_id, trust.environment_id, key)
        const qualified = await this.#qualifyResource(client, trust, sample.resource_local_ref, sample.property, at)
        if (!qualified.document.limits.some(limit => limit.code === 'SUPPORT_WINDOW_TRUNCATED')) {
          qualified.document.status = 'current'
          qualified.fingerprint = qualificationFingerprint(qualified.document)
        }
        try {
          const published = await this.store.publishQualification(client, {
            tenantId: trust.tenant_id,
            environmentId: trust.environment_id,
            key,
            expectedVersion: Number(aggregate.version),
            document: { ...qualified.document, instant: at },
            fingerprint: qualified.fingerprint,
            instant: at,
            clock: this.clock,
          })
          await this.store.writeCache(client, key, trust.tenant_id, trust.environment_id, published.document, qualified.fingerprint, published.document.status, this.clock)
          rebuiltCount += 1
        } catch (error) {
          if (error?.code !== 'OC_STALE_DERIVATIVE') throw error
        }
      }
      return Object.freeze({
        rebuilt: rebuiltCount,
        instant: at,
        effects_replayed: 0,
        permissions_restored: false,
      })
    })
  }
}

export function createOperationalContextKernel(options) {
  return new OperationalContextKernel(options)
}
