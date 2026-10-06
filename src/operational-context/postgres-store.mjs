import { randomUUID } from 'node:crypto'
import { canonicalJson } from '../canonical-json.mjs'
import { OC_BOUNDS, OC_CONTRACTS } from './bounds.mjs'
import { ocError } from './errors.mjs'
import { resourceIdentity, pairFingerprint, aggregateKey } from './identity.mjs'
import { observationFingerprint } from './contracts.mjs'
import { sourceInstant, nowIso } from './time.mjs'

function uniqueViolation(error) {
  return error?.code === '23505'
}

function rowResource(row) {
  return {
    contract: OC_CONTRACTS.resource,
    tenant_id: row.tenant_id,
    environment_id: row.environment_id,
    source_instance_id: row.source_instance_id,
    namespace: row.namespace,
    type: row.type,
    source_id: row.source_id,
    incarnation: row.incarnation_absent ? { absence: 'not_available' } : row.incarnation,
    ...(row.label == null ? {} : { label: row.label }),
  }
}

function observationRow(row) {
  return {
    local_ref: row.local_ref,
    tenant_id: row.tenant_id,
    environment_id: row.environment_id,
    resource_local_ref: row.resource_local_ref,
    property: row.property,
    delivery_id: row.delivery_id,
    measurement_id: row.measurement_id,
    result_kind: row.result_kind,
    document: row.document,
    fingerprint: row.fingerprint,
    source_observed_at: row.source_date_unknown ? { absence: 'unknown' } : row.source_observed_at?.toISOString?.() ?? row.source_observed_at,
    received_at: row.received_at?.toISOString?.() ?? row.received_at,
    mapping_ref: row.mapping_ref,
    mapping_version: row.mapping_version,
    rule_ref: row.rule_ref,
    rule_version: row.rule_version,
    producer_id: row.producer_id,
    source_instance_id: row.source_instance_id,
    correction_of: row.correction_of,
    retraction_of: row.retraction_of,
  }
}

export class PostgresContextStore {
  constructor(pool) {
    if (typeof pool?.connect !== 'function') throw ocError('OC_UNAVAILABLE', 'PostgreSQL pool is required')
    this.pool = pool
  }

  async withClient(fn) {
    const client = await this.pool.connect()
    try {
      await client.query(`SET statement_timeout = ${OC_BOUNDS.sql_statement_timeout_ms}`)
      return await fn(client)
    } finally {
      client.release()
    }
  }

  async withTransaction(fn) {
    return this.withClient(async client => {
      await client.query('BEGIN')
      await client.query(`SET LOCAL statement_timeout = ${OC_BOUNDS.sql_statement_timeout_ms}`)
      try {
        const result = await fn(client)
        await client.query('COMMIT')
        return result
      } catch (error) {
        try { await client.query('ROLLBACK') } catch { /* keep original */ }
        throw error
      }
    })
  }

  async lockDelivery(client, tenantId, environmentId, deliveryId) {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
      `oc:delivery:${tenantId}\u001f${environmentId}\u001f${deliveryId}`,
    ])
  }

  async lockPair(client, tenantId, environmentId, pair) {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
      `oc:pair:${tenantId}\u001f${environmentId}\u001f${pair}`,
    ])
  }

  async upsertResource(client, resource, clock) {
    const resolved = resourceIdentity(resource)
    const incarnationAbsent = typeof resolved.identity.incarnation === 'object'
    await client.query(
      `INSERT INTO dubsar_context.resources (
         local_ref, tenant_id, environment_id, source_instance_id, namespace, type, source_id,
         incarnation, incarnation_absent, label, identity_fingerprint, registered_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (local_ref) DO NOTHING`,
      [
        resolved.local_ref,
        resolved.identity.tenant_id,
        resolved.identity.environment_id,
        resolved.identity.source_instance_id,
        resolved.identity.namespace,
        resolved.identity.type,
        resolved.identity.source_id,
        incarnationAbsent ? null : resolved.identity.incarnation,
        incarnationAbsent,
        resource.label ?? null,
        resolved.fingerprint,
        nowIso(clock),
      ],
    )
    const row = (await client.query('SELECT * FROM dubsar_context.resources WHERE local_ref = $1', [resolved.local_ref])).rows[0]
    return { ...resolved, row }
  }

  async getResource(client, localRef) {
    const row = (await client.query('SELECT * FROM dubsar_context.resources WHERE local_ref = $1', [localRef])).rows[0]
    return row ? { local_ref: row.local_ref, identity: rowResource(row), fingerprint: row.identity_fingerprint, row } : null
  }

  async getResourceInScope(client, trust, localRef) {
    const row = (await client.query(
      `SELECT * FROM dubsar_context.resources
       WHERE local_ref = $1 AND tenant_id = $2 AND environment_id = $3`,
      [localRef, trust.tenant_id, trust.environment_id],
    )).rows[0]
    return row ? { local_ref: row.local_ref, identity: rowResource(row), fingerprint: row.identity_fingerprint, row } : null
  }

  async findResourceByIdentity(client, resource) {
    const resolved = resourceIdentity(resource)
    return this.getResource(client, resolved.local_ref)
  }

  async lockAggregate(client, tenantId, environmentId, key) {
    await client.query(
      `INSERT INTO dubsar_context.aggregates (tenant_id, environment_id, aggregate_key, version, status)
       VALUES ($1,$2,$3,0,'pending_recalculation')
       ON CONFLICT (tenant_id, environment_id, aggregate_key) DO NOTHING`,
      [tenantId, environmentId, key],
    )
    const row = (await client.query(
      `SELECT * FROM dubsar_context.aggregates
       WHERE tenant_id = $1 AND environment_id = $2 AND aggregate_key = $3
       FOR UPDATE`,
      [tenantId, environmentId, key],
    )).rows[0]
    return row
  }

  async insertObservation(client, { observation, resource, fingerprint, receivedAt }) {
    const localRef = `oco_${randomUUID().replaceAll('-', '')}`
    const source = sourceInstant(observation.source_observed_at)
    const measurementAbsent = typeof observation.measurement_id === 'object'
    try {
      await client.query(
        `INSERT INTO dubsar_context.observations (
           local_ref, tenant_id, environment_id, resource_local_ref, property, delivery_id,
           measurement_id, measurement_absent, result_kind, document, fingerprint,
           source_observed_at, source_date_unknown, received_at, mapping_ref, mapping_version,
           rule_ref, rule_version, producer_id, source_instance_id, correction_of, retraction_of
         ) VALUES (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
         )`,
        [
          localRef,
          observation.subject.tenant_id,
          observation.subject.environment_id,
          resource.local_ref,
          observation.property,
          observation.delivery_id,
          measurementAbsent ? null : observation.measurement_id,
          measurementAbsent,
          observation.result.kind,
          observation,
          fingerprint,
          source.kind === 'known' ? source.normalized : null,
          source.kind === 'unknown',
          receivedAt,
          observation.provenance.mapping_ref,
          observation.provenance.mapping_version,
          observation.rule_ref ?? null,
          observation.rule_version ?? null,
          observation.provenance.producer_id,
          observation.subject.source_instance_id,
          observation.correction_of ?? null,
          observation.retraction_of ?? null,
        ],
      )
    } catch (error) {
      if (uniqueViolation(error)) return { conflict: true, error }
      throw error
    }
    return { local_ref: localRef }
  }

  async getByMeasurement(client, tenantId, environmentId, measurementId) {
    const row = (await client.query(
      `SELECT * FROM dubsar_context.observations
       WHERE tenant_id = $1 AND environment_id = $2 AND measurement_id = $3 AND measurement_absent = false`,
      [tenantId, environmentId, measurementId],
    )).rows[0]
    return row ? observationRow(row) : null
  }

  async getByDelivery(client, tenantId, environmentId, deliveryId) {
    const row = (await client.query(
      `SELECT * FROM dubsar_context.observations
       WHERE tenant_id = $1 AND environment_id = $2 AND delivery_id = $3`,
      [tenantId, environmentId, deliveryId],
    )).rows[0]
    return row ? observationRow(row) : null
  }

  async getObservation(client, localRef) {
    const row = (await client.query('SELECT * FROM dubsar_context.observations WHERE local_ref = $1', [localRef])).rows[0]
    return row ? observationRow(row) : null
  }

  async listObservationsForResources(client, tenantId, environmentId, resourceRefs, propertyFilter, limit) {
    return this.listObservationsPage(client, tenantId, environmentId, resourceRefs, propertyFilter, {
      afterLocalRef: null,
      limit,
    })
  }

  async listObservationsPage(client, tenantId, environmentId, resourceRefs, propertyFilter, { afterLocalRef = null, limit } = {}) {
    if (!Array.isArray(resourceRefs) || resourceRefs.length === 0 || !Number.isFinite(limit) || limit <= 0) {
      return []
    }
    const result = await client.query(
      `SELECT * FROM dubsar_context.observations
       WHERE tenant_id = $1 AND environment_id = $2
         AND resource_local_ref = ANY($3::text[])
         AND ($4::text[] IS NULL OR property = ANY($4))
         AND ($5::text IS NULL OR local_ref > $5)
       ORDER BY local_ref
       LIMIT $6`,
      [tenantId, environmentId, resourceRefs, propertyFilter ?? null, afterLocalRef, limit],
    )
    return result.rows.map(observationRow)
  }

  async listDistinctProperties(client, tenantId, environmentId, resourceRefs) {
    const result = await client.query(
      `SELECT DISTINCT property
       FROM dubsar_context.observations
       WHERE tenant_id = $1 AND environment_id = $2
         AND resource_local_ref = ANY($3)
       ORDER BY property`,
      [tenantId, environmentId, resourceRefs],
    )
    return result.rows.map(row => row.property)
  }

  async listAggregateKeysForResources(client, tenantId, environmentId, resourceRefs) {
    const result = await client.query(
      `SELECT aggregate_key
       FROM dubsar_context.aggregates
       WHERE tenant_id = $1 AND environment_id = $2
         AND aggregate_key::jsonb ->> 'resource_local_ref' = ANY($3::text[])`,
      [tenantId, environmentId, resourceRefs],
    )
    return result.rows.map(row => row.aggregate_key)
  }

  async invalidateAggregate(client, tenantId, environmentId, key) {
    const row = await this.lockAggregate(client, tenantId, environmentId, key)
    await client.query(
      `UPDATE dubsar_context.aggregates
       SET version = version + 1, status = 'pending_recalculation', current_qualification_ref = NULL
       WHERE tenant_id = $1 AND environment_id = $2 AND aggregate_key = $3`,
      [tenantId, environmentId, key],
    )
    if (row.current_qualification_ref) {
      await client.query(
        `UPDATE dubsar_context.qualifications SET status = 'invalidated' WHERE local_ref = $1 AND status = 'current'`,
        [row.current_qualification_ref],
      )
    }
    const next = (await client.query(
      `SELECT * FROM dubsar_context.aggregates WHERE tenant_id = $1 AND environment_id = $2 AND aggregate_key = $3`,
      [tenantId, environmentId, key],
    )).rows[0]
    return next
  }

  async publishQualification(client, { tenantId, environmentId, key, expectedVersion, document, fingerprint, instant, clock }) {
    const aggregate = await this.lockAggregate(client, tenantId, environmentId, key)
    if (Number(aggregate.version) !== Number(expectedVersion)) {
      throw ocError('OC_STALE_DERIVATIVE', 'aggregate version changed before publish')
    }
    const localRef = `ocq_${randomUUID().replaceAll('-', '')}`
    const status = document.status === 'pending_recalculation' ? 'pending_recalculation' : 'current'
    const stored = { ...document, status }
    await client.query(
      `INSERT INTO dubsar_context.qualifications (
         local_ref, tenant_id, environment_id, aggregate_key, aggregate_version, instant, status, document, fingerprint, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [localRef, tenantId, environmentId, key, expectedVersion, instant, status, stored, fingerprint, nowIso(clock)],
    )
    await client.query(
      `UPDATE dubsar_context.aggregates
       SET status = $5, current_qualification_ref = $4
       WHERE tenant_id = $1 AND environment_id = $2 AND aggregate_key = $3`,
      [tenantId, environmentId, key, localRef, status],
    )
    return { local_ref: localRef, document: stored, aggregate_version: expectedVersion }
  }

  async currentQualification(client, tenantId, environmentId, key) {
    const aggregate = (await client.query(
      `SELECT * FROM dubsar_context.aggregates WHERE tenant_id = $1 AND environment_id = $2 AND aggregate_key = $3`,
      [tenantId, environmentId, key],
    )).rows[0]
    if (!aggregate) return { status: 'empty', aggregate: null, qualification: null }
    if (aggregate.status !== 'current' || !aggregate.current_qualification_ref) {
      return { status: aggregate.status, aggregate, qualification: null }
    }
    const row = (await client.query(
      'SELECT * FROM dubsar_context.qualifications WHERE local_ref = $1',
      [aggregate.current_qualification_ref],
    )).rows[0]
    return { status: aggregate.status, aggregate, qualification: row }
  }

  async insertAssociation(client, { association, left, right, pair, clock }) {
    const localRef = `oca_${randomUUID().replaceAll('-', '')}`
    const document = {
      contract: OC_CONTRACTS.association,
      association_type: association.association_type,
      left: left.identity,
      right: right.identity,
    }
    try {
      await client.query(
        `INSERT INTO dubsar_context.associations (
           local_ref, tenant_id, environment_id, association_type, left_ref, right_ref,
           pair_fingerprint, status, version, document
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'candidate',1,$8)`,
        [
          localRef,
          left.identity.tenant_id,
          left.identity.environment_id,
          association.association_type,
          left.local_ref,
          right.local_ref,
          pair,
          document,
        ],
      )
    } catch (error) {
      if (uniqueViolation(error)) return { conflict: true }
      throw error
    }
    await this.appendAssociationEvent(client, localRef, 1, 'propose', document, clock)
    return { local_ref: localRef, version: 1, status: 'candidate', pair_fingerprint: pair }
  }

  async appendAssociationEvent(client, associationRef, version, action, document, clock) {
    await client.query(
      `INSERT INTO dubsar_context.association_events (event_ref, association_ref, version, action, document, recorded_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [`oce_${randomUUID().replaceAll('-', '')}`, associationRef, version, action, document, nowIso(clock)],
    )
  }

  async getAssociation(client, localRef) {
    const row = (await client.query('SELECT * FROM dubsar_context.associations WHERE local_ref = $1', [localRef])).rows[0]
    return row ?? null
  }

  async getAssociationByPair(client, tenantId, environmentId, type, pair) {
    const row = (await client.query(
      `SELECT * FROM dubsar_context.associations
       WHERE tenant_id = $1 AND environment_id = $2 AND association_type = $3 AND pair_fingerprint = $4
       FOR UPDATE`,
      [tenantId, environmentId, type, pair],
    )).rows[0]
    return row ?? null
  }

  async listAssociations(client, tenantId, environmentId, resourceRefs) {
    const result = await client.query(
      `SELECT * FROM dubsar_context.associations
       WHERE tenant_id = $1 AND environment_id = $2
         AND (left_ref = ANY($3) OR right_ref = ANY($3))
       ORDER BY local_ref`,
      [tenantId, environmentId, resourceRefs],
    )
    return result.rows
  }

  async updateAssociationStatus(client, row, expectedVersion, status, clock) {
    if (Number(row.version) !== Number(expectedVersion)) {
      throw ocError('OC_VERSION_CONFLICT', 'association expected version mismatch')
    }
    const next = Number(row.version) + 1
    const updated = await client.query(
      `UPDATE dubsar_context.associations SET status = $2, version = $3
       WHERE local_ref = $1 AND version = $4
       RETURNING *`,
      [row.local_ref, status, next, expectedVersion],
    )
    if (updated.rowCount !== 1) throw ocError('OC_VERSION_CONFLICT', 'association concurrent update')
    await this.appendAssociationEvent(client, row.local_ref, next, status === 'admitted' ? 'admit' : 'revoke', updated.rows[0].document, clock)
    return updated.rows[0]
  }

  async upsertMapping(client, trust, mapping, status) {
    return this.#upsertVersioned(client, {
      table: 'mappings',
      refColumn: 'mapping_ref',
      refValue: mapping.mapping_ref,
      version: mapping.version,
      trust,
      document: mapping,
      status,
      entity: 'mapping',
    })
  }

  async getMapping(client, trust, mappingRef, version) {
    const row = (await client.query(
      `SELECT * FROM dubsar_context.mappings
       WHERE tenant_id = $1 AND environment_id = $2 AND mapping_ref = $3 AND version = $4`,
      [trust.tenant_id, trust.environment_id, mappingRef, version],
    )).rows[0]
    return row ?? null
  }

  async upsertRule(client, trust, rule, status) {
    return this.#upsertVersioned(client, {
      table: 'rules',
      refColumn: 'rule_ref',
      refValue: rule.rule_ref,
      version: rule.version,
      trust,
      document: rule,
      status,
      entity: 'rule',
    })
  }

  async #upsertVersioned(client, { table, refColumn, refValue, version, trust, document, status, entity }) {
    const allowed = table === 'mappings' || table === 'rules'
    const allowedCol = refColumn === 'mapping_ref' || refColumn === 'rule_ref'
    if (!allowed || !allowedCol) throw ocError('OC_CONTRACT_INVALID', 'unknown versioned table')
    const selectSql = `SELECT * FROM dubsar_context.${table}
       WHERE tenant_id = $1 AND environment_id = $2 AND ${refColumn} = $3 AND version = $4
       FOR UPDATE`
    const insertSql = `INSERT INTO dubsar_context.${table}
         (${refColumn}, version, tenant_id, environment_id, status, document)
       VALUES ($1,$2,$3,$4,$5,$6)`
    const updateSql = `UPDATE dubsar_context.${table} SET status = $5
       WHERE tenant_id = $1 AND environment_id = $2 AND ${refColumn} = $3 AND version = $4`
    const existing = (await client.query(selectSql, [
      trust.tenant_id, trust.environment_id, refValue, version,
    ])).rows[0]
    if (!existing) {
      try {
        await client.query(insertSql, [
          refValue, version, trust.tenant_id, trust.environment_id, status, document,
        ])
      } catch (error) {
        if (!uniqueViolation(error)) throw error
        return this.#upsertVersioned(client, { table, refColumn, refValue, version, trust, document, status, entity })
      }
      return { ...document, status, outcome: 'applied' }
    }
    if (canonicalJson(existing.document) !== canonicalJson(document)) {
      throw ocError('OC_INTEGRITY_CONFLICT', `${entity} version already bound to different content`)
    }
    if (existing.status === status) {
      return { ...existing.document, status: existing.status, outcome: 'duplicate_identical' }
    }
    await client.query(updateSql, [
      trust.tenant_id, trust.environment_id, refValue, version, status,
    ])
    return { ...existing.document, status, outcome: 'applied' }
  }

  async getRule(client, trust, ruleRef, version) {
    const row = (await client.query(
      `SELECT * FROM dubsar_context.rules
       WHERE tenant_id = $1 AND environment_id = $2 AND rule_ref = $3 AND version = $4`,
      [trust.tenant_id, trust.environment_id, ruleRef, version],
    )).rows[0]
    return row ?? null
  }

  async writeCache(client, key, tenantId, environmentId, document, fingerprint, status, clock) {
    const cacheStatus = status === 'pending_recalculation' ? 'stale' : status
    await client.query(
      `INSERT INTO dubsar_context.derivative_cache (cache_key, tenant_id, environment_id, document, input_fingerprint, status, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (cache_key) DO UPDATE SET document = EXCLUDED.document, input_fingerprint = EXCLUDED.input_fingerprint,
         status = EXCLUDED.status, updated_at = EXCLUDED.updated_at`,
      [key, tenantId, environmentId, document, fingerprint, cacheStatus, nowIso(clock)],
    )
  }

  async deleteCache(client, tenantId, environmentId) {
    await client.query(
      'DELETE FROM dubsar_context.derivative_cache WHERE tenant_id = $1 AND environment_id = $2',
      [tenantId, environmentId],
    )
  }

  async corruptCache(client, key) {
    await client.query(
      `UPDATE dubsar_context.derivative_cache SET status = 'stale', document = '{"corrupted":true}'::jsonb WHERE cache_key = $1`,
      [key],
    )
  }

  async insertViewReceipt(client, view) {
    await client.query(
      `INSERT INTO dubsar_context.view_receipts (view_ref, tenant_id, environment_id, reader_id, document, created_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [view.view_ref, view.tenant_id, view.environment_id, view.reader_id, view, view.created_at],
    )
  }

  async listAllObservations(client, tenantId, environmentId) {
    const result = await client.query(
      `SELECT * FROM dubsar_context.observations
       WHERE tenant_id = $1 AND environment_id = $2
       ORDER BY local_ref`,
      [tenantId, environmentId],
    )
    return result.rows.map(observationRow)
  }
}

export { aggregateKey, observationFingerprint, pairFingerprint }
