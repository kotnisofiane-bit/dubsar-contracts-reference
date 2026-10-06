import { canonicalJson } from '../canonical-json.mjs'
import { ocError } from './errors.mjs'
import { OC_BOUNDS } from './bounds.mjs'
import { matchesStateGeneration } from './state-projection.mjs'

// All policy mutations and views take this transaction lock. This serializes the
// configuration snapshot with its recorded time; no retrospective configuration.
export async function lockStatePolicy(client, trust) {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`oc:state-policy:${trust.tenant_id}:${trust.environment_id}`])
}

export async function appendStatePolicy(client, trust, kind, document, status, recordedAt) {
  const ref = document[`${kind}_ref`]
  const params = [trust.tenant_id, trust.environment_id, kind, ref, document.version]
  const prior = await client.query(`SELECT document FROM dubsar_context.state_policy_events
    WHERE tenant_id=$1 AND environment_id=$2 AND kind=$3 AND policy_ref=$4 AND version=$5 LIMIT 1`, params)
  if (prior.rows.length && canonicalJson(prior.rows[0].document) !== canonicalJson(document)) {
    throw ocError('OC_INTEGRITY_CONFLICT', 'state policy version is immutable')
  }
  await client.query(`INSERT INTO dubsar_context.state_policy_events
    (tenant_id,environment_id,kind,policy_ref,version,resource_local_ref,property,status,document,recorded_at,principal_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,
  [...params, document.resource_local_ref ?? null, document.property ?? null, status,
    JSON.stringify(document), recordedAt, trust.principal_id])
}

export async function statePolicyAt(client, trust, resource, property, instant) {
  const scope = [trust.tenant_id, trust.environment_id]
  const bindingRows = await client.query(`SELECT document,status FROM dubsar_context.state_policy_events
    WHERE tenant_id=$1 AND environment_id=$2 AND kind='binding' AND status='admitted'
      AND resource_local_ref=$3 AND property=$4 AND recorded_at <= $5
      AND (document->>'effective_at')::timestamptz <= $5
    ORDER BY recorded_at DESC,event_no DESC LIMIT 1`, [...scope, resource, property, instant])
  if (!bindingRows.rows.length) return { binding: null, mapping: null, rule: null }
  const b = bindingRows.rows[0]
  const binding = { ...b.document, status: b.status }
  const status = await client.query(`SELECT status FROM dubsar_context.state_policy_events
    WHERE tenant_id=$1 AND environment_id=$2 AND kind='binding' AND policy_ref=$3 AND version=$4 AND recorded_at <= $5
    ORDER BY recorded_at DESC,event_no DESC LIMIT 1`, [...scope, binding.binding_ref, binding.version, instant])
  binding.status = status.rows[0].status
  const policies = {}
  for (const kind of ['mapping', 'rule']) {
    const found = await client.query(`SELECT document,status FROM dubsar_context.state_policy_events
      WHERE tenant_id=$1 AND environment_id=$2 AND kind=$3 AND policy_ref=$4 AND version=$5 AND recorded_at <= $6
      ORDER BY recorded_at DESC,event_no DESC LIMIT 1`,
    [...scope, kind, binding[`${kind}_ref`], binding[`${kind}_version`], instant])
    policies[kind] = found.rows[0] ? { ...found.rows[0].document, status: found.rows[0].status } : null
  }
  return { binding, ...policies }
}

// Recognize only selected supports that matched the admitted policy at receipt.
// All lateral lookups return at most one event; the result is bounded by the
// caller's existing support window. No unbounded generation history is loaded.
export async function supersededStateSupports(client, trust, observations, binding, instant) {
  if (!binding || binding.status !== 'admitted' || observations.length === 0) return []
  if (observations.length > OC_BOUNDS.max_observations_examined) {
    throw ocError('OC_BOUND_EXCEEDED', 'state history exceeds the support window')
  }
  const refs = observations.filter(row => row.document.contract === 'dubsar.operational-context.observation/2'
    && !matchesStateGeneration(row, binding)).map(row => row.local_ref)
  if (refs.length === 0) return []
  const result = await client.query(`SELECT o.local_ref
    FROM dubsar_context.observations o
    JOIN LATERAL (
      SELECT e.document,e.policy_ref,e.version FROM dubsar_context.state_policy_events e
      WHERE e.tenant_id=o.tenant_id AND e.environment_id=o.environment_id
        AND e.kind='binding' AND e.status='admitted'
        AND e.resource_local_ref=o.resource_local_ref AND e.property=o.property
        AND e.recorded_at <= o.received_at
        AND (e.document->>'effective_at')::timestamptz <= o.received_at
      ORDER BY e.recorded_at DESC,e.event_no DESC LIMIT 1
    ) b ON true
    JOIN LATERAL (
      SELECT e.status FROM dubsar_context.state_policy_events e
      WHERE e.tenant_id=o.tenant_id AND e.environment_id=o.environment_id
        AND e.kind='binding' AND e.policy_ref=b.policy_ref AND e.version=b.version
        AND e.recorded_at <= o.received_at
      ORDER BY e.recorded_at DESC,e.event_no DESC LIMIT 1
    ) bs ON bs.status='admitted'
    JOIN LATERAL (
      SELECT e.status FROM dubsar_context.state_policy_events e
      WHERE e.tenant_id=o.tenant_id AND e.environment_id=o.environment_id
        AND e.kind='mapping' AND e.policy_ref=b.document->>'mapping_ref'
        AND e.version=(b.document->>'mapping_version')::integer AND e.recorded_at <= o.received_at
      ORDER BY e.recorded_at DESC,e.event_no DESC LIMIT 1
    ) ms ON ms.status='admitted'
    JOIN LATERAL (
      SELECT e.status FROM dubsar_context.state_policy_events e
      WHERE e.tenant_id=o.tenant_id AND e.environment_id=o.environment_id
        AND e.kind='rule' AND e.policy_ref=b.document->>'rule_ref'
        AND e.version=(b.document->>'rule_version')::integer AND e.recorded_at <= o.received_at
      ORDER BY e.recorded_at DESC,e.event_no DESC LIMIT 1
    ) rs ON rs.status='admitted'
    WHERE o.tenant_id=$1 AND o.environment_id=$2
      AND o.resource_local_ref=$3 AND o.property=$4 AND o.local_ref=ANY($5::text[])
      AND o.received_at <= $8
      AND (b.policy_ref,b.version) IS DISTINCT FROM ($6::text,$7::integer)
      AND o.document->>'contract'='dubsar.operational-context.observation/2'
      AND o.producer_id=b.document->>'producer_id'
      AND o.source_instance_id=b.document->>'source_instance_id'
      AND o.document->'state_order'->>'producer_epoch'=b.document->>'producer_epoch'
      AND o.document->'provenance'->>'producer_id'=b.document->>'producer_id'
      AND o.document->'subject'->>'source_instance_id'=b.document->>'source_instance_id'
      AND o.document->'provenance'->>'mapping_ref'=b.document->>'mapping_ref'
      AND (o.document->'provenance'->>'mapping_version')::integer=(b.document->>'mapping_version')::integer
      AND o.document->>'rule_ref'=b.document->>'rule_ref'
      AND (o.document->>'rule_version')::integer=(b.document->>'rule_version')::integer
    LIMIT $9`,
  [trust.tenant_id, trust.environment_id, binding.resource_local_ref, binding.property,
    refs, binding.binding_ref, binding.version, instant,
    OC_BOUNDS.max_observations_examined])
  return result.rows.map(row => row.local_ref)
}
