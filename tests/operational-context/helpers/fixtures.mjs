export function resource(overrides = {}) {
  return {
    contract: 'dubsar.operational-context.resource/1',
    tenant_id: 'tenant:lab',
    environment_id: 'env:test',
    source_instance_id: 'src:n8n-a',
    namespace: 'workflow',
    type: 'workflow',
    source_id: 'export-commandes',
    incarnation: { absence: 'not_available' },
    label: 'export commandes',
    ...overrides,
  }
}

export function trust(overrides = {}) {
  return {
    contract: 'dubsar.operational-context.trust/1',
    tenant_id: 'tenant:lab',
    environment_id: 'env:test',
    principal_id: 'principal:ops',
    principal_kind: 'human',
    ...overrides,
  }
}

export function period(start = '2026-09-18T08:00:00Z', end = '2026-09-18T12:00:00Z') {
  return { start, end }
}

export function observation(overrides = {}) {
  const subject = overrides.subject ?? resource()
  const { subject: _ignored, ...rest } = overrides
  return {
    contract: 'dubsar.operational-context.observation/1',
    delivery_id: 'delivery:a-1',
    measurement_id: { absence: 'not_provided' },
    subject,
    property: 'enabled',
    result: { kind: 'measured', value_type: 'boolean', value: true },
    provenance: {
      producer_id: 'producer:a',
      connector_revision: 'connector:1',
      mapping_ref: 'map:enabled',
      mapping_version: 1,
    },
    source_observed_at: '2026-09-18T09:00:00Z',
    scope: { period: period(), complete: true },
    rule_ref: 'rule:fresh',
    rule_version: 1,
    ...rest,
  }
}

export function mapping(overrides = {}) {
  return {
    contract: 'dubsar.operational-context.mapping/1',
    mapping_ref: 'map:enabled',
    version: 1,
    property: 'enabled',
    value_type: 'boolean',
    comparable_source_instances: ['src:n8n-a', 'src:n8n-b'],
    ...overrides,
  }
}

export function rule(overrides = {}) {
  return {
    contract: 'dubsar.operational-context.rule/1',
    rule_ref: 'rule:fresh',
    version: 1,
    freshness_max_age_ms: 3_600_000,
    ...overrides,
  }
}

export function association(left, right, type = 'same_resource') {
  return {
    contract: 'dubsar.operational-context.association/1',
    association_type: type,
    left,
    right,
  }
}

export function viewRequest(resources, extra = {}) {
  return {
    contract: 'dubsar.operational-context.view-request/1',
    resources,
    relation_depth: 0,
    ...extra,
  }
}
