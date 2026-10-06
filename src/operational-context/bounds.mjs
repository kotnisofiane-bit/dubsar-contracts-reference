/** Laboratory V0 bounds. Not a B2B SLO. */
export const OC_BOUNDS = Object.freeze({
  observation_utf8_bytes: 64 * 1024,
  max_resources_per_call: 20,
  max_relation_depth: 1,
  max_observations_examined: 200,
  max_response_utf8_bytes: 256 * 1024,
  sql_statement_timeout_ms: 5000,
  identifier_max_length: 256,
  identifier_min_length: 1,
})

export const OC_CONTRACTS = Object.freeze({
  observation: 'dubsar.operational-context.observation/1',
  resource: 'dubsar.operational-context.resource/1',
  association: 'dubsar.operational-context.association/1',
  qualification: 'dubsar.operational-context.qualification/1',
  viewRequest: 'dubsar.operational-context.view-request/1',
  view: 'dubsar.operational-context.view/1',
  mapping: 'dubsar.operational-context.mapping/1',
  rule: 'dubsar.operational-context.rule/1',
  ingestResult: 'dubsar.operational-context.ingest-result/1',
  trust: 'dubsar.operational-context.trust/1',
})

export const OC_HASH_DOMAINS = Object.freeze({
  resource: 'dubsar.oc.resource.v1',
  observation: 'dubsar.oc.observation.v1',
  pair: 'dubsar.oc.pair.v1',
  qualification: 'dubsar.oc.qualify.v1',
  view: 'dubsar.oc.view.v1',
})
