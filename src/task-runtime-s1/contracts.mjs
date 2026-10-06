// Contract-only S1 boundary. No admission, replay store, transport or authority.
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { canonicalJson, domainSeparatedHash } from '../canonical-json.mjs'
import {
  assertContract as assertV1Contract,
  bindTaskAuthorization as bindV1Authorization,
  hashRuntimeLock,
  hashTaskProfile as hashV1Profile,
  schemaRegistry as v1Registry,
} from '../contracts.mjs'
import { SchemaRegistry } from '../schema-validator.mjs'

const read = path => JSON.parse(fs.readFileSync(new URL(path, import.meta.url), 'utf8'))
const template = read('../../contracts/task-runtime-s1/probe-policy.json')
const request = read('../../contracts/task-runtime-s1/synthetic-request.json')
const registry = new SchemaRegistry(fileURLToPath(new URL('../../schemas/task-runtime-s1/', import.meta.url)))
// Resolve frozen v1 definitions locally without changing the v1 registry.
for (const document of v1Registry.documents.values()) {
  registry.identifiers.set(document.identifier, document)
  registry.identifiers.set(document.fileUrl, document)
}

export const S1_PROFILE_ID = 'dubsar.gateway.probe.v1'
export const S1_LEASE_SCHEMA = 'dubsar.task-lease.v2'
export const S1_RECEIPT_SCHEMA = 'dubsar.s1.egress-receipt.v1'
export const S1_DOMAINS = Object.freeze({
  request: 'dubsar.s1.gateway-request.v1',
  policy: 'dubsar.s1.egress-policy.v1',
  profile: 'dubsar.task-profile.v2',
  lease: 'dubsar.contract.task-lease.v2',
  receipt: 'dubsar.s1.egress-receipt.v1',
})
export const SYNTHETIC_REQUEST_DIGEST = domainSeparatedHash(S1_DOMAINS.request, request)
export const SYNTHETIC_REQUEST_BYTES = Buffer.byteLength(canonicalJson(request), 'utf8')

export class S1ContractError extends Error {
  constructor(code) {
    super(code)
    this.name = 'S1ContractError'
    this.code = code
  }
}
export function rejectS1(code) { throw new S1ContractError(code) }
const check = (condition, code) => { if (!condition) rejectS1(code) }
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const exact = (value, keys) => object(value) && same(Object.keys(value).sort(), [...keys].sort())
const digest = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value)
const same = (left, right) => {
  try { return canonicalJson(left) === canonicalJson(right) } catch { return false }
}
function schema(name, value, code) {
  try { check(registry.validate(name, value).length === 0, code) }
  catch (error) { if (error instanceof S1ContractError) throw error; rejectS1(code) }
}
function instant(value, code) {
  check(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value), code)
  const ms = Date.parse(value)
  check(Number.isFinite(ms) && new Date(ms).toISOString() === value, code)
  return ms
}

check(template.request_digest === SYNTHETIC_REQUEST_DIGEST, 'S1_CATALOGUE_INVALID')
export function closedS1Policy() { return structuredClone(template) }
export function syntheticS1Request() { return structuredClone(request) }
export function assertS1ReferencesClosed() { return registry.assertAllReferencesClosed() }

export function assertS1Policy(policy) {
  check(exact(policy, Object.keys(template)), 'S1_POLICY_SHAPE_INVALID')
  check(policy.schema === template.schema && policy.contract_version === template.contract_version
    && policy.policy_id === S1_PROFILE_ID, 'S1_POLICY_VERSION_INVALID')
  check(same(policy.destination, template.destination), 'S1_POLICY_DESTINATION_INVALID')
  check(same(policy.operation, template.operation), 'S1_POLICY_ROUTE_INVALID')
  check(same(policy.gateway_scope, template.gateway_scope), 'S1_POLICY_CONTEXT_INVALID')
  check(policy.request_digest === SYNTHETIC_REQUEST_DIGEST, 'S1_POLICY_REQUEST_DIGEST_MISMATCH')
  check(object(policy.bounds), 'S1_POLICY_BUDGET_INVALID')
  check(policy.bounds.window_seconds === 30 && policy.bounds.request_timeout_ms === 2000,
    'S1_POLICY_DURATION_INVALID')
  check(same(policy.bounds, template.bounds), 'S1_POLICY_BUDGET_INVALID')
  check(same(policy.protocol, template.protocol), 'S1_POLICY_PROTOCOL_INVALID')
  check(policy.authentication === template.authentication && policy.revocation === template.revocation,
    'S1_POLICY_CREDENTIAL_MODE_INVALID')
  schema('egress-policy.schema.json', policy, 'S1_POLICY_SHAPE_INVALID')
  return policy
}
export function hashS1Policy(policy) {
  return domainSeparatedHash(S1_DOMAINS.policy, assertS1Policy(policy))
}

// Trusted Core/Task Manager configuration only; never a requester-side builder.
export function createS1ClosedProfile(config) {
  check(exact(config, ['runtime_lock', 'input_digest', 'enforcer_digest']), 'S1_PROFILE_CONFIG_INVALID')
  check(digest(config.input_digest) && digest(config.enforcer_digest), 'S1_PROFILE_CONFIG_INVALID')
  try { hashRuntimeLock(config.runtime_lock) } catch { rejectS1('S1_RUNTIME_LOCK_INVALID') }
  const profile = {
    allowed_operations: ['collect', 'create', 'execute', 'inspect', 'terminate'],
    allowed_outputs: ['/workspace/out/result.json'],
    capabilities: { drop: ['ALL'], add: ['CHOWN', 'KILL', 'SETGID', 'SETUID'] },
    commands: { pilot: 'python3 /workspace/run_gateway_probe.py' },
    effect: 'none',
    entrypoint: ['timeout', '70', 'tail', '-f', '/dev/null'],
    filesystem: { rootfs_read_only: true, mounts: [
      { path: '/run', kind: 'tmpfs', size_bytes: 2097152, flags: ['nodev', 'noexec', 'nosuid'] },
      { path: '/tmp', kind: 'tmpfs', size_bytes: 8388608, flags: ['nodev', 'noexec', 'nosuid'] },
      { path: '/workspace', kind: 'tmpfs', size_bytes: 16777216, flags: ['nodev', 'nosuid'] },
    ] },
    identity: { uid: 65532, gid: 65532 },
    image: config.runtime_lock.task_image,
    input_digest: config.input_digest,
    input_root: '/workspace',
    limits: { cpu_millicores: 500, memory_bytes: 134217728, pids: 256, disk_bytes: 27262976,
      ttl_seconds: 60, command_timeout_ms: 20000, output_bytes: 1048576 },
    network: { policy: 'egress_mediated_gateway', enforcer_ref: 'dubsar.mediated.egress.v1',
      enforcer_digest: config.enforcer_digest, egress_policy: closedS1Policy() },
    output_root: '/workspace/out',
    profile_id: S1_PROFILE_ID,
    runtime_lock: structuredClone(config.runtime_lock),
  }
  return assertS1ClosedProfile(profile)
}
function v1Profile(profile) { return { ...profile, network: { policy: 'egress_none' } } }
export function assertS1ClosedProfile(profile) {
  assertS1Policy(profile?.network?.egress_policy)
  schema('closed-profile.schema.json', profile, 'S1_PROFILE_INVALID')
  try { hashV1Profile(v1Profile(profile)) } catch { rejectS1('S1_PROFILE_INVALID') }
  return profile
}
export function hashS1Profile(profile) {
  return domainSeparatedHash(S1_DOMAINS.profile, assertS1ClosedProfile(profile))
}
export function bindS1TaskAuthorization(profile) {
  assertS1ClosedProfile(profile)
  return {
    ...bindV1Authorization(v1Profile(profile)),
    network: structuredClone(profile.network),
    profile_digest: hashS1Profile(profile),
  }
}

// Structural/semantic validation is not admission or single-use consumption.
export function assertS1TaskLease(lease) {
  check(lease?.schema === S1_LEASE_SCHEMA && lease?.contract_version === '2.0.0', 'S1_LEASE_VERSION_INVALID')
  assertS1Policy(lease?.task?.network?.egress_policy)
  schema('task-lease.schema.json', lease, 'S1_LEASE_INVALID')
  const issued = instant(lease.issued_at, 'S1_LEASE_TEMPORAL_INVALID')
  const notBefore = instant(lease.not_before, 'S1_LEASE_TEMPORAL_INVALID')
  const expires = instant(lease.expires_at, 'S1_LEASE_TEMPORAL_INVALID')
  check(issued <= notBefore && notBefore < expires && expires - notBefore <= 300000
    && notBefore - issued <= 5000 && [issued, notBefore, expires].every(ms => ms % 1000 === 0),
  'S1_LEASE_TEMPORAL_INVALID')
  try {
    assertV1Contract('task-lease', {
      ...lease, schema: 'dubsar.task-lease.v1', contract_version: '1.0.0',
      task: { ...lease.task, network: { policy: 'egress_none' } },
    })
  } catch { rejectS1('S1_LEASE_INVARIANT_INVALID') }
  return lease
}
export function assertS1LeaseBinding(lease, closedProfile) {
  assertS1TaskLease(lease)
  check(closedProfile !== undefined && closedProfile !== null, 'S1_CLOSED_PROFILE_REQUIRED')
  check(same(lease.task, bindS1TaskAuthorization(closedProfile)), 'S1_LEASE_PROFILE_MISMATCH')
  return lease
}
export function hashS1TaskLease(lease) {
  return domainSeparatedHash(S1_DOMAINS.lease, assertS1TaskLease(lease))
}

const observationSources = Object.freeze({
  MEDIATOR_POLICY_READBACK: 'MEDIATOR',
  NETWORK_FENCE_READBACK: 'HOST_ENFORCER',
  GATEWAY_PEER: 'MEDIATOR',
  BYPASS_PROBES: 'QUALIFIER',
})
function assertEnforcement(receipt) {
  const proof = receipt.enforcement
  check(object(proof), 'S1_ENFORCEMENT_NOT_PROVEN')
  check(object(receipt.window) && object(receipt.operation), 'S1_RECEIPT_INVALID')
  // This contract-only lot has no trust verifier. Metadata cannot acquire proof.
  check(proof.proof_acquired === false, 'S1_ENFORCEMENT_PROOF_UNAVAILABLE')
  check(proof.policy_applied === false, 'S1_ENFORCEMENT_NOT_PROVEN')
  if (proof.level === 'DECLARED_ONLY') {
    check(receipt.effective_policy !== null && proof.observations_status === 'STRUCTURALLY_VALID'
      && Array.isArray(proof.declared_observations) && proof.declared_observations.length === 4,
    'S1_ENFORCEMENT_NOT_PROVEN')
    check(proof.declared_observations.every(o => object(o) && typeof o.kind === 'string'
      && typeof o.source === 'string'), 'S1_ENFORCEMENT_NOT_PROVEN')
    const kinds = proof.declared_observations.map(o => o.kind)
    check(same([...kinds].sort(), Object.keys(observationSources).sort()), 'S1_ENFORCEMENT_NOT_PROVEN')
    const created = instant(receipt.window.sandbox_created_at, 'S1_ENFORCEMENT_TIME_INVALID')
    const bound = instant(receipt.operation.started_at ?? receipt.recorded_at, 'S1_ENFORCEMENT_TIME_INVALID')
    for (const observation of proof.declared_observations) {
      check(observation.source === observationSources[observation.kind]
        && observation.lease_digest === receipt.lease_digest
        && observation.effective_policy_digest === receipt.effective_policy_digest
        && observation.sandbox_id === receipt.sandbox_id && observation.session_id === receipt.session_id,
      'S1_ENFORCEMENT_BINDING_MISMATCH')
      const at = instant(observation.observed_at, 'S1_ENFORCEMENT_TIME_INVALID')
      check(at >= created && at <= bound, 'S1_ENFORCEMENT_TIME_INVALID')
    }
  } else {
    check(proof.observations_status === 'NONE' && Array.isArray(proof.declared_observations)
      && proof.declared_observations.length === 0, 'S1_ENFORCEMENT_NOT_PROVEN')
    check(proof.level === 'MODEL_ONLY' || proof.level === 'NOT_PROVEN', 'S1_ENFORCEMENT_NOT_PROVEN')
  }
  if (proof.level === 'MODEL_ONLY') {
    check(receipt.operation.result === 'SIMULATED' && receipt.effective_policy !== null,
    'S1_RECEIPT_RESULT_INVALID')
  }
  if (proof.level === 'NOT_PROVEN') {
    check(receipt.effective_policy === null && receipt.operation.result === 'DENIED',
      'S1_ENFORCEMENT_NOT_PROVEN')
  }
}

export function assertS1EgressReceipt(receipt, context) {
  check(exact(context, ['lease', 'closed_profile', 'policy_digest']) && digest(context.policy_digest),
    'S1_RECEIPT_CONTEXT_REQUIRED')
  const lease = assertS1LeaseBinding(context.lease, context.closed_profile)
  check(receipt?.schema === S1_RECEIPT_SCHEMA && receipt?.contract_version === '1.0.0',
    'S1_RECEIPT_VERSION_INVALID')
  assertS1Policy(receipt.requested_policy)
  check(same(receipt.requested_policy, lease.task.network.egress_policy)
    && receipt.requested_policy_digest === hashS1Policy(receipt.requested_policy),
  'S1_REQUESTED_POLICY_MISMATCH')
  if (receipt.effective_policy !== null) {
    check(same(receipt.effective_policy, receipt.requested_policy), 'S1_EFFECTIVE_POLICY_MISMATCH')
    check(receipt.effective_policy_digest === hashS1Policy(receipt.effective_policy),
      'S1_EFFECTIVE_POLICY_DIGEST_MISMATCH')
  } else {
    check(receipt.effective_policy_digest === null, 'S1_EFFECTIVE_POLICY_DIGEST_MISMATCH')
  }
  // Check the application claim before generic shape errors for deterministic refusal.
  assertEnforcement(receipt)
  schema('egress-receipt.schema.json', receipt, 'S1_RECEIPT_INVALID')
  for (const field of ['lease_id', 'task_id', 'action_id', 'tenant_id', 'mission_id', 'evidence_correlation_id']) {
    check(receipt[field] === lease[field], 'S1_RECEIPT_BINDING_MISMATCH')
  }
  check(receipt.lease_digest === hashS1TaskLease(lease) && receipt.policy_digest === context.policy_digest
    && receipt.profile_digest === lease.task.profile_digest
    && receipt.runtime_lock_digest === lease.task.runtime_lock_digest, 'S1_RECEIPT_BINDING_MISMATCH')
  check(same(receipt.destination, receipt.requested_policy.destination)
    && same(receipt.route, receipt.requested_policy.operation), 'S1_RECEIPT_DESTINATION_MISMATCH')

  const timeCode = 'S1_RECEIPT_TEMPORAL_INVALID'
  const recorded = instant(receipt.recorded_at, timeCode)
  const created = instant(receipt.window.sandbox_created_at, timeCode)
  // An authorization boundary, not a claim that activation actually occurred.
  const notBefore = instant(receipt.window.not_before, timeCode)
  const expires = instant(receipt.window.expires_at, timeCode)
  check(created >= Date.parse(lease.not_before) && notBefore >= created && recorded >= created
    && notBefore < expires && expires === Math.min(Date.parse(lease.expires_at),
      created + lease.task.limits.ttl_seconds * 1000, notBefore + 30000), timeCode)
  const op = receipt.operation
  let start
  if (op.result === 'DENIED') {
    // The refusal is dated by recorded_at. There was no operation to timestamp.
    check(op.attempts === 0 && op.forwarded === false && op.request_bytes === 0
      && op.response_bytes === 0 && op.response_digest === null && op.generation_tokens === null
      && op.gateway_receipt_ref === null && op.started_at === null && op.finished_at === null
      && op.duration_ms === null, 'S1_RECEIPT_RESULT_INVALID')
  } else {
    start = instant(op.started_at, timeCode)
    const finish = instant(op.finished_at, timeCode)
    check(start >= notBefore && start < expires && finish >= start && finish <= expires
      && finish - start <= 2000 && op.duration_ms === finish - start && recorded >= finish, timeCode)
  }
  if (receipt.window.revoked_at !== null) {
    const revoked = instant(receipt.window.revoked_at, timeCode)
    check(revoked >= Date.parse(lease.issued_at) && revoked <= expires && revoked <= recorded, timeCode)
    check(op.result !== 'SUCCEEDED' && (op.result === 'DENIED' || start < revoked),
      'S1_RECEIPT_REVOCATION_INVALID')
  }
  check(op.request_digest === SYNTHETIC_REQUEST_DIGEST, 'S1_RECEIPT_REQUEST_DIGEST_MISMATCH')
  check(op.attempts <= 1 && op.request_bytes <= 4096 && op.response_bytes <= 16384
    && (op.generation_tokens === null || op.generation_tokens <= 128), 'S1_RECEIPT_BUDGET_INVALID')
  if (op.attempts === 1) check(op.request_bytes === SYNTHETIC_REQUEST_BYTES, 'S1_RECEIPT_BUDGET_INVALID')
  if (op.attempts === 0) check(op.request_bytes === 0 && op.response_bytes === 0
    && op.response_digest === null && op.generation_tokens === null && op.forwarded === false
    && op.gateway_receipt_ref === null, 'S1_RECEIPT_RESULT_INVALID')
  check((op.response_bytes === 0) === (op.response_digest === null), 'S1_RECEIPT_RESULT_INVALID')
  if (op.response_bytes === 0) check(op.generation_tokens === null, 'S1_RECEIPT_RESULT_INVALID')
  if (op.forwarded || op.gateway_receipt_ref !== null) rejectS1('S1_ENFORCEMENT_PROOF_UNAVAILABLE')
  if (op.result === 'SIMULATED') {
    check(['MODEL_ONLY', 'DECLARED_ONLY'].includes(receipt.enforcement.level) && op.attempts === 1
      && op.response_bytes > 0 && op.response_digest !== null && op.generation_tokens !== null,
    'S1_RECEIPT_RESULT_INVALID')
  } else if (op.result !== 'DENIED') {
    // Runtime outcomes require trust verification, which this lot does not provide.
    rejectS1('S1_ENFORCEMENT_PROOF_UNAVAILABLE')
  }
  return receipt
}
export function hashS1EgressReceipt(receipt, context) {
  return domainSeparatedHash(S1_DOMAINS.receipt, assertS1EgressReceipt(receipt, context))
}
