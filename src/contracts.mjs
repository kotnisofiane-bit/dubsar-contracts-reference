import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalJson, domainSeparatedHash } from './canonical-json.mjs'
import { SchemaRegistry } from './schema-validator.mjs'
import { assertTransitionAllowed } from './state-machine.mjs'

const schemaDirectory = fileURLToPath(new URL('../schemas/v1/', import.meta.url))
const contractSet = JSON.parse(fs.readFileSync(new URL('../contracts/v1/contract-set.json', import.meta.url), 'utf8'))

export const schemaRegistry = new SchemaRegistry(schemaDirectory)
export const CONTRACT_KINDS = Object.freeze(contractSet.contracts.map(entry => entry.name))
export const CONTRACT_SET = Object.freeze(contractSet)

const metadataByKind = new Map(contractSet.contracts.map(entry => [entry.name, entry]))
const semanticValidators = new Map([
  ['action-proposal', validateActionProposal],
  ['action-receipt', validateActionReceipt],
  ['approval-record', validateApprovalRecord],
  ['capability-claims', validateCapabilityClaims],
  ['execution-lease', validateExecutionLease],
  ['state-transition', validateStateTransition],
  ['task-lease', validateTaskLease],
  ['workflow-ir', validateWorkflowIr],
])

const TASK_LEASE_MAX_VALIDITY_MS = 300000

export function validateContract(kind, value) {
  const metadata = metadataFor(kind)
  const schemaErrors = schemaRegistry.validate(path.basename(metadata.schema_path), value)
  const errors = [...schemaErrors]
  errors.push(...secretMaterialErrors(value))
  if (schemaErrors.length === 0) {
    try {
      semanticValidators.get(kind)(value)
    } catch (error) {
      errors.push(error instanceof Error ? error.message : 'semantic validation failed')
    }
  }
  return errors
}

export function assertContract(kind, value) {
  const errors = validateContract(kind, value)
  if (errors.length > 0) throw new Error(`${kind} rejected: ${errors.slice(0, 12).join('; ')}`)
  return value
}

export function hashContract(kind, value) {
  assertContract(kind, value)
  return domainSeparatedHash(metadataFor(kind).domain_separator, value)
}

export function hashPayload(value) {
  const errors = secretMaterialErrors(value)
  if (errors.length > 0) throw new Error(`payload rejected: ${errors.join('; ')}`)
  return domainSeparatedHash('dubsar.payload.v1', value)
}

const RUNTIME_LOCK_KEYS = Object.freeze(['adapter_image', 'execd_image', 'opensandbox_commit', 'server_image', 'task_image'])
const TASK_PROFILE_KEYS = Object.freeze([
  'allowed_operations',
  'allowed_outputs',
  'capabilities',
  'commands',
  'effect',
  'entrypoint',
  'filesystem',
  'identity',
  'image',
  'input_digest',
  'input_root',
  'limits',
  'network',
  'output_root',
  'profile_id',
  'runtime_lock',
])
const TASK_AUTHORIZATION_KEYS = Object.freeze([
  'allowed_operations',
  'capabilities',
  'effect',
  'filesystem',
  'identity',
  'input_digest',
  'limits',
  'network',
  'profile_id',
])
const DIGEST = /^sha256:[a-f0-9]{64}$/
const GIT_COMMIT = /^[a-f0-9]{40}$/
const PROFILE_ID = /^[a-z][a-z0-9]*(?:\.[a-z0-9]+)*\.v(?:0|[1-9][0-9]*)$/
const OUTPUT_PATH = /^\/workspace\/out\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const COMMAND_NAME = /^[a-z][a-z0-9_]{1,63}$/

export function hashRuntimeLock(lock) {
  assertRuntimeLock(lock)
  return domainSeparatedHash('dubsar.runtime-lock.v1', lock)
}

export function hashTaskProfile(profile) {
  assertTaskProfile(profile)
  return domainSeparatedHash('dubsar.task-profile.v1', profile)
}

export function bindTaskAuthorization(closedProfile) {
  assertTaskProfile(closedProfile)
  return {
    profile_id: closedProfile.profile_id,
    effect: closedProfile.effect,
    input_digest: closedProfile.input_digest,
    runtime_lock_digest: hashRuntimeLock(closedProfile.runtime_lock),
    profile_digest: hashTaskProfile(closedProfile),
    limits: structuredClone(closedProfile.limits),
    identity: structuredClone(closedProfile.identity),
    filesystem: structuredClone(closedProfile.filesystem),
    capabilities: structuredClone(closedProfile.capabilities),
    network: structuredClone(closedProfile.network),
    allowed_operations: structuredClone(closedProfile.allowed_operations),
  }
}

export function assertTaskLeaseReplayStore(store) {
  if (typeof store?.consumeOnce !== 'function') {
    throw new TypeError('task lease replay store is required')
  }
  return store
}

export function assertApprovalCurrent(approval, workflow, now = new Date()) {
  assertContract('approval-record', approval)
  assertContract('workflow-ir', workflow)
  const digest = hashContract('workflow-ir', workflow)
  if (approval.workflow.workflow_id !== workflow.workflow_id
    || approval.workflow.workflow_version !== workflow.workflow_version
    || approval.workflow.workflow_digest !== digest) {
    throw new Error('approval does not bind the current workflow digest and version')
  }
  const instant = toInstant(now)
  if (approval.revoked_at !== null) throw new Error('approval is revoked')
  if (instant < Date.parse(approval.issued_at)) throw new Error('approval is not yet valid')
  if (instant >= Date.parse(approval.expires_at)) throw new Error('approval is expired')
  return true
}

export function consumeExecutionLease(lease, expected, replayCache, now = new Date()) {
  assertContract('execution-lease', lease)
  assertSet(replayCache, 'execution lease replay cache')
  const instant = toInstant(now)
  if (instant < Date.parse(lease.not_before)) throw new Error('execution lease is not yet valid')
  if (instant >= Date.parse(lease.expires_at)) throw new Error('execution lease is expired')
  compareExact(lease.run_id, expected.run_id, 'execution lease run')
  compareExact(lease.step_id, expected.step_id, 'execution lease step')
  compareExact(lease.workflow.workflow_id, expected.workflow_id, 'execution lease workflow id')
  compareExact(lease.workflow.workflow_version, expected.workflow_version, 'execution lease workflow version')
  compareExact(lease.workflow.workflow_digest, expected.workflow_digest, 'execution lease workflow digest')
  compareExact(lease.approval_id, expected.approval_id, 'execution lease approval')
  compareExact(lease.worker.workload_id, expected.worker.workload_id, 'execution lease workload')
  compareExact(lease.worker.instance_id, expected.worker.instance_id, 'execution lease instance')
  compareExact(canonicalJson(lease.expected_action), canonicalJson(expected.expected_action), 'execution lease expected action')
  const replayIdentity = `${lease.replay_protection.replay_key}:${lease.nonce}`
  if (replayCache.has(replayIdentity)) throw new Error('execution lease replay detected')
  replayCache.add(replayIdentity)
  return true
}

export async function consumeTaskLease(lease, expected, replayStore, now = new Date()) {
  assertContract('task-lease', lease)
  assertTaskLeaseReplayStore(replayStore)
  if (!isPlainObject(expected) || !isPlainObject(expected.task_manager)) {
    throw new TypeError('task lease expectation must bind a task manager identity')
  }
  if (!isPlainObject(expected.closedProfile)) {
    throw new TypeError('task lease closed profile is required')
  }
  let boundTask
  try {
    boundTask = bindTaskAuthorization(expected.closedProfile)
  } catch (error) {
    throw new Error(`task lease closed profile is invalid: ${error instanceof Error ? error.message : 'rejected'}`)
  }
  const instant = toInstant(now)
  if (instant < Date.parse(lease.not_before)) throw new Error('task lease is not yet valid')
  if (instant >= Date.parse(lease.expires_at)) throw new Error('task lease is expired')
  compareExact(lease.task_id, expected.task_id, 'task lease task')
  compareExact(lease.action_id, expected.action_id, 'task lease action')
  compareExact(lease.tenant_id, expected.tenant_id, 'task lease tenant')
  compareExact(lease.mission_id, expected.mission_id, 'task lease mission')
  compareExact(lease.task_manager.workload_id, expected.task_manager.workload_id, 'task lease workload')
  compareExact(lease.task_manager.instance_id, expected.task_manager.instance_id, 'task lease instance')
  compareExact(canonicalJson(lease.task), canonicalJson(boundTask), 'task lease closed profile')
  const replayIdentity = `${lease.replay_protection.replay_key}:${lease.nonce}`
  const consumed = await replayStore.consumeOnce(replayIdentity, lease.expires_at)
  if (consumed !== true) {
    throw new Error('task lease replay detected')
  }
  return true
}

export function taskLeaseAllows(lease, operation) {
  assertContract('task-lease', lease)
  return typeof operation === 'string' && lease.task.allowed_operations.includes(operation)
}

export function consumeCapabilityClaims(claims, proposal, expectedWorkloadId, usedJtis, now = new Date()) {
  assertSet(usedJtis, 'capability replay cache')
  assertCapabilityClaimsBound(claims, proposal, expectedWorkloadId, now)
  if (usedJtis.has(claims.jti)) throw new Error('capability replay detected')
  usedJtis.add(claims.jti)
  return true
}

export function assertCapabilityClaimsBound(claims, proposal, expectedWorkloadId, now = new Date()) {
  assertContract('capability-claims', claims)
  assertContract('action-proposal', proposal)
  const instant = toInstant(now)
  if (instant < Date.parse(claims.not_before)) throw new Error('capability is not yet valid')
  if (instant >= Date.parse(claims.expires_at)) throw new Error('capability is expired')
  if (claims.revoked_at !== null) throw new Error('capability is revoked')
  compareExact(claims.subject_workload_id, expectedWorkloadId, 'capability workload')
  compareExact(claims.subject_workload_id, proposal.workload_identity.workload_id, 'proposal workload')
  compareExact(claims.run_id, proposal.run_id, 'capability run')
  compareExact(claims.step_id, proposal.step_id, 'capability step')
  compareExact(claims.workflow_id, proposal.workflow_id, 'capability workflow id')
  compareExact(claims.workflow_digest, proposal.workflow_digest, 'capability workflow digest')
  compareExact(claims.approval_id, proposal.approval_id, 'capability approval')
  compareExact(claims.proposal_id, proposal.proposal_id, 'capability proposal')
  compareExact(canonicalJson(claims.action), canonicalJson(proposal.action), 'capability action')
  compareExact(claims.connection_ref, proposal.connection_ref, 'capability connection reference')
  compareExact(claims.payload_digest, proposalPayloadDigest(proposal), 'capability payload digest')
  if (claims.destinations.length !== 1 || canonicalJson(claims.destinations[0]) !== canonicalJson(proposal.destination)) {
    throw new Error('capability destination does not exactly bind the proposal')
  }
  return true
}

export function proposalPayloadDigest(proposal) {
  assertContract('action-proposal', proposal)
  return Object.hasOwn(proposal, 'payload') ? hashPayload(proposal.payload) : proposal.payload_digest
}

export function receiptEvidenceDigest(receipt) {
  if (!isPlainObject(receipt) || !isPlainObject(receipt.evidence_chain)) {
    throw new TypeError('action receipt evidence chain is missing')
  }
  const preimage = structuredClone(receipt)
  delete preimage.evidence_chain.event_digest
  return domainSeparatedHash('dubsar.evidence.action-receipt.v1', preimage)
}

export function assertNoSecretMaterial(value) {
  const errors = secretMaterialErrors(value)
  if (errors.length > 0) throw new Error(errors.join('; '))
}

function validateWorkflowIr(workflow) {
  assertSequentialOrder(workflow.nodes, 'workflow nodes')
  assertSequentialOrder(workflow.transitions, 'workflow transitions')
  assertUnique(workflow.nodes.map(node => node.node_id), 'workflow node ids')
  assertUnique(workflow.transitions.map(edge => edge.transition_id), 'workflow transition ids')
  const nodes = new Map(workflow.nodes.map(node => [node.node_id, node]))
  const entry = nodes.get(workflow.entry_node_id)
  if (entry === undefined || entry.kind !== 'trigger') throw new Error('workflow entry must reference a trigger node')
  if (workflow.nodes.filter(node => node.kind === 'trigger').length !== 1) throw new Error('workflow must have exactly one trigger')
  const templateIds = []
  for (const node of workflow.nodes) {
    if (!isPlainObject(node.parameters)) throw new Error(`node ${node.node_id} parameters must be an object`)
    assertSortedUnique(node.templates.map(template => template.template_id), `node ${node.node_id} template ids`)
    templateIds.push(...node.templates.map(template => template.template_id))
  }
  assertUnique(templateIds, 'workflow template ids')
  const templateSet = new Set(templateIds)
  for (const edge of workflow.transitions) {
    if (!nodes.has(edge.from_node_id) || !nodes.has(edge.to_node_id)) throw new Error('workflow transition references an unknown node')
    if (edge.from_node_id === edge.to_node_id) throw new Error('workflow self-transition is not admitted')
    if (edge.condition.kind === 'always' && edge.condition.template_ref !== null) throw new Error('always transition cannot reference a template')
    if (edge.condition.kind === 'template' && !templateSet.has(edge.condition.template_ref)) throw new Error('template transition references an unknown template')
  }
  const reachable = new Set([workflow.entry_node_id])
  let changed = true
  while (changed) {
    changed = false
    for (const edge of workflow.transitions) {
      if (reachable.has(edge.from_node_id) && !reachable.has(edge.to_node_id)) {
        reachable.add(edge.to_node_id)
        changed = true
      }
    }
  }
  if (reachable.size !== workflow.nodes.length) throw new Error('workflow contains a node unreachable from its entry')
}

function validateApprovalRecord(approval) {
  assertBefore(approval.issued_at, approval.expires_at, 'approval')
  if ((approval.revoked_at === null) !== (approval.revocation_reason === null)) {
    throw new Error('approval revocation timestamp and reason must be present together')
  }
  if (approval.revoked_at !== null && Date.parse(approval.revoked_at) < Date.parse(approval.issued_at)) {
    throw new Error('approval revocation precedes issuance')
  }
  if (Date.parse(approval.policy_evaluation.evaluated_at) > Date.parse(approval.issued_at)) {
    throw new Error('approval policy evaluation follows issuance')
  }
  assertSortedUnique(approval.scope.node_ids, 'approval node scope')
  assertSortedUnique(approval.scope.connection_refs, 'approval connection scope')
  assertCanonicalOrder(approval.scope.destinations, 'approval destination scope')
}

function validateExecutionLease(lease) {
  assertChronology(lease.issued_at, lease.not_before, 'execution lease issuance')
  assertBefore(lease.not_before, lease.expires_at, 'execution lease validity')
  if (Date.parse(lease.expires_at) - Date.parse(lease.not_before) > 300000) {
    throw new Error('execution lease validity exceeds 300 seconds')
  }
}

function validateTaskLease(lease) {
  assertChronology(lease.issued_at, lease.not_before, 'task lease issuance')
  assertBefore(lease.not_before, lease.expires_at, 'task lease validity')
  const validityMs = Date.parse(lease.expires_at) - Date.parse(lease.not_before)
  if (validityMs > TASK_LEASE_MAX_VALIDITY_MS) throw new Error('task lease validity exceeds 300 seconds')
  const { limits, filesystem, capabilities, allowed_operations: operations } = lease.task
  if (limits.ttl_seconds * 1000 > validityMs) throw new Error('task lease sandbox ttl exceeds the lease validity')
  if (limits.command_timeout_ms > limits.ttl_seconds * 1000) throw new Error('task lease command timeout exceeds the sandbox ttl')
  assertSortedUnique(operations, 'task lease allowed operations')
  assertAdmittedMounts(filesystem.mounts, 'task lease')
  const mountedBytes = filesystem.mounts.reduce((total, mount) => total + mount.size_bytes, 0)
  if (mountedBytes > limits.disk_bytes) throw new Error('task lease mounted bytes exceed the disk limit')
  assertSortedUnique(capabilities.add, 'task lease added capabilities')
}

function assertAdmittedMounts(mounts, label) {
  if (!Array.isArray(mounts)) throw new Error(`${label} mounts are invalid`)
  const canonicalPaths = mounts.map(mount => {
    if (!isPlainObject(mount) || typeof mount.path !== 'string' || !Array.isArray(mount.flags)) {
      throw new Error(`${label} mount is invalid`)
    }
    const canonicalPath = canonicalizeBoundedMountPath(mount.path)
    assertSortedUnique(mount.flags, `${label} mount ${canonicalPath} flags`)
    if (!mount.flags.includes('nodev') || !mount.flags.includes('nosuid')) {
      throw new Error(`${label} mount ${canonicalPath} must drop device and setuid`)
    }
    return canonicalPath
  })
  assertSortedUnique(canonicalPaths, `${label} mount paths`)
}

const MOUNT_SEGMENT = /^[a-z0-9][a-z0-9_-]*$/
const ADMITTED_MOUNT_PATHS = new Set(['/run', '/tmp', '/workspace'])

function canonicalizeBoundedMountPath(rawPath) {
  if (typeof rawPath !== 'string' || rawPath.length < 2 || rawPath.length > 255) {
    throw new Error('task mount path is not canonical')
  }
  if (rawPath.includes('\0') || rawPath.includes('\\')) {
    throw new Error('task mount path is not canonical')
  }
  if (path.posix.normalize(rawPath) !== rawPath) {
    throw new Error('task mount path is not canonical')
  }
  const segments = rawPath.split('/')
  if (segments[0] !== '' || segments.length < 2) {
    throw new Error('task mount path is not canonical')
  }
  for (const segment of segments.slice(1)) {
    if (segment.length === 0 || segment === '.' || segment === '..' || !MOUNT_SEGMENT.test(segment)) {
      throw new Error('task mount path is not canonical')
    }
  }
  if (isForbiddenMountPath(rawPath)) {
    throw new Error(`task lease mount ${rawPath} is not admitted`)
  }
  return rawPath
}

function isForbiddenMountPath(mountPath) {
  return mountPath.includes('docker.sock') || !ADMITTED_MOUNT_PATHS.has(mountPath)
}

function validateActionProposal(proposal) {
  if (Object.hasOwn(proposal, 'payload') && !isPlainObject(proposal.payload)) {
    throw new Error('action proposal payload must be an object')
  }
}

function validateCapabilityClaims(claims) {
  assertChronology(claims.issued_at, claims.not_before, 'capability issuance')
  assertBefore(claims.not_before, claims.expires_at, 'capability validity')
  if (Date.parse(claims.expires_at) - Date.parse(claims.not_before) > 120000) {
    throw new Error('capability validity exceeds 120 seconds')
  }
  if (claims.revoked_at !== null && Date.parse(claims.revoked_at) < Date.parse(claims.issued_at)) {
    throw new Error('capability revocation precedes issuance')
  }
  if (claims.bounds.max_attempts !== 1) throw new Error('single-use capability must allow exactly one attempt')
  assertCanonicalOrder(claims.destinations, 'capability destinations')
  if (canonicalJson(claims.bounds.allowed_destinations) !== canonicalJson(claims.destinations)) {
    throw new Error('capability bound destinations must equal its destination claims')
  }
}

function validateActionReceipt(receipt) {
  assertTransitionAllowed(receipt.before_state, receipt.after_state)
  if (receipt.before_state !== 'IN_FLIGHT' && receipt.before_state !== 'INDETERMINATE') {
    throw new Error('action receipt must record an execution or reconciliation outcome')
  }
  const successState = receipt.after_state === 'SUCCEEDED' || receipt.after_state === 'RECONCILED_SUCCEEDED'
  if (successState !== (receipt.result.kind === 'success')) {
    throw new Error('action receipt result kind does not match its resulting state')
  }
  if (receipt.after_state === 'FAILED_RETRYABLE' && receipt.result.error.retryable !== true) {
    throw new Error('retryable failure receipt must carry a retryable sanitized error')
  }
  if ((receipt.after_state === 'FAILED_FINAL' || receipt.after_state === 'RECONCILED_FAILED')
    && receipt.result.error.retryable !== false) {
    throw new Error('final failure receipt cannot carry a retryable sanitized error')
  }
  if ((receipt.after_state === 'INDETERMINATE' || receipt.after_state === 'HUMAN_DECISION_REQUIRED')
    && receipt.result.error.retryable !== false) {
    throw new Error('indeterminate receipt cannot authorize automatic retry')
  }
  if (receipt.evidence_chain.event_digest !== receiptEvidenceDigest(receipt)) {
    throw new Error('action receipt evidence digest does not bind the receipt and prior event')
  }
}

function validateStateTransition(transition) {
  assertTransitionAllowed(transition.from_state, transition.to_state)
  const admittedAuthorities = authoritiesForTransition(transition.from_state, transition.to_state)
  if (!admittedAuthorities.has(transition.actor.authority)) {
    throw new Error('state transition actor is not authoritative for this transition')
  }
}

function authoritiesForTransition(from, to) {
  if (from === 'RECEIVED') return new Set(['CORE'])
  // TASK_MANAGER is named in the actor enum so Task receipts can name their
  // authority, but this machine remains the Broker's external-action matrix.
  if (from === 'AUTHORIZED' || from === 'IN_FLIGHT') return new Set(['BROKER'])
  if (from === 'INDETERMINATE' && to === 'HUMAN_DECISION_REQUIRED') return new Set(['CORE', 'EVIDENCE_PLANE'])
  if (from === 'INDETERMINATE') return new Set(['EVIDENCE_PLANE', 'HUMAN'])
  return new Set()
}

function secretMaterialErrors(value, path = '$', errors = []) {
  if (typeof value === 'string') {
    if (/^Bearer\s/i.test(value) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)) {
      errors.push(`${path}: secret-shaped string is forbidden`)
    }
    return errors
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => secretMaterialErrors(entry, `${path}[${index}]`, errors))
    return errors
  }
  if (!isPlainObject(value)) return errors
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
    if (isForbiddenSecretKey(normalized)) errors.push(`${path}.${key}: secret field is forbidden`)
    secretMaterialErrors(entry, `${path}.${key}`, errors)
  }
  return errors
}

const FORBIDDEN_SECRET_KEYS = new Set([
  'accesstoken',
  'apikey',
  'authorization',
  'authorizationheader',
  'bearer',
  'clientsecret',
  'credential',
  'credentialvalue',
  'jwt',
  'password',
  'privatekey',
  'providersecret',
  'refreshtoken',
  'secret',
  'token',
])

function isForbiddenSecretKey(normalized) {
  return FORBIDDEN_SECRET_KEYS.has(normalized)
    || normalized.includes('password')
    || normalized.includes('secret')
    || normalized.includes('credential')
    || normalized.includes('privatekey')
    || normalized.endsWith('accesstoken')
    || normalized.endsWith('refreshtoken')
}

function metadataFor(kind) {
  const metadata = metadataByKind.get(kind)
  if (metadata === undefined) throw new Error(`unknown contract kind: ${String(kind)}`)
  return metadata
}

function assertSequentialOrder(items, label) {
  items.forEach((item, index) => {
    if (item.order !== index) throw new Error(`${label} must be sorted with contiguous order values`)
  })
}

function assertUnique(values, label) {
  if (new Set(values).size !== values.length) throw new Error(`${label} must be unique`)
}

function assertSortedUnique(values, label) {
  assertUnique(values, label)
  const sorted = [...values].sort()
  if (canonicalJson(values) !== canonicalJson(sorted)) throw new Error(`${label} must be sorted`)
}

function assertCanonicalOrder(values, label) {
  const encoded = values.map(value => canonicalJson(value))
  const sorted = [...encoded].sort()
  if (canonicalJson(encoded) !== canonicalJson(sorted)) throw new Error(`${label} must be canonically sorted`)
}

function assertChronology(start, end, label) {
  if (Date.parse(start) > Date.parse(end)) throw new Error(`${label} timestamps are not chronological`)
}

function assertBefore(start, end, label) {
  if (Date.parse(start) >= Date.parse(end)) throw new Error(`${label} requires a positive interval`)
}

function compareExact(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} binding mismatch`)
}

function assertSet(value, label) {
  if (!(value instanceof Set)) throw new TypeError(`${label} must be a Set`)
}

function toInstant(value) {
  const instant = value instanceof Date ? value.getTime() : Date.parse(value)
  if (!Number.isFinite(instant)) throw new TypeError('invalid validation time')
  return instant
}

function exactKeys(value, expected) {
  return isPlainObject(value) && Object.keys(value).sort().join(',') === [...expected].sort().join(',')
}

function assertRuntimeLock(lock) {
  if (!exactKeys(lock, RUNTIME_LOCK_KEYS)) throw new TypeError('runtime lock is invalid')
  for (const key of ['adapter_image', 'execd_image', 'server_image', 'task_image']) {
    if (!DIGEST.test(lock[key])) throw new TypeError(`runtime lock ${key} is invalid`)
  }
  if (!GIT_COMMIT.test(lock.opensandbox_commit)) throw new TypeError('runtime lock commit is invalid')
}

function assertTaskProfile(profile) {
  if (!exactKeys(profile, TASK_PROFILE_KEYS)) throw new TypeError('task profile is invalid')
  if (!PROFILE_ID.test(profile.profile_id) || profile.effect !== 'none' || !DIGEST.test(profile.input_digest)) {
    throw new TypeError('task profile identity is invalid')
  }
  assertRuntimeLock(profile.runtime_lock)
  if (profile.image !== profile.runtime_lock.task_image) throw new TypeError('task profile image does not bind the runtime lock')
  if (profile.input_root !== '/workspace' || profile.output_root !== '/workspace/out') {
    throw new TypeError('task profile roots are invalid')
  }
  if (!Array.isArray(profile.entrypoint) || profile.entrypoint.length < 1 || profile.entrypoint.length > 8
    || profile.entrypoint.some(part => typeof part !== 'string' || part.length === 0 || part.length > 128)) {
    throw new TypeError('task profile entrypoint is invalid')
  }
  if (!isPlainObject(profile.commands) || Object.keys(profile.commands).length < 1 || Object.keys(profile.commands).length > 16) {
    throw new TypeError('task profile commands are invalid')
  }
  for (const [name, command] of Object.entries(profile.commands)) {
    if (!COMMAND_NAME.test(name) || typeof command !== 'string' || command.length < 1 || command.length > 256) {
      throw new TypeError('task profile command is invalid')
    }
  }
  if (!Array.isArray(profile.allowed_outputs) || profile.allowed_outputs.length < 1 || profile.allowed_outputs.length > 8
    || profile.allowed_outputs.some(outputPath => !OUTPUT_PATH.test(outputPath))) {
    throw new TypeError('task profile outputs are invalid')
  }
  assertSortedUnique(profile.allowed_outputs, 'task profile outputs')
  assertSortedUnique(profile.allowed_operations, 'task profile operations')
  if (!isPlainObject(profile.filesystem) || !Array.isArray(profile.filesystem.mounts)) {
    throw new TypeError('task profile filesystem is invalid')
  }
  try {
    assertAdmittedMounts(profile.filesystem.mounts, 'task profile')
  } catch (error) {
    throw new TypeError(error instanceof Error ? error.message : 'task profile filesystem is invalid')
  }
}

export function taskAuthorizationSlice(task) {
  if (!isPlainObject(task)) throw new TypeError('task authorization is invalid')
  return Object.fromEntries(TASK_AUTHORIZATION_KEYS.map(key => [key, structuredClone(task[key])]))
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
