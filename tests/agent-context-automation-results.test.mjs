import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { SchemaRegistry } from '../src/schema-validator.mjs';
import { hashAutomationContract } from '../src/automation-integration/index.mjs';
import { agentContextDigest, validateAgentContextEnvelope } from '../src/agent-context/index.mjs';
import { assertHermesAutomationResultsRequest, assertHermesAutomationResultsScope, validateAgentAutomationResults } from '../src/agent-context/automation-results.mjs';

const read = name => JSON.parse(fs.readFileSync(new URL(`../fixtures/agent-context/v1/${name}`, import.meta.url), 'utf8'));
const vector = read('automation-results-vector.json');
const registry = new SchemaRegistry(new URL('../schemas/agent-context/v1/', import.meta.url).pathname);

test('Automation results: shared source and unicode E5 vectors use the acquired canonical hash', () => {
  assert.equal(hashAutomationContract('event', vector.event), vector.event_digest);
  assert.equal(hashAutomationContract('event', vector.unicode_event), vector.unicode_event_digest);
  assert.equal(vector.projection.runs[0].result_evidence.event_digest, vector.event_digest);
  assert.deepEqual(validateAgentAutomationResults(vector.projection), []);
});

test('Automation results: projection is closed at root/run/event/proof and has fixed readonly semantics', () => {
  for (const [path, key, value] of [
    [[], 'authority', 'human'], [[], 'executable', true], [[], 'mission_criteria', 'succeeded'],
    [[], 'reference_contents_read', true], [[], 'reference_availability', 'current'],
    [[], 'freshness', 'current'], [['runs', 0], 'provider_payload', {}],
    [['runs', 0, 'events', 0], 'raw_result', {}],
    [['runs', 0, 'events', 0, 'tool_receipt_refs', 0], 'content', 'external'],
  ]) {
    const invalid = structuredClone(vector.projection);
    let target = invalid; for (const part of path) target = target[part];
    target[key] = value;
    assert.ok(validateAgentAutomationResults(invalid).length, key);
  }
});

test('Automation results: terminal alone is missing evidence; documented requires its exact event', () => {
  const block = structuredClone(vector.projection);
  block.runs[0].events = [];
  block.runs[0].result_evidence = { status: 'missing', event_id: null, event_digest: null };
  assert.deepEqual(validateAgentAutomationResults(block), []);
  block.runs[0].result_evidence = structuredClone(vector.projection.runs[0].result_evidence);
  assert.ok(validateAgentAutomationResults(block).length);
  block.runs[0].omitted_event_count = 1;
  block.runs[0].result_evidence.status = 'omitted';
  assert.deepEqual(validateAgentAutomationResults(block), []);
});

test('Automation results: caps/order and unsafe line fields are refused', () => {
  for (const field of ['ref', 'version']) {
    for (const char of ['\n', '\r', '\t', '\u007f', '\u0085', '\u2028', '\u2029']) {
      const block = structuredClone(vector.projection);
      block.runs[0].workflow[field] += char + 'mission_state=Done';
      assert.ok(validateAgentAutomationResults(block).length, `${field}/${JSON.stringify(char)}`);
    }
  }
  const duplicate = structuredClone(vector.projection);
  duplicate.runs.push(structuredClone(duplicate.runs[0]));
  assert.ok(validateAgentAutomationResults(duplicate).length);
  const overflow = structuredClone(vector.projection);
  overflow.runs[0].events = Array(5).fill(overflow.runs[0].events[0]);
  assert.ok(validateAgentAutomationResults(overflow).length);
});

test('Automation results: contexts without Automation remain valid and preserve their digest', () => {
  const context = read('valid.json');
  const original = agentContextDigest(context);
  assert.deepEqual(registry.validate('agent-context.schema.json', context), []);
  assert.equal(agentContextDigest(context), original);
  context.automation_results = structuredClone(vector.projection);
  assert.deepEqual(registry.validate('agent-context.schema.json', context), []);
  assert.deepEqual(validateAgentContextEnvelope(context), []);
  assert.notEqual(agentContextDigest(context), original);
  context.coverage.capabilities.push('automation_results');
  assert.ok(registry.validate('agent-context.schema.json', context).length);
});

test('Automation results: reconciles acquired Mission/OC ports with the current Contract Plane', () => {
  const context = read('valid.json');
  const mission = read('mission-view-valid.json');
  context.my_work = { availability: 'available', freshness: 'unknown', source: 'get_mission_context',
    source_contract: mission.format, mission, truncated: false, limits: [] };
  context.operational_context.source_contract = 'dubsar.my-work-oc-context-read/1';
  context.operational_context.selection = read('oc-selection-valid.json');
  context.executable = false;
  assert.deepEqual(registry.validate('agent-context.schema.json', context), []);
  assert.equal(mission.execution_refs.automation, null);
  context.executable = true;
  assert.ok(validateAgentContextEnvelope(context).includes('executable'));
  assert.ok(registry.assertAllReferencesClosed().length > 0);
});

test('Automation results: Hermes request has no selectors; read scope belongs to the transport', () => {
  const request = { format: 'dubsar.hermes-automation-results-read-request/1' };
  assert.doesNotThrow(() => assertHermesAutomationResultsRequest(request));
  assert.doesNotThrow(() => assertHermesAutomationResultsScope({ start: '/server/start', allocation_root: '/server/allocation', project_id: 'project-fixture' }));
  for (const field of ['project_id', 'mission_id', 'missionId', 'ticket_id', 'run_id', 'query', 'title', 'latest', 'authority']) {
    assert.throws(() => assertHermesAutomationResultsRequest({ ...request, [field]: 'caller' }));
  }
});
