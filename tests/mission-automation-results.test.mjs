import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { SchemaRegistry } from '../src/schema-validator.mjs';
import { hashAutomationContract, validateAutomationContract } from '../src/automation-integration/index.mjs';
import {
  MISSION_AUTOMATION_RESULTS_MAX_BYTES, MISSION_AUTOMATION_RESULTS_SCHEMA,
  missionAutomationResultsSchemas, validateMissionAutomationResults,
} from '../src/automation-integration/mission-results.mjs';

const root = path.resolve(import.meta.dirname, '..');
const read = () => JSON.parse(fs.readFileSync(path.join(root, 'fixtures/automation-integration/v1/valid/mission-results-view.json'), 'utf8'));
const check = (value, ok) => assert.equal(validateMissionAutomationResults(value).ok, ok);

test('Mission automation results: nominal closed view reuses canonical E5 schema/hash and closed references', () => {
  const value = read();
  check(value, true);
  assert.deepEqual(missionAutomationResultsSchemas.validate(MISSION_AUTOMATION_RESULTS_SCHEMA, value), []);
  assert.doesNotThrow(() => missionAutomationResultsSchemas.assertAllReferencesClosed());
  assert.equal(value.runs[0].events[0].event_digest, hashAutomationContract('event', value.runs[0].events[0].event));
  assert.equal(value.runs[0].events[0].reference_contents_read, false);
  assert.equal(value.mission_criteria, 'not_evaluated');
});

test('Mission automation results: root and every nested object are closed', () => {
  for (const select of [v => v, v => v.mission, v => v.source_snapshots,
    v => v.source_snapshots.automation_registry, v => v.omissions, v => v.runs[0],
    v => v.runs[0].workflow, v => v.runs[0].step_identity, v => v.runs[0].result_evidence,
    v => v.runs[0].recorded_times, v => v.runs[0].events[0], v => v.runs[0].events[0].event,
    v => v.runs[0].events[0].event.steps[0]]) {
    const value = read(); select(value).permission = 'execute'; check(value, false);
  }
});

test('Mission automation results: does not carry authority, execution permission, freshness or mission success', () => {
  for (const [key, field] of [['authority', 'execute'], ['executable', true], ['mission_criteria', 'fulfilled'], ['freshness', 'current'], ['read_at', '2026-10-03T12:00:00.000Z']]) {
    const value = read(); value[key] = field; check(value, false);
  }
  const value = read(); value.source_snapshots.atomic = true; check(value, false);
  value.source_snapshots.atomic = false; value.runs[0].events[0].reference_contents_read = true; check(value, false);
});

test('Mission automation results: altered E5 digest and rehashed wrong bindings are refused', () => {
  for (const change of [e => { e.occurred_at = '2026-09-28T20:00:00.000Z'; },
    e => { e.mission_ref = 'mission:another'; }, e => { e.automation_run_id = 'run_another00001'; },
    e => { e.request_digest = '1'.repeat(64); }, e => { e.workflow_digest = '2'.repeat(64); },
    e => { e.steps[0].execution_id = 'exec_another0001'; }]) {
    const value = read(); const item = value.runs[0].events[0]; change(item.event);
    check(value, false);
    if (item.event.mission_ref !== value.runs[0].mission_ref || item.event.automation_run_id !== value.runs[0].automation_run_id
        || item.event.request_digest !== value.runs[0].request_digest || item.event.workflow_digest !== value.runs[0].workflow.digest
        || item.event.steps[0].execution_id !== value.runs[0].step_identity.execution_id) {
      item.event_digest = hashAutomationContract('event', item.event); check(value, false);
    }
  }
});

test('Mission automation results: a terminal state alone has missing result evidence', () => {
  const value = read(); const run = value.runs[0]; run.events = [];
  run.result_evidence = { status: 'missing', event_id: null, event_digest: null };
  check(value, true); assert.equal(run.recorded_state, 'succeeded');
  run.result_evidence.status = 'documented'; check(value, false);
});

test('Mission automation results: success requires the accepted E5 durable receipt fields, not an HTTP outcome', () => {
  const value = read(); const run = value.runs[0]; const item = run.events[0];
  item.event.steps[0].tool_receipt_ref = null; item.event.steps[0].tool_receipt_digest = null;
  // The pre-existing wire validator permits null receipts; accept_run_event's success rule does not.
  assert.equal(validateAutomationContract('event', item.event).ok, true);
  item.event_digest = hashAutomationContract('event', item.event); run.result_evidence.event_digest = item.event_digest;
  check(value, false);
});

test('Mission automation results: omissions keep an exact result identity without claiming it was included', () => {
  const value = read(); const run = value.runs[0]; run.events = [];
  run.omitted_event_count = 1; run.result_evidence.status = 'omitted';
  value.omissions.events = 1; value.truncated = true; check(value, true);
  run.result_evidence.status = 'documented'; check(value, false);
  run.result_evidence.status = 'omitted'; value.omissions.events = 0; check(value, false);
});

test('Mission automation results: deterministic unique run order and all count/byte caps are checked', () => {
  const value = read(); value.runs.push(structuredClone(value.runs[0])); check(value, false);
  value.runs = Array.from({ length: 9 }, () => structuredClone(read().runs[0])); check(value, false);
  const large = read(); const run = large.runs[0]; const item = run.events[0];
  item.event.evidence_refs = Array.from({ length: 16 }, (_, i) => ({ ref: `artifact:${i}:${'x'.repeat(235)}`,
    digest: '4'.repeat(64), media_type: 'application/json', size_bytes: 1000 }));
  run.events = Array.from({ length: 8 }, (_, i) => {
    const copy = structuredClone(item); copy.event.event_sequence = i + 1; copy.event.event_id = `event_0000000${i}`;
    copy.event_digest = hashAutomationContract('event', copy.event); return copy;
  });
  run.result_evidence = { status: 'documented', event_id: run.events.at(-1).event.event_id, event_digest: run.events.at(-1).event_digest };
  assert.ok(Buffer.byteLength(JSON.stringify(large)) > MISSION_AUTOMATION_RESULTS_MAX_BYTES); check(large, false);
});

test('Mission automation results: mission binding, recorded completion, source digests and unavailable views are explicit', () => {
  for (const change of [v => { v.mission.work_id = 'mission:other'; },
    v => { v.runs[0].completion = 'not_recorded_terminal'; },
    v => { v.source_snapshots.mission_registry.digest = null; },
    v => { v.availability = 'unavailable'; }]) {
    const value = read(); change(value); check(value, false);
  }
});

test('Mission automation results: does not extend Mission View v1 or accepted context', () => {
  const registry = new SchemaRegistry(path.join(root, 'schemas/agent-context/v1'));
  const view = JSON.parse(fs.readFileSync(path.join(root, 'fixtures/agent-context/v1/mission-view-valid.json')));
  assert.deepEqual(registry.validate('my-work-mission-view.schema.json', view), []);
  assert.equal(view.execution_refs.automation, null);
  view.execution_refs.automation = { runs: [] };
  assert.ok(registry.validate('my-work-mission-view.schema.json', view).length > 0);
});
