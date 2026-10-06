import path from 'node:path';
import { SchemaRegistry } from '../schema-validator.mjs';
import { assertAutomationContract, hashAutomationContract } from './index.mjs';

export const MISSION_AUTOMATION_RESULTS_FORMAT = 'dubsar.my-work-mission-automation-results/1';
export const MISSION_AUTOMATION_RESULTS_MAX_BYTES = 32768;
export const MISSION_AUTOMATION_RESULTS_MAX_RUNS = 8;
export const MISSION_AUTOMATION_RESULTS_MAX_EVENTS_PER_RUN = 8;
export const MISSION_AUTOMATION_RESULTS_MAX_EVENTS = 32;
export const MISSION_AUTOMATION_RESULTS_SCHEMA = 'mission-results-view.schema.json';
export const missionAutomationResultsSchemas = new SchemaRegistry(
  path.resolve(import.meta.dirname, '../../schemas/automation-integration/v1'),
);

const terminal = new Set(['succeeded', 'failed', 'rejected']);
const results = new Set(['step_result', 'terminal', 'reconciled']);
const ordered = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function recordedAutomationCompletion(state) {
  return terminal.has(state) ? 'recorded_terminal'
    : state === 'indeterminate' ? 'indeterminate' : 'not_recorded_terminal';
}

/** Integrity/binding of a recorded E5, not authority or a reread of its evidence. */
export function assertMissionAutomationEvent(run, item) {
  const event = item.event;
  assertAutomationContract('event', event);
  if (hashAutomationContract('event', event) !== item.event_digest
      || event.automation_run_id !== run.automation_run_id
      || event.mission_ref !== run.mission_ref
      || event.request_digest !== run.request_digest
      || event.workflow_digest !== run.workflow.digest
      || event.steps.some(step => ['step_id', 'step_instance_id', 'execution_id']
        .some(key => step[key] !== run.step_identity[key]))) {
    throw new TypeError('AUTOMATION_EVENT_BINDING_INVALID');
  }
  // The same success evidence requirement as accept_run_event in My Work.
  if (event.run_state === 'succeeded' && (event.steps.length !== 1
      || event.steps[0].tool_status !== 'succeeded'
      || event.steps[0].remote_durable !== true
      || event.steps[0].tool_receipt_ref === null
      || event.steps[0].tool_receipt_digest === null)) {
    throw new TypeError('AUTOMATION_RESULT_EVIDENCE_INVALID');
  }
  return event;
}

export function isAutomationResultEvent(event) { return results.has(event.event_type); }

export function validateMissionAutomationResults(view) {
  try {
    const errors = missionAutomationResultsSchemas.validate(MISSION_AUTOMATION_RESULTS_SCHEMA, view);
    if (errors.length) return { ok: false, errors };
    if (Buffer.byteLength(JSON.stringify(view), 'utf8') > MISSION_AUTOMATION_RESULTS_MAX_BYTES) {
      return { ok: false, errors: ['MAX_BYTES'] };
    }
    if (view.availability !== 'available' && view.runs.length) throw new TypeError('UNAVAILABLE_HAS_RUNS');
    const ids = new Set();
    let eventCount = 0;
    for (const source of Object.values(view.source_snapshots)) {
      if (source && typeof source === 'object' && source.availability === 'read' && source.digest === null) {
        throw new TypeError('READ_SOURCE_DIGEST_MISSING');
      }
    }
    for (const [index, run] of view.runs.entries()) {
      if (ids.has(run.automation_run_id)
          || (index && ordered(view.runs[index - 1].automation_run_id, run.automation_run_id) >= 0)) {
        throw new TypeError('RUN_ORDER_OR_DUPLICATE');
      }
      ids.add(run.automation_run_id);
      const identity = run.mission_binding_method === 'work_id' ? view.mission.work_id : view.mission.ticket_id;
      if (identity === null || run.mission_ref !== identity) throw new TypeError('MISSION_BINDING_INVALID');
      if (run.completion !== recordedAutomationCompletion(run.recorded_state)) throw new TypeError('COMPLETION_INVALID');
      let previous = 0;
      const eventIds = new Set();
      for (const item of run.events) {
        const event = assertMissionAutomationEvent(run, item);
        if (event.event_sequence <= previous || eventIds.has(event.event_id)) throw new TypeError('EVENT_ORDER_OR_DUPLICATE');
        previous = event.event_sequence;
        eventIds.add(event.event_id);
        eventCount += 1;
      }
      const summary = run.result_evidence;
      if (summary.status === 'missing') {
        if (summary.event_id !== null || summary.event_digest !== null || run.events.some(item => isAutomationResultEvent(item.event))) {
          throw new TypeError('MISSING_RESULT_INVALID');
        }
      } else {
        const item = run.events.find(item => item.event.event_id === summary.event_id);
        if ((summary.status === 'documented' && (!item || !isAutomationResultEvent(item.event)
              || item.event_digest !== summary.event_digest))
            || (summary.status === 'omitted' && (item || run.omitted_event_count < 1))) {
          throw new TypeError('RESULT_REFERENCE_INVALID');
        }
      }
    }
    if (eventCount > MISSION_AUTOMATION_RESULTS_MAX_EVENTS) throw new TypeError('MAX_EVENTS');
    if (view.omissions.events !== view.omissions.events_in_omitted_runs
        + view.runs.reduce((sum, run) => sum + run.omitted_event_count, 0)) {
      throw new TypeError('OMISSION_COUNT_INVALID');
    }
    if (view.truncated !== (view.omissions.runs > 0 || view.omissions.events > 0)) throw new TypeError('TRUNCATION_INVALID');
    return { ok: true, errors: [] };
  } catch (error) {
    return { ok: false, errors: [error.message] };
  }
}

export function assertMissionAutomationResults(view) {
  const result = validateMissionAutomationResults(view);
  if (!result.ok) throw new TypeError(`invalid mission Automation results: ${result.errors.slice(0, 3).join('; ')}`);
  return view;
}
