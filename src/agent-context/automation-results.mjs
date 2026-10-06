import path from 'node:path';
import { SchemaRegistry } from '../schema-validator.mjs';

export const AGENT_AUTOMATION_RESULTS_FORMAT = 'dubsar.agent-context.automation-results/1';
export const AGENT_AUTOMATION_RESULTS_MAX_RUNS = 8;
export const AGENT_AUTOMATION_RESULTS_MAX_EVENTS_PER_RUN = 4;
export const AGENT_AUTOMATION_RESULTS_MAX_EVENTS = 16;
export const AGENT_AUTOMATION_RESULTS_MAX_PROOF_REFS = 4;
const registry = new SchemaRegistry(path.resolve(import.meta.dirname, '../../schemas/agent-context/v1'));

export function assertHermesAutomationResultsRequest(request) {
  const errors = registry.validate('hermes-automation-results-read-request.schema.json', request);
  if (errors.length) throw new TypeError('invalid Hermes Automation results read request');
  return request;
}

export function assertHermesAutomationResultsScope(scope) {
  const errors = registry.validate('trusted-my-work-read-scope.schema.json', scope);
  if (errors.length) throw new TypeError('invalid transport-owned My Work read scope');
  return scope;
}

export function validateAgentAutomationResults(block) {
  const errors = registry.validate('automation-results.schema.json', block);
  if (errors.length) return errors;
  if (block.availability !== 'available' && block.runs.length) errors.push('unavailable runs');
  let events = 0;
  for (const [i, run] of block.runs.entries()) {
    if (i && block.runs[i - 1].automation_run_id >= run.automation_run_id) errors.push('run order');
    const completion = ['succeeded', 'failed', 'rejected'].includes(run.recorded_state)
      ? 'recorded_terminal' : run.recorded_state === 'indeterminate' ? 'indeterminate' : 'not_recorded_terminal';
    if (completion !== run.completion) errors.push('completion');
    events += run.events.length;
    if (run.events.some((event, n) => n && run.events[n - 1].event_sequence >= event.event_sequence)) errors.push('event order');
    const result = run.result_evidence;
    const match = run.events.find(event => event.event_id === result.event_id);
    if (result.status === 'documented' && (!match || match.event_digest !== result.event_digest
      || !['step_result', 'terminal', 'reconciled'].includes(match.event_type))) errors.push('documented evidence');
    if (result.status === 'missing' && (result.event_id !== null || result.event_digest !== null
      || run.events.some(event => event.event_type !== 'started'))) errors.push('missing evidence');
    if (result.status === 'omitted' && (match || result.event_id === null || result.event_digest === null
      || run.omitted_event_count < 1)) errors.push('omitted evidence');
  }
  if (events > AGENT_AUTOMATION_RESULTS_MAX_EVENTS) errors.push('event cap');
  return errors;
}
