import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { SchemaRegistry } from '../../src/schema-validator.mjs';
import { hashAutomationContract, validateAutomationBindings, validateAutomationContract } from '../../src/automation-integration/index.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const registry = new SchemaRegistry(path.join(root, 'schemas/automation-integration/v1'));
const fixture = name => JSON.parse(fs.readFileSync(path.join(root, `fixtures/automation-integration/v1/valid/${name}.json`)));
const clone = structuredClone;
const values = { context: fixture('context'), invocation: fixture('invocation'), request: fixture('request'), admission: fixture('admission'), event: fixture('event') };
values['step-plan'] = values.request.step_plan[0];
values['run-request'] = values.request;
values['context-capsule'] = values.context;
values['tool-invocation'] = values.invocation;
values['step-admission'] = values.admission;
values['run-event'] = values.event;
values['submit-run'] = values.request;
values['accept-run-event'] = values.event;
values['lookup-run'] = { automation_run_id: values.request.automation_run_id, mission_ref: values.request.mission_ref };
values['read-events'] = { automation_run_id: values.request.automation_run_id, after_sequence: 0, limit: 32 };
values['prepare-step'] = { admission_request_id: values.admission.admission_request_id, automation_run_id: values.request.automation_run_id, step_instance_id: values.request.step_plan[0].step_instance_id, authority_ref: values.request.authority_ref };
values['inspect-step'] = { admission_request_id: values.admission.admission_request_id, automation_run_id: values.request.automation_run_id, step_instance_id: values.request.step_plan[0].step_instance_id };
values['recover-run'] = { recovery_request_id: 'recover_00000001', mission_ref: values.request.mission_ref, automation_run_id: values.request.automation_run_id };
values['step-admission-response'] = { admission_request_id: values.admission.admission_request_id, automation_run_id: values.request.automation_run_id, step_instance_id: values.request.step_plan[0].step_instance_id, execution_id: values.invocation.execution_id, state: 'ready', engine_permit_ref: 'permit:engine-001', tool_permit_ref: 'permit:tool-001', request_digest: values.request.step_plan[0].request_digest, expires_at: values.admission.expires_at };
values['event-ack'] = { event_id: values.event.event_id, event_sequence: values.event.event_sequence, event_digest: hashAutomationContract('event', values.event), accepted: true, duplicate: false };
values['rpc-request'] = { contract: 'dubsar.automation.rpc/1', request_id: 'rpcreq_00000001', operation: 'read_events', payload: values['read-events'] };
values['rpc-result'] = { contract: 'dubsar.automation.rpc-result/1', request_id: 'rpcreq_00000001', ok: true, result: {} };

const aliases = { context: 'context-capsule', request: 'run-request', invocation: 'tool-invocation', admission: 'step-admission', event: 'run-event' };
function schemaAccepts(kind, value) { return registry.validate(`${aliases[kind] ?? kind}.schema.json`, value).length === 0; }
function assertParity(kind, value, expected) {
  assert.equal(schemaAccepts(kind, value), expected, `${kind} schema`);
  assert.equal(validateAutomationContract(kind, value).ok, expected, `${kind} pure validator`);
}

test('C0 schema and pure-validator parity accepts every nominal message family', () => {
  for (const [kind, value] of Object.entries(values)) assertParity(kind, value, true);
});

test('C0 schema and pure-validator parity rejects nested fields, enums, nullability and bounds', () => {
  const cases = [];
  const add = (kind, mutate) => { const value = clone(values[kind]); mutate(value); cases.push([kind, value]); };
  add('context', v => { v.items = [{}]; });
  add('step-plan', v => { v.input.state = 'open'; });
  add('request', v => { v.policy.attempts = 2; });
  add('request', v => { v.human_gate_refs = []; });
  add('request', v => { v.workflow_version = 'x'.repeat(129); });
  add('invocation', v => { v.input.owner = 'not/owner'; });
  add('admission', v => { v.issuance_state = 'ready-ish'; });
  add('admission', v => { v.engine_permit_ref = null; });
  add('event', v => { v.event_sequence = 0; });
  add('event', v => { v.steps[0].transport_state = 'unknown'; });
  add('event', v => { v.steps[0].tool_status = null; v.steps[0].tool_receipt_ref = 'artifact:receipt-001'; v.steps[0].tool_receipt_digest = null; });
  add('event', v => { v.steps[0].remote_durable = false; });
  add('event', v => { v.evidence_refs = [{}]; });
  add('event-ack', v => { v.accepted = false; });
  add('read-events', v => { v.limit = 33; });
  add('rpc-request', v => { v.payload.limit = 33; });
  add('rpc-result', v => { v.error = { code: 'INTERNAL' }; });
  for (const [kind, value] of cases) assertParity(kind, value, false);
});

test('C0-06 invocation binding is independent of JSON property insertion order', () => {
  const reordered = Object.fromEntries(Object.entries(values.invocation).reverse());
  assert.notDeepEqual(Object.keys(reordered), Object.keys(values.invocation));
  assert.equal(hashAutomationContract('invocation', reordered), values.request.step_plan[0].request_digest);
  assert.equal(validateAutomationBindings({ ...values, invocation: reordered }).ok, true);
});
