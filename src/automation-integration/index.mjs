import { createHash } from 'node:crypto';

const ID = /^[A-Za-z0-9_-]{8,128}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const CAPABILITY = 'dubsar.capability.github.list_issues';
const DOMAINS = Object.freeze({
  workflow: 'dubsar.automation.workflow.v1', context: 'dubsar.automation.context.v1',
  request: 'dubsar.automation.request.v1', invocation: 'dubsar.automation.tool-request.v1',
  event: 'dubsar.automation.run-event.v1'
});
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const obj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => obj(v) && Object.keys(v).length === keys.length && keys.every(k => own(v, k));
const id = v => typeof v === 'string' && ID.test(v);
const ref = v => typeof v === 'string' && v.length >= 1 && v.length <= 256 && !/[\u0000-\u001f]/.test(v);
const digest = v => typeof v === 'string' && DIGEST.test(v);
const time = v => typeof v === 'string' && TIME.test(v) && Number.isFinite(Date.parse(v));
const safe = v => Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
const bytes = v => Buffer.byteLength(JSON.stringify(v), 'utf8');
const unique = a => new Set(a).size === a.length;
const fail = (path, code) => ({ path, code });

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError('unsafe control number');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (obj(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  throw new TypeError('unsupported JSON value');
}

function depth(v) {
  if (!obj(v) && !Array.isArray(v)) return 0;
  return 1 + Math.max(0, ...Object.values(v).map(depth));
}

function common(v, maxBytes = 262144) {
  if (!obj(v)) return fail('$', 'TYPE');
  if (depth(v) > 16) return fail('$', 'MAX_DEPTH');
  if (bytes(v) > maxBytes) return fail('$', 'MAX_BYTES');
  try { canonical(v); } catch { return fail('$', 'UNSAFE_NUMBER'); }
}

function invocation(v) {
  const keys = ['execution_id','capability_id','connection_ref','input','correlation_id','idempotency_key'];
  if (!exact(v, keys)) return fail('$', 'CLOSED_OBJECT');
  if (!id(v.execution_id) || v.capability_id !== CAPABILITY || !ref(v.connection_ref) || !id(v.correlation_id) || !id(v.idempotency_key)) return fail('$', 'FIELD');
  if (!exact(v.input, ['owner','repo']) || ![v.input.owner,v.input.repo].every(x => typeof x === 'string' && x.length >= 1 && x.length <= 100 && /^[A-Za-z0-9_.-]+$/.test(x))) return fail('$.input', 'INPUT');
  return common(v, 65536);
}

function context(v) {
  if (!exact(v, ['context_ref','context_digest','captured_at','expires_at','items'])) return fail('$', 'CLOSED_OBJECT');
  if (!ref(v.context_ref) || !digest(v.context_digest) || !time(v.captured_at) || !time(v.expires_at) || !Array.isArray(v.items) || v.items.length > 32) return fail('$', 'FIELD');
  const sortKeys=[];
  for (const x of v.items) {
    if (!exact(x,['kind','source_ref','source_digest','captured_at','policy_ref','required','qualification','payload'])) return fail('$.items','CLOSED_OBJECT');
    if (!['oc','memory','mission'].includes(x.kind)||!ref(x.source_ref)||!digest(x.source_digest)||!time(x.captured_at)||!ref(x.policy_ref)||typeof x.required!=='boolean'||!['qualified','advisory'].includes(x.qualification)||!obj(x.payload)) return fail('$.items','FIELD');
    sortKeys.push(`${x.kind}\u0000${x.source_ref}`);
  }
  if (!unique(sortKeys) || sortKeys.some((x,i)=>i && x < sortKeys[i-1])) return fail('$.items','ORDER_OR_DUPLICATE');
  if (hashAutomationContract('context', {...v, context_digest: undefined}, true) !== v.context_digest) return fail('$.context_digest','DIGEST_MISMATCH');
  return common(v,65536);
}

function step(v) {
  const k=['step_id','step_instance_id','execution_id','capability_id','connection_ref','input','correlation_id','idempotency_key','request_digest'];
  if (!exact(v,k)) return fail('$','CLOSED_OBJECT');
  const e=invocation(Object.fromEntries(k.slice(2,8).map(x=>[x,v[x]])));
  if (!id(v.step_id)||!id(v.step_instance_id)||!digest(v.request_digest)||e) return fail('$','FIELD');
  return hashAutomationContract('invocation',Object.fromEntries(k.slice(2,8).map(x=>[x,v[x]])))===v.request_digest?undefined:fail('$.request_digest','DIGEST_MISMATCH');
}

function request(v) {
  const k=['contract','launch_request_id','mission_ref','mission_revision','automation_run_id','workflow_ref','workflow_version','workflow_digest','workflow_digest_scheme','authority_ref','human_gate_refs','context','deadline','step_plan','policy','scope_ref'];
  if (!exact(v,k)||v.contract!=='dubsar.automation.run-request/1') return fail('$','CLOSED_OBJECT');
  if (!id(v.launch_request_id)||!ref(v.mission_ref)||!safe(v.mission_revision)||v.mission_revision<1||!id(v.automation_run_id)||!ref(v.workflow_ref)||typeof v.workflow_version!=='string'||v.workflow_version.length<1||v.workflow_version.length>128||!digest(v.workflow_digest)||v.workflow_digest_scheme!==DOMAINS.workflow||!ref(v.authority_ref)||!Array.isArray(v.human_gate_refs)||v.human_gate_refs.length<1||v.human_gate_refs.length>8||!unique(v.human_gate_refs)||!v.human_gate_refs.every(ref)||!time(v.deadline)||!ref(v.scope_ref)) return fail('$','FIELD');
  if (!Array.isArray(v.step_plan)||v.step_plan.length!==1||step(v.step_plan[0])) return fail('$.step_plan','STEP');
  if (!exact(v.policy,['attempts','auto_retry','max_active_runs','effect'])||v.policy.attempts!==1||v.policy.auto_retry!==false||v.policy.max_active_runs!==1||v.policy.effect!=='read') return fail('$.policy','POLICY');
  const ce=context(v.context); if(ce) return ce;
  if(Date.parse(v.context.expires_at)>Date.parse(v.deadline)) return fail('$.context.expires_at','AFTER_DEADLINE');
  return common(v);
}

function admission(v) {
  const k=['contract','admission_request_id','mission_ref','automation_run_id','step_id','step_instance_id','execution_id','request_digest','authority_ref','engine_permit_ref','engine_generation','tool_permit_ref','tool_binding','expires_at','issuance_state'];
  if(!exact(v,k)||v.contract!=='dubsar.automation.step-admission/1'||![v.admission_request_id,v.automation_run_id,v.step_id,v.step_instance_id,v.execution_id].every(id)||!digest(v.request_digest)||!ref(v.mission_ref)||!ref(v.authority_ref)||!safe(v.engine_generation)||!time(v.expires_at)||!['preparing','ready','closed_uncertain','rejected'].includes(v.issuance_state)) return fail('$','FIELD');
  for(const x of ['engine_permit_ref','tool_permit_ref']) if(v[x]!==null&&!ref(v[x])) return fail(`$.${x}`,'FIELD');
  if(['ready','rejected'].includes(v.issuance_state)&&(v.engine_permit_ref===null||v.tool_permit_ref===null)) return fail('$','PERMIT_NULL');
  if(!exact(v.tool_binding,['principal','execution_id','capability_id','catalog_revision','connection_ref','connection_revision','input_hash'])||!ref(v.tool_binding.principal)||v.tool_binding.execution_id!==v.execution_id||v.tool_binding.capability_id!==CAPABILITY||![v.tool_binding.catalog_revision,v.tool_binding.connection_revision].every(ref)||!ref(v.tool_binding.connection_ref)||!digest(v.tool_binding.input_hash)) return fail('$.tool_binding','FIELD');
  return common(v);
}

function event(v) {
  const k=['contract','event_id','event_sequence','mission_ref','automation_run_id','workflow_digest','request_digest','occurred_at','event_type','run_state','native_run_state','steps','evidence_refs'];
  if(!exact(v,k)||v.contract!=='dubsar.automation.run-event/1'||!id(v.event_id)||!safe(v.event_sequence)||v.event_sequence<1||!ref(v.mission_ref)||!id(v.automation_run_id)||!digest(v.workflow_digest)||!digest(v.request_digest)||!time(v.occurred_at)||!['started','step_result','terminal','reconciled'].includes(v.event_type)||!['running','succeeded','failed','rejected','indeterminate'].includes(v.run_state)||typeof v.native_run_state!=='string'||v.native_run_state.length>128||!Array.isArray(v.steps)||v.steps.length>1||!Array.isArray(v.evidence_refs)||v.evidence_refs.length>16) return fail('$','FIELD');
  if(v.steps.length===0&&!['started'].includes(v.event_type)&&v.run_state!=='rejected') return fail('$.steps','EMPTY');
  for(const s of v.steps){const sk=['step_id','step_instance_id','execution_id','native_step_state','transport_state','tool_status','tool_receipt_ref','tool_receipt_digest','remote_durable','provider_dispatch_count','retry_allowed']; if(!exact(s,sk)||![s.step_id,s.step_instance_id,s.execution_id].every(id)||typeof s.native_step_state!=='string'||!['not_sent_proved','post_committed','response_received','response_lost','receipt_read'].includes(s.transport_state)||!(s.tool_status===null||['succeeded','rejected','failed','indeterminate'].includes(s.tool_status))||typeof s.remote_durable!=='boolean'||!(s.provider_dispatch_count===null||[0,1].includes(s.provider_dispatch_count))||s.retry_allowed!==false) return fail('$.steps','FIELD'); if((s.tool_receipt_ref===null)!==(s.tool_receipt_digest===null)||s.tool_receipt_ref!==null&&(!ref(s.tool_receipt_ref)||!digest(s.tool_receipt_digest))) return fail('$.steps','RECEIPT'); if(s.tool_status==='succeeded'&&!s.remote_durable)return fail('$.steps','DURABILITY');}
  for(const a of v.evidence_refs) if(!exact(a,['ref','digest','media_type','size_bytes'])||!ref(a.ref)||!digest(a.digest)||typeof a.media_type!=='string'||a.media_type.length>128||!safe(a.size_bytes)) return fail('$.evidence_refs','FIELD');
  return common(v);
}

function admissionResponse(v) {
  const k=['admission_request_id','automation_run_id','step_instance_id','execution_id','state','engine_permit_ref','tool_permit_ref','request_digest','expires_at'];
  if(!exact(v,k)||![v.admission_request_id,v.automation_run_id,v.step_instance_id,v.execution_id].every(id)||!['ready','rejected','indeterminate'].includes(v.state)||![v.engine_permit_ref,v.tool_permit_ref].every(ref)||!digest(v.request_digest)||!time(v.expires_at)) return fail('$','FIELD');
  return common(v,32768);
}
function eventAck(v) {
  if(!exact(v,['event_id','event_sequence','event_digest','accepted','duplicate'])||!id(v.event_id)||!safe(v.event_sequence)||v.event_sequence<1||!digest(v.event_digest)||v.accepted!==true||typeof v.duplicate!=='boolean') return fail('$','FIELD');
  return common(v);
}
function operation(v, fields) {
  if(!exact(v,Object.keys(fields))) return fail('$','CLOSED_OBJECT');
  for(const [key,check] of Object.entries(fields)) if(!check(v[key])) return fail(`$.${key}`,'FIELD');
  return common(v);
}
const operationValidators={
  'lookup-run':v=>operation(v,{automation_run_id:id,mission_ref:ref}),
  'read-events':v=>operation(v,{automation_run_id:id,after_sequence:safe,limit:x=>safe(x)&&x>=1&&x<=32}),
  'prepare-step':v=>operation(v,{admission_request_id:id,automation_run_id:id,step_instance_id:id,authority_ref:ref}),
  'inspect-step':v=>operation(v,{admission_request_id:id,automation_run_id:id,step_instance_id:id}),
  'recover-run':v=>operation(v,{recovery_request_id:id,mission_ref:ref,automation_run_id:id}),
  'submit-run':request,
  'accept-run-event':event
};
function rpcRequest(v) {
  const operationName=typeof v?.operation==='string'?v.operation.replaceAll('_','-'):'';
  if(!exact(v,['contract','request_id','operation','payload'])||v.contract!=='dubsar.automation.rpc/1'||!id(v.request_id)||!own(operationValidators,operationName)) return fail('$','FIELD');
  return operationValidators[operationName](v.payload);
}
function rpcResult(v) {
  if(!obj(v)||v.contract!=='dubsar.automation.rpc-result/1'||!id(v.request_id)) return fail('$','FIELD');
  if(v.ok===true) return exact(v,['contract','request_id','ok','result'])&&obj(v.result)?common(v):fail('$','CLOSED_OBJECT');
  const codes=['UNAUTHORIZED','INVALID_MESSAGE','BINDING_CONFLICT','NOT_FOUND','BUSY','UNAVAILABLE','INDETERMINATE'];
  return v.ok===false&&exact(v,['contract','request_id','ok','error'])&&exact(v.error,['code'])&&codes.includes(v.error.code)?common(v):fail('$','CLOSED_OBJECT');
}
const validators={context,'context-capsule':context,'step-plan':step,request,'run-request':request,invocation,'tool-invocation':invocation,admission,'step-admission':admission,event,'run-event':event,'step-admission-response':admissionResponse,'event-ack':eventAck,...operationValidators,'rpc-request':rpcRequest,'rpc-result':rpcResult};
export function validateAutomationContract(kind,value){const e=common(value,kind==='invocation'?65536:262144)||validators[kind]?.(value)||(!validators[kind]?fail('$','UNKNOWN_KIND'):undefined); return e?{ok:false,errors:[e]}:{ok:true,errors:[]};}
export function assertAutomationContract(kind,value){const r=validateAutomationContract(kind,value);if(!r.ok){const e=new TypeError(`invalid automation contract: ${r.errors[0].code} at ${r.errors[0].path}`);e.code=r.errors[0].code;throw e;}return value;}
export function hashAutomationContract(kind,value,omitUndefined=false){const domain=DOMAINS[kind];if(!domain)throw new TypeError('unknown hash domain');let material=value;if(omitUndefined) material=JSON.parse(JSON.stringify(value)); else assertAutomationContract(kind,value);return createHash('sha256').update(`${domain}\n${canonical(material)}`,'utf8').digest('hex');}
export function validateAutomationBindings({request:r,admission:a,invocation:i,event:e}){for(const [k,v] of [['request',r],['admission',a],['invocation',i],['event',e]]){const q=validateAutomationContract(k,v);if(!q.ok)return q;}const s=r.step_plan[0];const matches=a.mission_ref===r.mission_ref&&a.automation_run_id===r.automation_run_id&&a.step_id===s.step_id&&a.step_instance_id===s.step_instance_id&&a.execution_id===s.execution_id&&a.request_digest===s.request_digest&&hashAutomationContract('invocation',i)===s.request_digest&&e.mission_ref===r.mission_ref&&e.automation_run_id===r.automation_run_id&&e.workflow_digest===r.workflow_digest&&e.request_digest===hashAutomationContract('request',r)&&e.steps.every(x=>x.step_id===s.step_id&&x.step_instance_id===s.step_instance_id&&x.execution_id===s.execution_id);return matches?{ok:true,errors:[]}:{ok:false,errors:[fail('$','BINDING_CONFLICT')]};}
export function validateRecoveryTransition({from,to,sameEngagement}){const allowed={prepared:['indeterminate'],launch_committed:['running','indeterminate'],running:['succeeded','failed','rejected','indeterminate'],indeterminate:['indeterminate','succeeded','failed','rejected']};return sameEngagement===true&&allowed[from]?.includes(to)?{ok:true,errors:[]}:{ok:false,errors:[fail('$','REEXECUTION_NOT_AUTHORIZED')]};}

// Strict control-message parser: duplicate keys, unsafe/-0 numbers, depth and bytes are rejected before use.
export function parseAutomationJson(raw,{maxBytes=262144,maxDepth=16}={}){if(typeof raw!=='string'&&!(raw instanceof Uint8Array))throw new TypeError('bytes required');const text=typeof raw==='string'?raw:Buffer.from(raw).toString('utf8');if(Buffer.byteLength(text)>maxBytes)throw Object.assign(new SyntaxError('message exceeds byte limit'),{code:'MAX_BYTES'});let i=0;const ws=()=>{while(/\s/.test(text[i]??''))i++;};function val(d){if(d>maxDepth)throw Object.assign(new SyntaxError('maximum depth exceeded'),{code:'MAX_DEPTH'});ws();const c=text[i];if(c==='"'){const start=i++;for(;i<text.length;i++){if(text[i]==='\\')i++;else if(text[i]==='"')return JSON.parse(text.slice(start,++i));}throw new SyntaxError('unterminated string');}if(c==='['){i++;const a=[];ws();if(text[i]===']'){i++;return a;}for(;;){a.push(val(d+1));ws();if(text[i++]===']')return a;if(text[i-1]!==',')throw new SyntaxError('array syntax');}}if(c==='{'){i++;const o={};const keys=new Set;ws();if(text[i]==='}'){i++;return o;}for(;;){const k=val(d+1);if(typeof k!=='string')throw new SyntaxError('key');if(keys.has(k))throw Object.assign(new SyntaxError('duplicate key'),{code:'DUPLICATE_KEY'});keys.add(k);ws();if(text[i++]!==':')throw new SyntaxError('colon');o[k]=val(d+1);ws();if(text[i++]==='}')return o;if(text[i-1]!==',')throw new SyntaxError('object syntax');}}const m=text.slice(i).match(/^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/);if(!m)throw new SyntaxError('value');i+=m[0].length;if(m[0]==='true')return true;if(m[0]==='false')return false;if(m[0]==='null')return null;const n=Number(m[0]);if(!Number.isSafeInteger(n)||Object.is(n,-0))throw Object.assign(new SyntaxError('unsafe control number'),{code:'UNSAFE_NUMBER'});return n;}const out=val(0);ws();if(i!==text.length)throw new SyntaxError('trailing data');return out;}
export { DOMAINS };
