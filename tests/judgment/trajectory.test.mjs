import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import { canonicalJson } from '../../src/canonical-json.mjs'
import { agentContextDigest } from '../../src/agent-context/index.mjs'
import { hashAutomationContract } from '../../src/automation-integration/index.mjs'
import { judgmentBytesDigest,judgmentCanonicalDigest,validateJudgmentOutput,validateJudgmentTrajectory,validateJudgmentTrajectoryChain } from '../../src/judgment/index.mjs'
import { fixture,freeze } from './helpers.mjs'

for(const vector of fixture('digest-vectors.json').vectors) {
  test(`shared digest vector: ${vector.vector_id}`,()=>{
    assert.equal(canonicalJson(vector.value),vector.canonical_utf8)
    assert.equal(judgmentBytesDigest(vector.canonical_utf8),vector.bytes_digest)
    assert.equal(judgmentCanonicalDigest(vector.kind,vector.value),vector.canonical_digest)
    assert.notEqual(vector.bytes_digest,vector.canonical_digest,'raw bytes and domain-separated identity are distinct')
  })
}

test('source E5 and AgentContext digests retain their native codecs',()=>{
  const native=JSON.parse(fs.readFileSync(new URL('../../fixtures/agent-context/v1/automation-results-vector.json',import.meta.url),'utf8'))
  assert.equal(hashAutomationContract('event',native.event),native.event_digest)
  const input=fixture('historical-run-input.json')
  assert.equal(input.context.elements[0].reference.digest,native.event_digest)
  const ac=JSON.parse(fs.readFileSync(new URL('../../fixtures/agent-context/v1/valid.json',import.meta.url),'utf8'))
  const expected=JSON.parse(fs.readFileSync(new URL('../../fixtures/agent-context/v1/digest-vector.json',import.meta.url),'utf8'))
  assert.equal(agentContextDigest(ac),expected.expected_digest)
})

test('one technical turn records exact sent bytes, unmeasured costs and no semantic session metadata',()=>{
  const trace=fixture('trajectory-valid.json'), input=JSON.parse(trace.input.sent_utf8)
  assert.deepEqual(validateJudgmentTrajectory(trace),[])
  assert.equal(trace.usage.cost.microusd,null)
  for(const key of ['session_ref','runtime_ref','request_id','turn_id']) assert.equal(Object.hasOwn(input,key),false,key)
})

test('changed input, raw reply, source limits and validated reply cannot reuse a trace digest',()=>{
  for(const [change,expected] of [
    [v=>{v.input.sent_utf8=v.input.sent_utf8.replace('documenté','pertinent')},'SENT_INPUT_DIGEST_MISMATCH'],
    [v=>{v.response.raw_utf8+=' '},'RAW_RESPONSE_DIGEST_MISMATCH'],
    [v=>{v.response.validation.output.payload.status='undetermined'},'VALIDATED_OUTPUT_MISMATCH'],
    [v=>{v.limits[0].detail='changed'},'TRACE_LIMIT_CHANGED'],
    [v=>{v.origins[0].reference.digest='b'.repeat(64)},'TRACE_ORIGIN_CHANGED'],
  ]) {
    const trace=fixture('trajectory-valid.json');change(trace)
    assert.ok(validateJudgmentTrajectory(trace).includes(expected),expected)
  }
})

test('a rejected raw response is preserved and never becomes a validated decision',()=>{
  const trace=fixture('trajectory-valid.json'),input=JSON.parse(trace.input.sent_utf8)
  const bad=fixture('conclude-output.json');bad.payload.element_ids=[]
  trace.response={response_ref:'response_001',raw_utf8:canonicalJson(bad),raw_digest:judgmentBytesDigest(canonicalJson(bad)),
    validation:{status:'rejected',output:null,error_codes:validateJudgmentOutput(input,bad)}}
  assert.deepEqual(validateJudgmentTrajectory(trace),[])
  trace.response.validation.status='validated';trace.response.validation.output=bad
  assert.ok(validateJudgmentTrajectory(trace).includes('REJECTION_MISMATCH'))
})

test('malformed and duplicate-key model replies are explicitly rejected',()=>{
  for(const raw of ['not JSON','{"move":"approve","move":"stop"}']) {
    const trace=fixture('trajectory-valid.json')
    trace.response={response_ref:'response_001',raw_utf8:raw,raw_digest:judgmentBytesDigest(raw),validation:{status:'rejected',output:null,error_codes:['OUTPUT_JSON']}}
    assert.deepEqual(validateJudgmentTrajectory(trace),[])
  }
})

test('actual consultation result is exact, and inaccessible references never become read content',()=>{
  const trace=fixture('trajectory-valid.json'),input=fixture('consultable-input.json')
  const vector=fixture('conformance.json').cases.find(v=>v.case_id==='relevant_source_not_yet_consulted')
  trace.input={sent_utf8:canonicalJson(input),sent_digest:judgmentBytesDigest(canonicalJson(input)),canonical_digest:judgmentCanonicalDigest('input',input)}
  trace.response={response_ref:'response_001',raw_utf8:canonicalJson(vector.output),raw_digest:judgmentBytesDigest(canonicalJson(vector.output)),validation:{status:'validated',output:vector.output,error_codes:[]}}
  trace.limits=structuredClone(input.context.limits)
  const result=structuredClone(input.context.elements[1]);result.content_verification='matched';result.text='Verified proof bytes read by the server.';result.limit_ids=['l_history']
  trace.consultations=[{consult_id:'consult_proof',status:'read',result,limit_ids:['l_history']}]
  assert.deepEqual(validateJudgmentTrajectory(trace),[])
  trace.consultations[0].result.reference.ref='artifact:substitute'
  assert.ok(validateJudgmentTrajectory(trace).includes('CONSULT_SUBSTITUTION'))
  trace.consultations[0]={consult_id:'consult_proof',status:'unavailable',result:null,limit_ids:['l_reference']}
  assert.deepEqual(validateJudgmentTrajectory(trace),[])
})

test('feedback is separate from effect approvals and unknown measurements cannot be invented',()=>{
  const trace=fixture('trajectory-valid.json')
  trace.human_feedback={kind:'judgment_feedback',effect_approval:false,reference:{ref:'feedback:fixture',digest:null,digest_scheme:null},rating:'useful',expected_move:'conclude',advisory:{content_trust:'advisory_data',ignored_by_authority:true,text:'Helpful qualification.'}}
  assert.deepEqual(validateJudgmentTrajectory(trace),[])
  trace.human_feedback.effect_approval=true
  assert.deepEqual(validateJudgmentTrajectory(trace),['TRAJECTORY_SCHEMA'])
  trace.human_feedback=null;trace.usage.cost.microusd=0
  assert.ok(validateJudgmentTrajectory(trace).includes('COST_METHOD_MISMATCH'))
  trace.usage.cost.microusd=null;trace.usage.tokens.input=1
  assert.ok(validateJudgmentTrajectory(trace).includes('TOKENS_METHOD_MISMATCH'))
})

test('trace validation on immutable snapshots never modifies the evidence',()=>{
  const trace=freeze(fixture('trajectory-valid.json')),before=canonicalJson(trace)
  for(let i=0;i<5;i++)assert.deepEqual(validateJudgmentTrajectory(trace),[])
  assert.equal(canonicalJson(trace),before)
})
