import assert from 'node:assert/strict'
import test from 'node:test'
import { canonicalJson } from '../../src/canonical-json.mjs'
import { judgmentBytesDigest,judgmentCanonicalDigest,validateJudgmentTrajectoryChain } from '../../src/judgment/index.mjs'
import { fixture,freeze } from './helpers.mjs'

function changeInput(turn,change) {
  const input=JSON.parse(turn.input.sent_utf8);change(input)
  turn.input={sent_utf8:canonicalJson(input),sent_digest:judgmentBytesDigest(canonicalJson(input)),canonical_digest:judgmentCanonicalDigest('input',input)}
}

test('offline revision chain retains the same claim and scope after a new qualified read',()=>{
  const vector=fixture('revision-trajectory.json')
  assert.notEqual(vector.turns[0].runtime_ref,vector.turns[1].runtime_ref,'technical restart correlation does not change semantic scope')
  assert.deepEqual(validateJudgmentTrajectoryChain(freeze(vector.turns)),vector.expected_error_codes)
})

test('rewritten prior turn or another human session cannot be attached to a trajectory',()=>{
  const vector=fixture('revision-trajectory.json')
  vector.turns[0].versions.model.revision='changed'
  assert.ok(validateJudgmentTrajectoryChain(vector.turns).includes('PREVIOUS_TURN_DIGEST_MISMATCH'))
  const another=fixture('revision-trajectory.json');another.turns[1].session_ref='other_session'
  assert.ok(validateJudgmentTrajectoryChain(another.turns).includes('CHAIN_BINDING_CHANGED'))
})

test('a revision cannot switch project/mission or silently change the supplied claim meaning',()=>{
  for(const [change,expected] of [
    [input=>{input.scope.mission_id='other_mission'},'JUDGMENT_SCOPE_CHANGED'],
    [input=>{input.claims[0].statement='A different claim'},'REVISION_CLAIM_CHANGED'],
  ]) {
    const {turns}=fixture('revision-trajectory.json')
    changeInput(turns[1],change)
    assert.ok(validateJudgmentTrajectoryChain(turns).includes(expected),expected)
  }
})

test('claim/support status is compared with the actual previous validated reply',()=>{
  const {turns}=fixture('revision-trajectory.json')
  changeInput(turns[1],input=>{input.previous_judgment.element_ids=[]})
  assert.ok(validateJudgmentTrajectoryChain(turns).includes('PREVIOUS_JUDGMENT_MISMATCH'))
})

test('a missing prefix, duplicate turn or empty chain is explicitly refused',()=>{
  const {turns}=fixture('revision-trajectory.json')
  assert.ok(validateJudgmentTrajectoryChain([turns[1]]).includes('CHAIN_START_NOT_ASSERTED'))
  turns[1].turn_id=turns[0].turn_id
  assert.ok(validateJudgmentTrajectoryChain(turns).includes('DUPLICATE_TURN'))
  assert.deepEqual(validateJudgmentTrajectoryChain([]),['TRAJECTORY_CHAIN_BOUND'])
})
