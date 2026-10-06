import { canonicalJson } from '../../src/canonical-json.mjs'
import { judgmentSchemas,judgmentBytesDigest,judgmentCanonicalDigest,validateJudgmentInput,validateJudgmentOutput,validateJudgmentTrajectory,validateJudgmentTrajectoryChain } from '../../src/judgment/index.mjs'
import { fixture,vectorInput } from '../../tests/judgment/helpers.mjs'

const vectors=fixture('conformance.json').cases
for(const vector of vectors) {
  const input=vectorInput(vector),inputErrors=validateJudgmentInput(input)
  const errors=validateJudgmentOutput(input,vector.output)
  if(inputErrors.length || (errors.length===0)!==vector.expected.valid || canonicalJson(errors)!==canonicalJson(vector.expected.error_codes))throw new Error(`Nonconforming vector: ${vector.case_id}`)
}
const digests=fixture('digest-vectors.json').vectors
for(const vector of digests) {
  if(canonicalJson(vector.value)!==vector.canonical_utf8 || judgmentBytesDigest(vector.canonical_utf8)!==vector.bytes_digest || judgmentCanonicalDigest(vector.kind,vector.value)!==vector.canonical_digest)throw new Error(`Digest mismatch: ${vector.vector_id}`)
}
const traceErrors=validateJudgmentTrajectory(fixture('trajectory-valid.json'))
if(traceErrors.length)throw new Error(`Trace rejected: ${traceErrors.join(',')}`)
const chainErrors=validateJudgmentTrajectoryChain(fixture('revision-trajectory.json').turns)
if(chainErrors.length)throw new Error(`Revision chain rejected: ${chainErrors.join(',')}`)
const references=judgmentSchemas.assertAllReferencesClosed()
process.stdout.write(JSON.stringify({gate:'JUDGMENT-CONTRACT-01',schemas:judgmentSchemas.schemaNames().length,conformance_vectors:vectors.length,digest_vectors:digests.length,revision_turns:2,closed_references:references.length,scope:'pure-local-validation'})+'\n')
