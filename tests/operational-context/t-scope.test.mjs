import assert from 'node:assert/strict'
import test from 'node:test'

test('T01–T23 implemented versus deferred for OC-KERNEL-01', () => {
  const implemented = [
    'T01 admit observation without mission',
    'T02 replay / disordered delivery identity',
    'T03 stale vs timeout/impossible vs proven absence',
    'T04 comparable conflict vs unlinked homonym',
    'T06 out-of-scope request and right revocation',
    'T08 rebuild from stored observations',
    'T09 two readers distinct perimeters',
    'T10 second environment isolation',
    'T11 delivery identity reused with different content',
    'T12 revoke mapping invalidates current qualification',
    'T14 reread after revocation without resurrection',
    'T16 lost acknowledgement then identical replay',
    'T17 concurrent association/observation versions',
    'T19 incompatible corrections expose divergence',
    'T20 hidden support does not leak through restricted view',
    'T21 time alone can stale a measure',
    'T23 rebuild does not replay effects',
  ]
  const deferred = [
    'T05 LLM self-claim is not a producer channel (needs live LLM harness)',
    'T07 Exact Action UNOBSERVED / work-registry binding',
    'T13 notification rediffusion and work-proposal dedup',
    'T15 mission expectation due-date / provider pagination cursor',
    'T18 provider cursor reset / recycled source generation',
    'T22 signed action-field binding from a context view',
  ]
  assert.equal(implemented.length + deferred.length, 23)
  assert.equal(new Set([...implemented, ...deferred]).size, 23)
})
