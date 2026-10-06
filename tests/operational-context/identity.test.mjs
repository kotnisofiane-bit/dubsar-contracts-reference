import assert from 'node:assert/strict'
import test from 'node:test'
import { resourceIdentity, pairFingerprint } from '../../src/operational-context/identity.mjs'
import { resource } from './helpers/fixtures.mjs'

test('AC02 homonyms are not identity and incarnation absence is explicit', () => {
  const left = resourceIdentity(resource({ source_id: 'commandes', label: 'commandes' }))
  const right = resourceIdentity(resource({ source_id: 'commandes', source_instance_id: 'src:crm-other', label: 'commandes' }))
  assert.notEqual(left.local_ref, right.local_ref)
  assert.deepEqual(left.identity.incarnation, { absence: 'not_available' })
  const recycled = resourceIdentity(resource({ incarnation: 'gen-2' }))
  assert.notEqual(recycled.local_ref, left.local_ref)
  assert.equal(recycled.identity.incarnation, 'gen-2')
})

test('AC02 tenant and environment remain distinct', () => {
  const a = resourceIdentity(resource({ tenant_id: 'tenant:a' }))
  const b = resourceIdentity(resource({ tenant_id: 'tenant:b' }))
  const env = resourceIdentity(resource({ environment_id: 'env:prod' }))
  assert.notEqual(a.local_ref, b.local_ref)
  assert.notEqual(a.local_ref, env.local_ref)
})

test('AC05 pair keys stay unambiguous when identifiers contain separators', () => {
  const left = resourceIdentity(resource({ source_id: 'a:b/c|d' }))
  const right = resourceIdentity(resource({ source_id: 'a', namespace: 'b/c|d', source_instance_id: 'src:n8n-b' }))
  const forward = pairFingerprint(left.identity, right.identity, 'same_resource')
  const reverse = pairFingerprint(right.identity, left.identity, 'same_resource')
  assert.equal(forward, reverse)
  assert.notEqual(left.local_ref, right.local_ref)
  assert.throws(() => pairFingerprint(left.identity, left.identity, 'same_resource'))
})
