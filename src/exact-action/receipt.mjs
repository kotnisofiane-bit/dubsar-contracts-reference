import { domainSeparatedHash } from '../canonical-json.mjs'
import { assertContract, receiptEvidenceDigest } from '../contracts.mjs'
import { assertExact, hashExact, same } from './contracts.mjs'

export function exactReceiptDigest(receipt) {
  const preimage = structuredClone(receipt)
  delete preimage.evidence_chain.event_digest
  return domainSeparatedHash('dubsar.evidence.action-receipt.v2', preimage)
}
export function sealExactReceipt(receipt, proof) {
  if (proof === undefined) return receipt
  assertContract('action-receipt', receipt)
  const sealed = { ...structuredClone(receipt), schema: 'dubsar.action-receipt.v2', contract_version: '2.0.0',
    exact_action: structuredClone(proof), business_outcome: 'UNOBSERVED' }
  sealed.evidence_chain.event_digest = exactReceiptDigest(sealed)
  assertExactReceipt(sealed)
  return sealed
}
export function assertExactReceipt(receipt) {
  assertExact('receipt', receipt)
  same(receipt.schema, 'dubsar.action-receipt.v2')
  same(receipt.contract_version, '2.0.0')
  same(receipt.business_outcome, 'UNOBSERVED')
  assertExact('proof', receipt.exact_action)
  same(receipt.exact_action.binding_digest, hashExact('binding', receipt.exact_action.binding))
  if (receipt.after_state === 'SUCCEEDED'
    && (receipt.result.provider_status < 200 || receipt.result.provider_status >= 300)) {
    throw new Error('EXACT_RECEIPT_PROVIDER_STATUS_INVALID')
  }
  for (const key of ['proposal_id', 'run_id', 'step_id']) same(receipt[key], receipt.exact_action.binding[key])
  same(receipt.evidence_chain.event_digest, exactReceiptDigest(receipt))
  const legacy = structuredClone(receipt)
  delete legacy.exact_action
  delete legacy.business_outcome
  legacy.schema = 'dubsar.action-receipt.v1'
  legacy.contract_version = '1.0.0'
  legacy.evidence_chain.event_digest = receiptEvidenceDigest(legacy)
  assertContract('action-receipt', legacy)
  return receipt
}
