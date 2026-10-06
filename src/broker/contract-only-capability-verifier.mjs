import { assertContract } from '../contracts.mjs'
import { BrokerRejection } from './broker-error.mjs'

/**
 * A deliberately non-cryptographic verifier for the Lot 2B in-memory pilot.
 * It validates the claims contract and the approval binding only. A future
 * authority adapter must replace it; this class is not a JWT or PKI verifier.
 */
export class ContractOnlyCapabilityVerifier {
  verify({ claims, approval }) {
    try {
      assertContract('capability-claims', claims)
      assertContract('approval-record', approval)
    } catch {
      throw new BrokerRejection('BROKER_CAPABILITY_INVALID')
    }
    if (claims.approval_id !== approval.approval_id) {
      throw new BrokerRejection('BROKER_APPROVAL_MISMATCH')
    }
    return structuredClone(claims)
  }
}
