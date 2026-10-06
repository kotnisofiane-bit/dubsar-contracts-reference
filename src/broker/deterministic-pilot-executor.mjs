import { canonicalJson } from '../canonical-json.mjs'
import { BrokerRejection } from './broker-error.mjs'

export const PILOT_ACTION = Object.freeze({
  kind: 'connector_action',
  connector: Object.freeze({ name: 'dubsar.ticketing', version: '1.2.3' }),
  operation: 'create_ticket',
})

export const PILOT_PAYLOAD = Object.freeze({
  priority: 'normal',
  summary: 'DUBSAR Community',
})

export const PILOT_DESTINATION = Object.freeze({
  scheme: 'https',
  host: 'tickets.example.invalid',
  port: 443,
  path_prefix: '/api/v1/tickets',
  methods: Object.freeze(['POST']),
})

export class DeterministicPilotExecutor {
  executionCount = 0

  assertSupported(proposal) {
    if (canonicalJson(proposal.action) !== canonicalJson(PILOT_ACTION)
      || canonicalJson(proposal.payload) !== canonicalJson(PILOT_PAYLOAD)
      || canonicalJson(proposal.destination) !== canonicalJson(PILOT_DESTINATION)) {
      throw new BrokerRejection('BROKER_ACTION_UNSUPPORTED')
    }
  }

  async execute({ proposal }) {
    this.assertSupported(proposal)
    this.executionCount += 1
    return {
      kind: 'success',
      provider_status: 200,
      output: {
        effect: 'none',
        pilot: 'deterministic_ticket_preview',
        summary: proposal.payload.summary,
      },
    }
  }
}
