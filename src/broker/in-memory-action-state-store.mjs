import { assertContract } from '../contracts.mjs'
import { BrokerRejection, reject } from './broker-error.mjs'

const ACTION_ID = /^action_[a-z0-9][a-z0-9_-]{7,127}$/

export class InMemoryActionStateStore {
  #records = new Map()

  create(actionId, observedAt) {
    if (!ACTION_ID.test(actionId) || typeof observedAt !== 'string') reject('BROKER_STATE_RECORD_INVALID')
    if (this.#records.has(actionId)) reject('BROKER_ACTION_ALREADY_EXISTS')
    this.#records.set(actionId, {
      action_id: actionId,
      state: 'RECEIVED',
      created_at: observedAt,
      transitions: [],
    })
    return this.get(actionId)
  }

  transition(actionId, toState, event) {
    const record = this.#records.get(actionId)
    if (record === undefined) reject('BROKER_ACTION_NOT_FOUND')
    const sequence = record.transitions.length + 1
    const suffix = actionId.slice('action_'.length)
    const transition = {
      schema: 'dubsar.state-transition.v1',
      contract_version: '1.0.0',
      transition_id: `transition_${suffix}_${String(sequence).padStart(3, '0')}`,
      action_id: actionId,
      from_state: record.state,
      to_state: toState,
      actor: {
        authority: event?.authority,
        identity_ref: event?.identity_ref,
      },
      reason_code: event?.reason_code,
      observed_at: event?.observed_at,
    }
    try {
      assertContract('state-transition', transition)
    } catch {
      throw new BrokerRejection('BROKER_TRANSITION_FORBIDDEN')
    }
    record.state = toState
    record.transitions.push(transition)
    return structuredClone(transition)
  }

  get(actionId) {
    const record = this.#records.get(actionId)
    return record === undefined ? null : structuredClone(record)
  }

  snapshot() {
    return [...this.#records.values()].map(record => structuredClone(record))
  }
}
