import { BrokerRejection } from './broker-error.mjs'

export class PostgresActionStore {
  #pool

  constructor({ pool } = {}) {
    if (typeof pool?.connect !== 'function') throw new TypeError('BROKER_POSTGRES_POOL_REQUIRED')
    this.#pool = pool
  }

  async claim(input) {
    return this.#transaction(client => this.#claim(client, input))
  }

  // Only the trusted records port supplies this one-use, callback-scoped handle.
  // It owns BEGIN/COMMIT/ROLLBACK; never acquire a second claim connection here.
  async claimInTransaction(input, transaction) {
    if (typeof transaction?.run !== 'function') throw new BrokerRejection('BROKER_ADMISSION_TRANSACTION_REQUIRED')
    try { return await transaction.run(client => this.#claim(client, input)) } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_STORAGE_UNAVAILABLE')
    }
  }

  async #claim(client, {
    actionId,
    proposal,
    proposalDigest,
    claims,
    kid,
    fingerprint,
    actionDigest,
    approvalDigest,
    approvalMaxActions,
    pendingContext,
    observedAt,
    assertAdmissionCurrent,
  }) {
      let result
      try {
        result = await client.query(
          `SELECT dubsar_broker.claim_action(
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15::jsonb, $16, $17, $18, $19, $20, $21
          ) AS claim`,
          [
            actionId,
            proposal.proposal_id,
            proposalDigest,
            proposal.workflow_id,
            proposal.workflow_digest,
            proposal.approval_id,
            approvalDigest,
            approvalMaxActions,
            proposal.run_id,
            proposal.step_id,
            actionDigest,
            claims.payload_digest,
            claims.subject_workload_id,
            proposal.workload_identity.instance_id,
            JSON.stringify(pendingContext),
            claims.jti,
            kid,
            claims.expires_at,
            proposal.idempotency_key,
            fingerprint,
            observedAt,
          ],
        )
      } catch (error) {
        if (error?.constraint === 'broker_consumed_jtis_pkey') {
          throw new BrokerRejection('BROKER_CAPABILITY_REPLAY')
        }
        throw error
      }
      const claim = result.rows[0]?.claim
      // Exact-mode caller holds the authoritative decision lock until this
      // transaction commits. Recheck its clock after SQL lock waits; a throw
      // rolls back JTI consumption, approval usage and the pending action.
      if (assertAdmissionCurrent !== undefined) await assertAdmissionCurrent()
      if (claim?.kind === 'idempotency_conflict') throw new BrokerRejection('BROKER_IDEMPOTENCY_CONFLICT')
      if (claim?.kind === 'approval_conflict') throw new BrokerRejection('BROKER_APPROVAL_DIGEST_CONFLICT')
      if (claim?.kind === 'approval_limit') throw new BrokerRejection('BROKER_APPROVAL_ACTION_LIMIT_EXCEEDED')
      if (!['claimed', 'completed', 'in_flight'].includes(claim?.kind)) {
        throw new BrokerRejection('BROKER_STORAGE_RESPONSE_INVALID')
      }
      return claim
  }

  async finalize({ actionId, toState, receipt, reasonCode, brokerIdentity, observedAt }) {
    return this.#transaction(async client => {
      const result = await client.query(
        `SELECT dubsar_broker.finalize_action(
          $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9
        ) AS receipt`,
        [
          actionId,
          toState,
          receipt.receipt_id,
          receipt.capability_jti,
          receipt.evidence_chain.event_digest,
          JSON.stringify(receipt),
          reasonCode,
          brokerIdentity.workload_id,
          observedAt,
        ],
      )
      if (result.rows[0]?.receipt === undefined) throw new BrokerRejection('BROKER_STORAGE_RESPONSE_INVALID')
      return result.rows[0].receipt
    })
  }

  async listInFlight() {
    return this.#query(async client => {
      const result = await client.query(
        `SELECT action_id, pending_context
         FROM dubsar_broker.broker_actions
         WHERE state = 'IN_FLIGHT'
         ORDER BY action_id`,
      )
      return result.rows.map(row => ({
        actionId: row.action_id,
        pendingContext: row.pending_context,
      }))
    })
  }

  async getAction(actionId) {
    return this.#query(async client => {
      const action = await client.query(
        `SELECT action_id, state, created_at, updated_at, version
         FROM dubsar_broker.broker_actions WHERE action_id = $1`,
        [actionId],
      )
      if (action.rowCount === 0) return null
      const transitions = await client.query(
        `SELECT transition_document FROM dubsar_broker.broker_action_transitions
         WHERE action_id = $1 ORDER BY sequence`,
        [actionId],
      )
      return {
        action_id: action.rows[0].action_id,
        state: action.rows[0].state,
        created_at: new Date(action.rows[0].created_at).toISOString(),
        updated_at: new Date(action.rows[0].updated_at).toISOString(),
        version: Number(action.rows[0].version),
        transitions: transitions.rows.map(row => row.transition_document),
      }
    })
  }

  async getReceipt(actionId) {
    return this.#query(async client => {
      const result = await client.query(
        'SELECT receipt_document FROM dubsar_broker.broker_receipts WHERE action_id = $1',
        [actionId],
      )
      return result.rowCount === 0 ? null : result.rows[0].receipt_document
    })
  }

  async #transaction(operation) {
    return this.#query(async client => {
      await client.query('BEGIN')
      try {
        await client.query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
        const result = await operation(client)
        await client.query('COMMIT')
        return structuredClone(result)
      } catch (error) {
        await client.query('ROLLBACK')
        if (error instanceof BrokerRejection) throw error
        if (error?.code === '40001' || error?.code === '40P01') {
          throw new BrokerRejection('BROKER_STORAGE_CONCURRENCY_RETRY_REQUIRED')
        }
        if (error?.code === '23514') throw new BrokerRejection('BROKER_TRANSITION_FORBIDDEN')
        if (error?.code === 'P0002') throw new BrokerRejection('BROKER_ACTION_NOT_FOUND')
        throw error
      }
    })
  }

  async #query(operation) {
    let client
    try {
      client = await this.#pool.connect()
      return await operation(client)
    } catch (error) {
      if (error instanceof BrokerRejection) throw error
      throw new BrokerRejection('BROKER_STORAGE_UNAVAILABLE')
    } finally {
      client?.release()
    }
  }
}
