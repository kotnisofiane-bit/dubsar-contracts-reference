/**
 * Process-memory replay adapter for the reference Task Manager verifier.
 *
 * `consumeOnce` may be synchronous or return a Promise; `consumeTaskLease`
 * and `admit` await the result. A value other than `true` is a replay.
 * Atomicity is only guaranteed on the Node.js event loop. It is not durable
 * across processes or restarts; production Task Managers must inject a shared
 * store with the same `consumeOnce(identity, expiresAt)` contract.
 */
export class InMemoryTaskLeaseReplayStore {
  #consumed = new Set()

  consumeOnce(identity, expiresAt) {
    if (typeof identity !== 'string' || identity.length < 8) {
      throw new TypeError('task lease replay identity is invalid')
    }
    if (typeof expiresAt !== 'string' || !Number.isFinite(Date.parse(expiresAt))) {
      throw new TypeError('task lease replay expiry is invalid')
    }
    if (this.#consumed.has(identity)) return false
    this.#consumed.add(identity)
    return true
  }
}
