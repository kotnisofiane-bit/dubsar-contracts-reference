// Qualification-only observer: no SQL values, raw errors, identities or secrets.
export function diagnosticPool(pool, events, source) {
  let connection = 0
  return { async connect() {
    const client = await pool.connect(), id = ++connection
    return { on: (...args) => client.on(...args),
      once: (...args) => client.once(...args),
      removeListener: (...args) => client.removeListener(...args),
      async query(sql, values) {
      const stage = /claim_action\(/.test(sql) ? 'claim' : /finalize_action\(/.test(sql) ? 'finalize'
        : ['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) ? sql : 'other'
      events.push({ source, connection: id, stage, event: 'start' })
      try {
        const result = await client.query(sql, values)
        events.push({ source, connection: id, stage, event: 'ok' })
        return result
      } catch (error) {
        events.push({ source, connection: id, stage, event: 'error',
          sqlstate: /^[0-9A-Z]{5}$/.test(error?.code ?? '') ? error.code : 'UNCLASSIFIED' })
        throw error
      }
    }, release: (...args) => client.release(...args) }
  } }
}

export function diagnosticOutcome(result) {
  return result.status === 'fulfilled' ? { status: result.status, state: result.value?.after_state }
    : { status: result.status, code: /^BROKER_[A-Z_]+$/.test(result.reason?.code ?? '')
      ? result.reason.code : 'UNCLASSIFIED' }
}
