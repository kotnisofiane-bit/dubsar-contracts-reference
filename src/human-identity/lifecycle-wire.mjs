import { createHash, sign, verify, randomUUID } from 'node:crypto'
import { canonicalBytes } from '../canonical-json.mjs'
import { closed, denied, text } from './proof.mjs'

const domain = Buffer.from('dubsar.session-lifecycle/1\0')
const names = ['version', 'issuer', 'audience', 'operation', 'request_id', 'issued_at', 'expires_at', 'body']
export const digestMessage = value => createHash('sha256').update(canonicalBytes(value)).digest('hex')
export function signMessage({ issuer, audience, operation, body, privateKey, now = Date.now(), requestId = randomUUID() }) {
  const issued = Math.floor(now / 1000)
  const message = { version: 'dubsar.session-lifecycle/1', issuer, audience, operation,
    request_id: requestId, issued_at: issued, expires_at: issued + 30, body }
  return { ...message, signature: sign(null, Buffer.concat([domain, canonicalBytes(message)]), privateKey).toString('base64url') }
}
export function verifyMessage(envelope, { issuer, audience, operations, publicKey, now = Date.now() }) {
  closed(envelope, [...names, 'signature'])
  const { signature, ...message } = structuredClone(envelope)
  for (const key of ['issuer', 'audience', 'operation', 'request_id']) text(message[key])
  if (message.version !== 'dubsar.session-lifecycle/1' || message.issuer !== issuer || message.audience !== audience
    || !operations.includes(message.operation) || !Number.isFinite(now)
    || !Number.isSafeInteger(message.issued_at) || !Number.isSafeInteger(message.expires_at)
    || message.issued_at * 1000 > now || message.expires_at * 1000 <= now
    || message.expires_at <= message.issued_at || message.expires_at - message.issued_at > 30
    || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)
    || !verify(null, Buffer.concat([domain, canonicalBytes(message)]), publicKey, Buffer.from(signature, 'base64url')))
    throw denied('HUMAN_LIFECYCLE_DENIED')
  return message
}

// One outstanding challenge per call; no positive cache, and timeout cancels I/O.
export function createSourceVerifier({ exchange, issuer, audience, privateKey, publicKey, clock, timeoutMs = 1000 }) {
  if (typeof exchange !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1000)
    throw denied('HUMAN_SOURCE_CONFIG_INVALID')
  return async body => {
    const request = signMessage({ issuer, audience, operation: 'verify', body, privateKey, now: Date.parse(clock.now()) })
    const controller = new AbortController()
    let timer
    try {
      const response = await Promise.race([exchange(request, controller.signal), new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(denied('HUMAN_SOURCE_UNAVAILABLE')) }, timeoutMs)
      })])
      const message = verifyMessage(response, { issuer: audience, audience: issuer, operations: ['verified'], publicKey, now: Date.parse(clock.now()) })
      closed(message.body, ['request_id', 'request_digest', 'active', 'expires_at'])
      if (message.body.request_id !== request.request_id || message.body.request_digest !== digestMessage(request)
        || message.body.active !== true || !Number.isSafeInteger(message.body.expires_at)
        || message.body.expires_at * 1000 <= Date.parse(clock.now())) throw denied('HUMAN_SOURCE_DENIED')
      return message.body.expires_at
    } catch { throw denied('HUMAN_SOURCE_DENIED') }
    finally { clearTimeout(timer); controller.abort() }
  }
}
