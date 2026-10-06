import { pathToFileURL } from 'node:url'
import { resolve, isAbsolute } from 'node:path'
import { closed, text } from '../human-identity/proof.mjs'

export const MAX_FRAME = 4 * 1024 * 1024
export function encodeFrame(value) {
  const body = Buffer.from(JSON.stringify(value), 'utf8')
  if (body.length > MAX_FRAME) throw new Error('EXACT_FRAME_TOO_LARGE')
  const header = Buffer.alloc(4); header.writeUInt32BE(body.length)
  return Buffer.concat([header, body])
}
export async function serve({ input, output, service, generation, protocol = 'dubsar.exact-ipc/1' }) {
  text(generation)
  if (!['dubsar.exact-ipc/1', 'dubsar.exact-ipc/2'].includes(protocol)) throw new Error('EXACT_CHANNEL_INVALID')
  let buffer = Buffer.alloc(0), pending = null
  const send = value => new Promise((ok, fail) => output.write(encodeFrame(value), error => error ? fail(error) : ok()))
  for await (const chunk of input) {
    buffer = Buffer.concat([buffer, chunk])
    if (buffer.length > MAX_FRAME + 4) throw new Error('EXACT_FRAME_TOO_LARGE')
    if (pending === null && buffer.length >= 4) {
      pending = buffer.readUInt32BE(0)
      if (!pending || pending > MAX_FRAME) throw new Error('EXACT_FRAME_INVALID')
    }
    if (pending !== null && buffer.length >= pending + 4) {
      if (buffer.length !== pending + 4) throw new Error('EXACT_PIPELINING_DENIED')
      const frame = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(4)))
      closed(frame, ['schema', 'generation', 'request_id', 'operation', 'params'])
      if (frame.schema !== protocol || frame.generation !== generation) throw new Error('EXACT_CHANNEL_INVALID')
      const operations = protocol === 'dubsar.exact-ipc/2' ? ['prepare', 'view', 'decide', 'lifecycle'] : ['prepare', 'view', 'decide']
      if (!operations.includes(frame.operation)) throw new Error('EXACT_OPERATION_INVALID')
      text(frame.request_id)
      let response
      try { response = { ok: true, result: await service.handle(frame.operation, frame.params) } }
      catch (error) { response = { ok: false, error: /^(HUMAN|EXACT|ARTIFACT)_[A-Z_]+$/.test(error.code ?? '') ? error.code : 'EXACT_AUTHORITY_FAILED' } }
      await send({ schema: protocol, generation, request_id: frame.request_id, ...response })
      buffer = Buffer.alloc(0); pending = null
    }
  }
  if (buffer.length) throw new Error('EXACT_FRAME_TRUNCATED')
}

// Trusted composition module is an explicit argv path, never request-controlled.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [, , compositionPath, generation] = process.argv
    if (!isAbsolute(compositionPath ?? '')) throw new Error('composition required')
    const composition = await import(pathToFileURL(compositionPath).href)
    const runtime = await composition.createAuthority()
    try { await serve({ input: process.stdin, output: process.stdout, service: runtime.service, generation, protocol: runtime.protocol }) }
    finally { await runtime.close() }
  } catch { process.stderr.write('EXACT_AUTHORITY_STOPPED\n'); process.exitCode = 1 }
}
