import { isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'

const MAX = 65536
const protocol = 'dubsar.document-access-ipc/1'
let composition
try {
  const file = process.argv[2]
  if (!file || !isAbsolute(file)) throw new Error('configuration')
  composition = await (await import(pathToFileURL(file).href)).createDocumentAuthority()
  const parts = []; let length = 0
  for await (const chunk of process.stdin) {
    length += chunk.length
    if (length > MAX + 4) throw new Error('frame')
    parts.push(chunk)
  }
  const input = Buffer.concat(parts)
  if (input.length < 5 || input.readUInt32BE(0) !== input.length - 4) throw new Error('frame')
  const frame = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input.subarray(4)))
  if (!frame || Object.keys(frame).sort().join(',') !== 'operation,params,request_id,schema'
    || frame.schema !== protocol || !/^[a-f0-9-]{36}$/.test(frame.request_id)
    || !['authorize', 'revalidate'].includes(frame.operation)) throw new Error('frame')
  const result = await composition.authority[frame.operation](frame.params)
  const data = Buffer.from(JSON.stringify({ schema: protocol, request_id: frame.request_id, result }))
  if (data.length > MAX) throw new Error('frame')
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(data.length)
  process.stdout.write(Buffer.concat([prefix, data]))
} catch { process.exitCode = 1 }
finally { if (composition?.close) await composition.close() }
