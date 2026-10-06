import test from 'node:test'
import assert from 'node:assert/strict'
import { Readable, Writable } from 'node:stream'
import { serve, encodeFrame, MAX_FRAME } from '../src/exact-action/stdio-authority.mjs'

function output() { const chunks = []; return { chunks, stream: new Writable({ write(chunk, encoding, done) { chunks.push(chunk); done() } }) } }
const frame = { schema: 'dubsar.exact-ipc/1', generation: 'generation:1', request_id: 'request:1', operation: 'view', params: { text: 'été 日本' } }
test('A01 frames preserve UTF8 across arbitrary chunk boundaries', async () => {
  const bytes = encodeFrame(frame), out = output()
  await serve({ input: Readable.from([...bytes].map(b => Buffer.from([b]))), output: out.stream,
    service: { handle: async (_, p) => p }, generation: frame.generation })
  const result = Buffer.concat(out.chunks)
  assert.equal(result.readUInt32BE(0), result.length - 4)
  assert.deepEqual(JSON.parse(result.subarray(4)).result, frame.params)
})
test('A01 wrong generation, unknown envelope fields, truncation and oversized frame fail closed', async () => {
  for (const bytes of [encodeFrame({ ...frame, generation: 'other' }), encodeFrame({ ...frame, extra: true }),
    encodeFrame(frame).subarray(0, 12), Buffer.from([255, 255, 255, 255])]) {
    let calls = 0
    await assert.rejects(serve({ input: Readable.from([bytes]), output: output().stream,
      service: { handle: async () => { calls++ } }, generation: frame.generation }))
    assert.equal(calls, 0)
  }
  assert.throws(() => encodeFrame({ x: 'a'.repeat(MAX_FRAME) }), /TOO_LARGE/)
})
test('A08 internal exception details never appear in IPC responses', async () => {
  const out = output()
  await serve({ input: Readable.from([encodeFrame(frame)]), output: out.stream,
    service: { handle() { throw new Error('private diagnostic') } }, generation: frame.generation })
  assert.equal(JSON.parse(Buffer.concat(out.chunks).subarray(4)).error, 'EXACT_AUTHORITY_FAILED')
})
