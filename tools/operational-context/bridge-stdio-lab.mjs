import { fileURLToPath } from 'node:url'
import path from 'node:path'

if (!process.argv.includes('--lab')) {
  process.stderr.write('refused: laboratory harness requires explicit --lab flag\n')
  process.exit(2)
}

const [
  { default: pg },
  { applyOperationalContextMigration },
  { createOperationalContextKernel },
  { SimulatedAuthority },
  { validateTrust },
  { createOperationalContextBridge },
  { OC_BRIDGE_BOUNDS, bridgeFailure },
  { ocError },
] = await Promise.all([
  import('pg'),
  import('../../src/operational-context/migrate.mjs'),
  import('../../src/operational-context/kernel.mjs'),
  import('../../src/operational-context/authority.mjs'),
  import('../../src/operational-context/contracts.mjs'),
  import('../../src/operational-context/bridge.mjs'),
  import('../../src/operational-context/bridge-protocol.mjs'),
  import('../../src/operational-context/errors.mjs'),
])

function invokedDirectly() {
  const self = fileURLToPath(import.meta.url)
  const argv1 = process.argv[1] ? path.resolve(process.argv[1]) : ''
  return self === argv1
}

function parseHostTrust() {
  try {
    return validateTrust(JSON.parse(process.env.OC_HOST_TRUST_JSON ?? ''))
  } catch {
    process.stderr.write('refused: host trust injection required\n')
    process.exit(1)
  }
}

function parseLabGrants() {
  try {
    const grants = JSON.parse(process.env.OC_LAB_GRANTS_JSON ?? '')
    if (!Array.isArray(grants)) throw new Error('grants')
    return grants
  } catch {
    process.stderr.write('refused: lab grants required\n')
    process.exit(1)
  }
}

class BoundedStdin {
  constructor(stream, maxBytes) {
    this.stream = stream
    this.maxBytes = maxBytes
    this.buffer = Buffer.alloc(0)
    this.ended = false
  }

  async readLine() {
    while (true) {
      const newline = this.buffer.indexOf(0x0a)
      if (newline !== -1) {
        let line = this.buffer.subarray(0, newline)
        if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1)
        this.buffer = this.buffer.subarray(newline + 1)
        return { line: line.toString('utf8') }
      }
      if (this.buffer.length > this.maxBytes) return { overflow: true }
      const chunk = await this.#readChunk()
      if (chunk === null) {
        if (this.buffer.length === 0) return { eof: true }
        const leftover = this.buffer
        this.buffer = Buffer.alloc(0)
        return {
          line: leftover.toString('utf8'),
          overflow: leftover.length > this.maxBytes,
        }
      }
      this.buffer = Buffer.concat([this.buffer, chunk])
      if (this.buffer.length > this.maxBytes && this.buffer.indexOf(0x0a) === -1) {
        return { overflow: true }
      }
    }
  }

  #readChunk() {
    if (this.ended) return Promise.resolve(null)
    return new Promise((resolve, reject) => {
      const onData = chunk => {
        cleanup()
        this.stream.pause()
        resolve(chunk)
      }
      const onEnd = () => {
        cleanup()
        this.ended = true
        resolve(null)
      }
      const onError = error => {
        cleanup()
        reject(error)
      }
      const cleanup = () => {
        this.stream.off('data', onData)
        this.stream.off('end', onEnd)
        this.stream.off('error', onError)
      }
      this.stream.once('data', onData)
      this.stream.once('end', onEnd)
      this.stream.once('error', onError)
      this.stream.resume()
    })
  }
}

async function serve(bridge) {
  const stdin = new BoundedStdin(process.stdin, OC_BRIDGE_BOUNDS.max_request_utf8_bytes)
  for (;;) {
    const item = await stdin.readLine()
    if (item.eof) return 0
    if (item.overflow) {
      process.stdout.write(`${JSON.stringify(bridgeFailure('', ocError('OC_BOUND_EXCEEDED', 'request exceeds UTF-8 bound')))}\n`)
      return 1
    }
    const response = await bridge.handle(item.line)
    process.stdout.write(`${JSON.stringify(response)}\n`)
  }
}

async function startBridgeStdioLab() {
  const url = process.env.DUBSAR_TEST_POSTGRES_URL
  if (!url) {
    process.stderr.write('refused: disposable PostgreSQL required\n')
    process.exit(1)
  }
  const hostTrust = parseHostTrust()
  const grants = parseLabGrants()
  const authority = new SimulatedAuthority()
  for (const grant of grants) authority.grant(grant)

  const pools = []
  const runtime = new pg.Pool({
    connectionString: url,
    options: '-c role=dubsar_context_runtime',
    max: 4,
    connectionTimeoutMillis: 3000,
    statement_timeout: 5000,
  })
  pools.push(runtime)
  if (process.env.OC_LAB_MIGRATE === '1') {
    const owner = new pg.Pool({
      connectionString: url,
      max: 2,
      connectionTimeoutMillis: 3000,
      statement_timeout: 5000,
    })
    pools.push(owner)
    await applyOperationalContextMigration(owner)
  }

  const now = process.env.OC_LAB_CLOCK_NOW
  const kernel = createOperationalContextKernel({
    pool: runtime,
    authority,
    clock: now ? { now: () => now } : undefined,
  })
  const bridge = createOperationalContextBridge({
    kernel,
    async resolveTrust() {
      return hostTrust
    },
  })
  process.stderr.write(`${JSON.stringify({ lab: true, pid: process.pid, ready: true })}\n`)
  try {
    return await serve(bridge)
  } finally {
    await Promise.all(pools.map(pool => pool.end()))
  }
}

if (invokedDirectly()) {
  startBridgeStdioLab().then(code => {
    process.exit(code ?? 0)
  }).catch(() => {
    process.stderr.write('refused: laboratory harness failed closed\n')
    process.exit(1)
  })
}
