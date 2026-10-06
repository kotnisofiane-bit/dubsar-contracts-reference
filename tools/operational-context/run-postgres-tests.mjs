import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

if (!process.env.DUBSAR_TEST_POSTGRES_URL) {
  process.stderr.write('disposable PostgreSQL required (DUBSAR_TEST_POSTGRES_URL)\n')
  process.exit(1)
}

const root = fileURLToPath(new URL('../../tests/operational-context/postgres/', import.meta.url))
const files = fs.readdirSync(root)
  .filter(name => name.endsWith('.test.mjs'))
  .map(name => path.join(root, name))
if (files.length === 0) {
  process.stderr.write('no PostgreSQL tests found\n')
  process.exit(1)
}

const child = spawn(process.execPath, ['--test', '--test-concurrency=1', ...files], { stdio: 'inherit', env: process.env })
child.on('exit', code => process.exit(code ?? 1))
