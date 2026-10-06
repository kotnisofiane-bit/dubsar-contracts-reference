import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const brokerRoot = fileURLToPath(new URL('../src/broker/', import.meta.url))

test('Lot 2B Broker source has no network, process, secret or runtime integration surface', () => {
  const files = fs.readdirSync(brokerRoot).filter(name => name.endsWith('.mjs')).sort()
  assert.ok(files.length >= 5)
  const source = files.map(name => fs.readFileSync(path.join(brokerRoot, name), 'utf8')).join('\n')
  const forbidden = [
    /node:(?:http|https|net|tls|dns|dgram|child_process|worker_threads)/,
    /\bfetch\s*\(/,
    /\bWebSocket\b/,
    /\bDocker\b/,
    /\b(?:apiKey|clientSecret|accessToken|privateKey)\b/,
    /activepieces/i,
  ]
  for (const pattern of forbidden) assert.doesNotMatch(source, pattern)
  assert.match(source, /ContractOnlyCapabilityVerifier/)
  assert.match(source, /BROKER_AUTHORITY_VERIFIER_REQUIRED/)
  assert.match(source, /INDETERMINATE/)
})
