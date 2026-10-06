import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import test from 'node:test'

const migration = fs.readFileSync(new URL('../migrations/001_durable_action_broker.sql', import.meta.url), 'utf8')
const runner = fs.readFileSync(new URL('../src/broker/postgres-migrations.mjs', import.meta.url), 'utf8')
const store = fs.readFileSync(new URL('../src/broker/postgres-action-store.mjs', import.meta.url), 'utf8')

test('005 changes only finalization lock order and preserves historical migration checksums', () => {
  const next = fs.readFileSync(new URL('../migrations/005_broker_finalization_lock_order.sql', import.meta.url), 'utf8').replace(/\r\n/g, '\n').trim()
  const begin = migration.indexOf('CREATE OR REPLACE FUNCTION dubsar_broker.finalize_action(')
  const end = migration.indexOf('$finalize$;', begin) + '$finalize$;'.length
  const original = migration.slice(begin, end).replace(/\r\n/g, '\n').trim()
  const lock = '  -- Match claim_action: idempotency before action, including deferred JTI FK checks.\n  PERFORM 1 FROM dubsar_broker.broker_idempotency\n  WHERE action_id = requested_action_id\n  FOR UPDATE;\n\n'
  assert.equal(next.replace(lock, ''), original)
  assert.ok(next.indexOf('PERFORM 1 FROM dubsar_broker.broker_idempotency') < next.indexOf('SELECT state INTO current_state'))
  const expected = JSON.parse(fs.readFileSync(new URL('./helpers/historical-migration-hashes.json', import.meta.url), 'utf8'))
  for (const [name, digest] of Object.entries(expected)) {
    assert.equal(createHash('sha256').update(fs.readFileSync(new URL('../migrations/' + name, import.meta.url))).digest('hex'), digest)
  }
})

test('durable Broker schema constrains replay, idempotency, receipts and transitions in PostgreSQL', () => {
  for (const table of [
    'broker_actions',
    'broker_approval_usage',
    'broker_consumed_jtis',
    'broker_idempotency',
    'broker_action_transitions',
    'broker_receipts',
  ]) assert.match(migration, new RegExp(`CREATE TABLE dubsar_broker\\.${table}`))

  assert.match(migration, /jti text PRIMARY KEY/)
  assert.match(migration, /idempotency_key text PRIMARY KEY/)
  assert.match(migration, /proposal_id text NOT NULL UNIQUE/)
  assert.match(migration, /action_id text NOT NULL UNIQUE REFERENCES dubsar_broker\.broker_actions/)
  assert.match(migration, /FOR UPDATE/)
  assert.match(migration, /broker_transitions_allowed CHECK/)
  assert.match(migration, /broker_transitions_authority_allowed CHECK/)
  assert.match(migration, /CREATE OR REPLACE FUNCTION dubsar_broker\.transition_action/)
  assert.doesNotMatch(migration, /DROP\s+(?:DATABASE|SCHEMA)|TRUNCATE/i)
})

test('approval action limits are consumed transactionally by the admitted claim function', () => {
  assert.match(store, /SET TRANSACTION ISOLATION LEVEL READ COMMITTED/)
  assert.match(migration, /approval_digest text PRIMARY KEY/)
  assert.match(migration, /consumed_actions integer NOT NULL/)
  assert.match(migration, /consumed_actions <= max_actions/)
  assert.match(migration, /CREATE OR REPLACE FUNCTION dubsar_broker\.claim_action/)
  assert.match(migration, /FROM dubsar_broker\.broker_approval_usage[\s\S]*FOR UPDATE/)
  assert.match(migration, /pg_advisory_xact_lock\(hashtextextended\('approval:'/)
  assert.match(migration, /UPDATE dubsar_broker\.broker_approval_usage[\s\S]*consumed_actions = consumed_actions \+ 1/)
})

test('the runtime role can mutate only through hardened security-definer functions', () => {
  assert.equal([...migration.matchAll(/SECURITY DEFINER\nSET search_path = pg_catalog, dubsar_broker/g)].length, 3)
  assert.match(migration, /REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_broker FROM dubsar_broker_runtime/)
  assert.match(migration, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_broker FROM PUBLIC/)
  assert.match(migration, /GRANT SELECT \([^)]+\)[\s\S]*TO dubsar_broker_runtime/)
  assert.doesNotMatch(migration, /GRANT CREATE[^;]*TO dubsar_broker_runtime/i)
  assert.match(migration, /GRANT EXECUTE ON FUNCTION dubsar_broker\.claim_action/)
  assert.match(migration, /GRANT EXECUTE ON FUNCTION dubsar_broker\.finalize_action/)
  assert.doesNotMatch(migration, /GRANT EXECUTE ON FUNCTION dubsar_broker\.transition_action/)
  assert.doesNotMatch(migration, /GRANT (?:INSERT|UPDATE|DELETE|ALL)[^;]*TO dubsar_broker_runtime/i)
  assert.doesNotMatch(migration, /\bEXECUTE\s+(?:format\s*\(|['"])/i)
  assert.match(store, /dubsar_broker\.claim_action/)
  assert.match(store, /dubsar_broker\.finalize_action/)
  assert.doesNotMatch(store, /\b(?:INSERT\s+INTO|UPDATE\s+dubsar_broker|DELETE\s+FROM)\b/i)
})

test('migration runner is serialized, checksummed and transactionally idempotent', () => {
  assert.match(runner, /pg_advisory_lock/)
  assert.match(runner, /createHash\('sha256'\)/)
  assert.match(runner, /BROKER_MIGRATION_CHECKSUM_MISMATCH/)
  assert.match(runner, /await client\.query\('BEGIN'\)/)
  assert.match(runner, /await client\.query\('COMMIT'\)/)
  assert.match(runner, /await client\.query\('ROLLBACK'\)/)
})
