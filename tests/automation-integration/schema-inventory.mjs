import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { SchemaRegistry } from '../../src/schema-validator.mjs';

test('C0-01 schema inventory is closed and all refs are local', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  const set = JSON.parse(fs.readFileSync(path.join(root, 'contracts/automation-integration/v1/contract-set.json')));
  const registry = new SchemaRegistry(path.join(root, 'schemas/automation-integration/v1'));
  assert.deepEqual(registry.schemaNames(), [...set.schemas].sort());
  for (const name of set.schemas) {
    const schema = registry.resolveSchema(name).schema;
    const closed = name === 'common.schema.json' || schema.additionalProperties === false
      || typeof schema.$ref === 'string'
      || (Array.isArray(schema.oneOf) && schema.oneOf.every(branch => branch.additionalProperties === false));
    assert.equal(closed, true, `${name} has a closed root`);
  }
  assert.doesNotThrow(() => registry.assertAllReferencesClosed());
});
