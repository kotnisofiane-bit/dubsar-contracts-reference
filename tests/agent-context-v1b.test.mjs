import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { SchemaRegistry } from "../src/schema-validator.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaDir = path.join(root, "schemas", "agent-context", "v1");
const fixtures = path.join(root, "fixtures", "agent-context", "v1");
const registry = new SchemaRegistry(schemaDir);

const read = (name) => JSON.parse(fs.readFileSync(path.join(fixtures, name), "utf8"));

test("V1-B Mission View fixture is accepted by the closed schema", () => {
  const value = read("mission-view-valid.json");
  assert.deepEqual(registry.validate("my-work-mission-view.schema.json", value), []);
  const forbidden = structuredClone(value);
  forbidden.permission = "execute";
  assert.ok(registry.validate("my-work-mission-view.schema.json", forbidden).length > 0);
});

test("V1-B Mission View cannot carry implicit authority", () => {
  const value = read("mission-view-valid.json");
  for (const key of ["authority", "human_gate", "permission", "tool_rights"]) {
    const altered = structuredClone(value);
    altered[key] = key === "human_gate" ? true : "granted";
    assert.ok(registry.validate("my-work-mission-view.schema.json", altered).length > 0, key);
  }
});

test("V1-B OC selector fixture is exact and closed", () => {
  const value = read("oc-selection-valid.json");
  assert.deepEqual(registry.validate("my-work-oc-selection.schema.json", value), []);
  assert.equal(value.selection_id, "mywork.release.current_sha");
  assert.equal(value.property, "mywork.release.current_sha");
  assert.equal(value.relation_depth, 0);
  for (const key of ["requested_resource", "requested_property", "requested_depth", "authority"]) {
    const altered = structuredClone(value);
    altered[key] = "caller";
    assert.ok(registry.validate("my-work-oc-selection.schema.json", altered).length > 0, key);
  }
});

test("V1-B Hermes-visible read requests cannot express mission or OC selection keys", () => {
  const mission = read("hermes-mission-context-read-request-valid.json");
  const oc = read("hermes-oc-context-read-request-valid.json");
  assert.deepEqual(registry.validate("hermes-mission-context-read-request.schema.json", mission), []);
  assert.deepEqual(registry.validate("hermes-oc-context-read-request.schema.json", oc), []);

  for (const key of ["mission_id", "ticket_id", "work_id", "user_text"]) {
    const altered = { ...mission, [key]: "attacker" };
    assert.ok(registry.validate("hermes-mission-context-read-request.schema.json", altered).length > 0, key);
  }
  for (const [key, value] of Object.entries({
    selection_id: "attacker",
    resource: "ocr_attacker",
    property: "attacker.property",
    relation_depth: 1,
    authority: "execute"
  })) {
    const altered = { ...oc, [key]: value };
    assert.ok(registry.validate("hermes-oc-context-read-request.schema.json", altered).length > 0, key);
  }
});

test("V1-B not-applicable OC read is explicit and contains no receipt", () => {
  const value = read("oc-context-read-not-applicable.json");
  assert.deepEqual(registry.validate("my-work-oc-context-read.schema.json", value), []);
  assert.equal(value.availability, "not_applicable");
  assert.equal(value.selection.availability, "not_applicable");
  assert.equal(value.selection.selection_id, null);
  assert.equal(value.receipt, null);
});

test("V1-B schema references are closed and V1-A schema remains present", () => {
  const refs = registry.assertAllReferencesClosed();
  assert.ok(refs.some((item) => item.source === "my-work-oc-context-read.schema.json"));
  assert.ok(registry.schemaNames().includes("agent-context.schema.json"));
});
