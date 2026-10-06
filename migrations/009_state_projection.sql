-- Additive opt-in state policy history. Never rewrite admitted observations.
CREATE TABLE IF NOT EXISTS dubsar_context.state_policy_events (
  event_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('binding', 'mapping', 'rule')),
  policy_ref text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  resource_local_ref text,
  property text,
  status text NOT NULL CHECK (status IN ('admitted', 'revoked')),
  document jsonb NOT NULL,
  recorded_at timestamptz NOT NULL,
  principal_id text NOT NULL
);
CREATE INDEX IF NOT EXISTS state_policy_scope_time ON dubsar_context.state_policy_events
  (tenant_id, environment_id, kind, resource_local_ref, property, recorded_at, event_no);
CREATE INDEX IF NOT EXISTS state_policy_ref_time ON dubsar_context.state_policy_events
  (tenant_id, environment_id, kind, policy_ref, version, recorded_at, event_no);
DROP TRIGGER IF EXISTS state_policy_events_immutable ON dubsar_context.state_policy_events;
CREATE TRIGGER state_policy_events_immutable BEFORE UPDATE OR DELETE
  ON dubsar_context.state_policy_events FOR EACH ROW
  EXECUTE FUNCTION dubsar_context.immutable_association_event();
ALTER TABLE dubsar_context.state_policy_events OWNER TO dubsar_context_owner;
REVOKE ALL ON dubsar_context.state_policy_events FROM PUBLIC;
GRANT SELECT, INSERT ON dubsar_context.state_policy_events TO dubsar_context_runtime;
GRANT USAGE, SELECT ON SEQUENCE dubsar_context.state_policy_events_event_no_seq TO dubsar_context_runtime;
