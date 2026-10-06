-- 008 Operational Context kernel. Additive after 001–007. Own schema and roles.
-- Idempotent: safe after Broker 001→008, and safe if the OC migrator ran first.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dubsar_context_owner') THEN
    CREATE ROLE dubsar_context_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dubsar_context_runtime') THEN
    CREATE ROLE dubsar_context_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS dubsar_context;
REVOKE ALL ON SCHEMA dubsar_context FROM PUBLIC;
GRANT USAGE ON SCHEMA dubsar_context TO dubsar_context_runtime;
REVOKE CREATE ON SCHEMA dubsar_context FROM PUBLIC;
REVOKE CREATE ON SCHEMA dubsar_context FROM dubsar_context_runtime;

CREATE TABLE IF NOT EXISTS dubsar_context.resources (
  local_ref text PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  source_instance_id text NOT NULL,
  namespace text NOT NULL,
  type text NOT NULL,
  source_id text NOT NULL,
  incarnation text,
  incarnation_absent boolean NOT NULL,
  label text,
  identity_fingerprint text NOT NULL UNIQUE,
  registered_at timestamptz NOT NULL,
  CONSTRAINT resources_incarnation_presence CHECK (
    (incarnation_absent AND incarnation IS NULL)
    OR (NOT incarnation_absent AND incarnation IS NOT NULL)
  ),
  CONSTRAINT resources_tokens CHECK (
    length(tenant_id) BETWEEN 1 AND 256
    AND length(environment_id) BETWEEN 1 AND 256
    AND length(source_instance_id) BETWEEN 1 AND 256
    AND length(namespace) BETWEEN 1 AND 256
    AND length(type) BETWEEN 1 AND 256
    AND length(source_id) BETWEEN 1 AND 256
    AND tenant_id !~ '[[:cntrl:]]'
    AND environment_id !~ '[[:cntrl:]]'
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS resources_identity
  ON dubsar_context.resources (
    tenant_id, environment_id, source_instance_id, namespace, type, source_id,
    COALESCE(incarnation, ''), incarnation_absent
  );

CREATE TABLE IF NOT EXISTS dubsar_context.observations (
  local_ref text PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  resource_local_ref text NOT NULL REFERENCES dubsar_context.resources (local_ref),
  property text NOT NULL,
  delivery_id text NOT NULL,
  measurement_id text,
  measurement_absent boolean NOT NULL,
  result_kind text NOT NULL CHECK (result_kind IN (
    'measured', 'proven_absence', 'collection_impossible', 'collection_partial'
  )),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^sha256:[a-f0-9]{64}$'),
  source_observed_at timestamptz,
  source_date_unknown boolean NOT NULL,
  received_at timestamptz NOT NULL,
  mapping_ref text,
  mapping_version integer,
  rule_ref text,
  rule_version integer,
  producer_id text NOT NULL,
  source_instance_id text NOT NULL,
  correction_of text REFERENCES dubsar_context.observations (local_ref),
  retraction_of text REFERENCES dubsar_context.observations (local_ref),
  UNIQUE (tenant_id, environment_id, delivery_id),
  CONSTRAINT observations_measurement_presence CHECK (
    (measurement_absent AND measurement_id IS NULL)
    OR (NOT measurement_absent AND measurement_id IS NOT NULL)
  ),
  CONSTRAINT observations_source_date CHECK (
    (source_date_unknown AND source_observed_at IS NULL)
    OR (NOT source_date_unknown AND source_observed_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS observations_measurement
  ON dubsar_context.observations (tenant_id, environment_id, measurement_id)
  WHERE measurement_absent = false;

CREATE TABLE IF NOT EXISTS dubsar_context.aggregates (
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  aggregate_key text NOT NULL,
  version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
  status text NOT NULL CHECK (status IN ('current', 'invalidated', 'pending_recalculation')),
  current_qualification_ref text,
  lock_marker boolean NOT NULL DEFAULT false CHECK (lock_marker = false),
  PRIMARY KEY (tenant_id, environment_id, aggregate_key)
);

CREATE TABLE IF NOT EXISTS dubsar_context.qualifications (
  local_ref text PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  aggregate_key text NOT NULL,
  aggregate_version bigint NOT NULL,
  instant timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('current', 'historical', 'invalidated', 'pending_recalculation')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^sha256:[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS dubsar_context.associations (
  local_ref text PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  association_type text NOT NULL CHECK (association_type IN ('related_to', 'same_resource')),
  left_ref text NOT NULL REFERENCES dubsar_context.resources (local_ref),
  right_ref text NOT NULL REFERENCES dubsar_context.resources (local_ref),
  pair_fingerprint text NOT NULL CHECK (pair_fingerprint ~ '^sha256:[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('candidate', 'admitted', 'revoked')),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  UNIQUE (tenant_id, environment_id, association_type, pair_fingerprint),
  CONSTRAINT associations_distinct_ends CHECK (left_ref <> right_ref)
);

CREATE TABLE IF NOT EXISTS dubsar_context.association_events (
  event_ref text PRIMARY KEY,
  association_ref text NOT NULL REFERENCES dubsar_context.associations (local_ref),
  version bigint NOT NULL,
  action text NOT NULL CHECK (action IN ('propose', 'admit', 'revoke', 'conflict')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  recorded_at timestamptz NOT NULL,
  UNIQUE (association_ref, version)
);

CREATE TABLE IF NOT EXISTS dubsar_context.mappings (
  mapping_ref text NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('admitted', 'revoked')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  PRIMARY KEY (tenant_id, environment_id, mapping_ref, version)
);

CREATE TABLE IF NOT EXISTS dubsar_context.rules (
  rule_ref text NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('admitted', 'revoked')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  PRIMARY KEY (tenant_id, environment_id, rule_ref, version)
);

CREATE TABLE IF NOT EXISTS dubsar_context.derivative_cache (
  cache_key text PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  document jsonb NOT NULL,
  input_fingerprint text NOT NULL,
  status text NOT NULL CHECK (status IN ('current', 'stale', 'invalidated')),
  updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS dubsar_context.view_receipts (
  view_ref text PRIMARY KEY,
  tenant_id text NOT NULL,
  environment_id text NOT NULL,
  reader_id text NOT NULL,
  document jsonb NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE OR REPLACE FUNCTION dubsar_context.immutable_observation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  RAISE EXCEPTION 'admitted observations are immutable' USING ERRCODE = '23514';
END
$fn$;

DROP TRIGGER IF EXISTS observations_immutable ON dubsar_context.observations;
CREATE TRIGGER observations_immutable
  BEFORE UPDATE OR DELETE ON dubsar_context.observations
  FOR EACH ROW EXECUTE FUNCTION dubsar_context.immutable_observation();

CREATE OR REPLACE FUNCTION dubsar_context.immutable_association_event() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  RAISE EXCEPTION 'association events are immutable' USING ERRCODE = '23514';
END
$fn$;

DROP TRIGGER IF EXISTS association_events_immutable ON dubsar_context.association_events;
CREATE TRIGGER association_events_immutable
  BEFORE UPDATE OR DELETE ON dubsar_context.association_events
  FOR EACH ROW EXECUTE FUNCTION dubsar_context.immutable_association_event();

ALTER SCHEMA dubsar_context OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.resources OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.observations OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.aggregates OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.qualifications OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.associations OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.association_events OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.mappings OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.rules OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.derivative_cache OWNER TO dubsar_context_owner;
ALTER TABLE dubsar_context.view_receipts OWNER TO dubsar_context_owner;
ALTER FUNCTION dubsar_context.immutable_observation() OWNER TO dubsar_context_owner;
ALTER FUNCTION dubsar_context.immutable_association_event() OWNER TO dubsar_context_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_context FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_context FROM PUBLIC;
GRANT SELECT, INSERT ON dubsar_context.resources TO dubsar_context_runtime;
GRANT SELECT, INSERT ON dubsar_context.observations TO dubsar_context_runtime;
GRANT SELECT, INSERT, UPDATE ON dubsar_context.aggregates TO dubsar_context_runtime;
GRANT SELECT, INSERT ON dubsar_context.qualifications TO dubsar_context_runtime;
GRANT UPDATE (status) ON dubsar_context.qualifications TO dubsar_context_runtime;
GRANT SELECT, INSERT, UPDATE ON dubsar_context.associations TO dubsar_context_runtime;
GRANT SELECT, INSERT ON dubsar_context.association_events TO dubsar_context_runtime;
GRANT SELECT, INSERT, UPDATE ON dubsar_context.mappings TO dubsar_context_runtime;
GRANT SELECT, INSERT, UPDATE ON dubsar_context.rules TO dubsar_context_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON dubsar_context.derivative_cache TO dubsar_context_runtime;
GRANT SELECT, INSERT ON dubsar_context.view_receipts TO dubsar_context_runtime;
