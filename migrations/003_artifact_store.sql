CREATE SCHEMA dubsar_artifacts;
REVOKE ALL ON SCHEMA dubsar_artifacts FROM PUBLIC;
CREATE TABLE dubsar_artifacts.objects (
  context_key text NOT NULL,
  idempotency_key text NOT NULL,
  artifact_id text PRIMARY KEY,
  request jsonb NOT NULL,
  reference jsonb NOT NULL,
  key_ref text NOT NULL,
  state text NOT NULL CHECK (state IN ('STAGING', 'PUBLISHED', 'QUARANTINED', 'INDETERMINATE')),
  UNIQUE (context_key, idempotency_key),
  CHECK (reference->>'artifact_id' = artifact_id),
  CHECK (state <> 'PUBLISHED' OR (reference->>'published_at' IS NOT NULL AND reference->>'evidence_ref' IS NOT NULL
    AND reference->>'deletion_state' = 'ACTIVE'))
);
CREATE UNIQUE INDEX artifact_location ON dubsar_artifacts.objects ((reference->>'location'));
CREATE FUNCTION dubsar_artifacts.preserve_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  IF NEW.context_key <> OLD.context_key OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.artifact_id <> OLD.artifact_id
    OR NEW.key_ref <> OLD.key_ref OR NEW.request <> OLD.request
    OR (NEW.reference - ARRAY['published_at', 'evidence_ref', 'deletion_state']) <> (OLD.reference - ARRAY['published_at', 'evidence_ref', 'deletion_state'])
    OR (OLD.state = 'QUARANTINED' AND NEW.state <> 'QUARANTINED')
    OR (OLD.reference->>'published_at' IS NOT NULL AND (NEW.state = 'STAGING' OR NEW.reference->>'published_at' IS DISTINCT FROM OLD.reference->>'published_at'
      OR NEW.reference->>'evidence_ref' IS DISTINCT FROM OLD.reference->>'evidence_ref')) THEN
    RAISE EXCEPTION 'immutable artifact identity' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$body$;
CREATE TRIGGER artifact_identity_immutable BEFORE UPDATE ON dubsar_artifacts.objects
  FOR EACH ROW EXECUTE FUNCTION dubsar_artifacts.preserve_identity();
REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_artifacts FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_artifacts FROM PUBLIC;
GRANT USAGE ON SCHEMA dubsar_artifacts TO dubsar_artifact_runtime;
GRANT SELECT, INSERT ON dubsar_artifacts.objects TO dubsar_artifact_runtime;
GRANT UPDATE (state, reference) ON dubsar_artifacts.objects TO dubsar_artifact_runtime;
