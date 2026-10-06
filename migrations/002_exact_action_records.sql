-- Provision dubsar_exact_records_runtime separately, as a non-owner service role.
-- Applied transactionally/checksummed by the existing owner-only migration runner.
CREATE SCHEMA dubsar_exact_records;
REVOKE ALL ON SCHEMA dubsar_exact_records FROM PUBLIC;

CREATE TABLE dubsar_exact_records.authorities (
  context_key text NOT NULL,
  subject text NOT NULL,
  active_function text NOT NULL,
  eligible boolean NOT NULL,
  PRIMARY KEY (context_key, subject)
);
CREATE TABLE dubsar_exact_records.decisions (
  context_key text NOT NULL,
  decision_ref text NOT NULL,
  subject text NOT NULL,
  documents jsonb NOT NULL CHECK (jsonb_typeof(documents) = 'object'),
  PRIMARY KEY (context_key, decision_ref),
  FOREIGN KEY (context_key, subject) REFERENCES dubsar_exact_records.authorities(context_key, subject)
);
CREATE TABLE dubsar_exact_records.revocations (
  context_key text NOT NULL,
  decision_ref text NOT NULL,
  revoked boolean NOT NULL DEFAULT false,
  PRIMARY KEY (context_key, decision_ref),
  FOREIGN KEY (context_key, decision_ref) REFERENCES dubsar_exact_records.decisions(context_key, decision_ref)
);

CREATE FUNCTION dubsar_exact_records.preserve_documents() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  RAISE EXCEPTION 'exact decision documents are immutable' USING ERRCODE = '23514';
END
$body$;
CREATE TRIGGER decisions_immutable BEFORE UPDATE OR DELETE ON dubsar_exact_records.decisions
  FOR EACH ROW EXECUTE FUNCTION dubsar_exact_records.preserve_documents();

CREATE FUNCTION dubsar_exact_records.preserve_revocation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $body$
BEGIN
  IF OLD.revoked AND NOT NEW.revoked THEN
    RAISE EXCEPTION 'exact revocation is irreversible' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$body$;
CREATE TRIGGER revocations_monotone BEFORE UPDATE ON dubsar_exact_records.revocations
  FOR EACH ROW EXECUTE FUNCTION dubsar_exact_records.preserve_revocation();

REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_exact_records FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_exact_records FROM PUBLIC;
GRANT USAGE ON SCHEMA dubsar_exact_records TO dubsar_exact_records_runtime;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA dubsar_exact_records TO dubsar_exact_records_runtime;
GRANT UPDATE (active_function, eligible) ON dubsar_exact_records.authorities TO dubsar_exact_records_runtime;
GRANT UPDATE (revoked) ON dubsar_exact_records.revocations TO dubsar_exact_records_runtime;

-- Admission uses the authority transaction itself. Finalization/recovery still
-- use the separate Broker role/pool after this transaction has committed.
GRANT USAGE ON SCHEMA dubsar_broker TO dubsar_exact_records_runtime;
GRANT EXECUTE ON FUNCTION dubsar_broker.claim_action(
  text, text, text, text, text, text, text, integer, text, text, text,
  text, text, text, jsonb, text, text, timestamptz, text, text, timestamptz
) TO dubsar_exact_records_runtime;
