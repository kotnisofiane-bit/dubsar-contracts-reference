CREATE SCHEMA dubsar_human;
REVOKE ALL ON SCHEMA dubsar_human FROM PUBLIC;
CREATE TABLE dubsar_human.memberships (
 context_key text NOT NULL, issuer text NOT NULL, external_subject text NOT NULL,
 principal text NOT NULL, environment text NOT NULL, active_function text NOT NULL CHECK(active_function='approver'),
 version bigint NOT NULL CHECK(version>0), enabled boolean NOT NULL,
 lock_marker boolean NOT NULL DEFAULT false CHECK(lock_marker=false),
 PRIMARY KEY(context_key,issuer,external_subject), UNIQUE(context_key,principal)
);
CREATE TABLE dubsar_human.sessions (
 context_key text NOT NULL, session_id text NOT NULL, issuer text NOT NULL,
 external_subject text NOT NULL, expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 lock_marker boolean NOT NULL DEFAULT false CHECK(lock_marker=false),
 PRIMARY KEY(context_key,session_id),
 FOREIGN KEY(context_key,issuer,external_subject) REFERENCES dubsar_human.memberships(context_key,issuer,external_subject)
);
CREATE TABLE dubsar_human.presentations (
 context_key text NOT NULL, presentation_id text NOT NULL, session_id text NOT NULL,
 membership_version bigint NOT NULL, principal text NOT NULL, documents jsonb NOT NULL,
 expires_at timestamptz NOT NULL, result jsonb, idempotency_key text,
 PRIMARY KEY(context_key,presentation_id),
 FOREIGN KEY(context_key,session_id) REFERENCES dubsar_human.sessions(context_key,session_id),
 UNIQUE(context_key,session_id,idempotency_key)
);
CREATE TABLE dubsar_human.decision_sessions (
 context_key text NOT NULL, decision_ref text NOT NULL, session_id text NOT NULL,
 membership_version bigint NOT NULL, principal text NOT NULL,
 PRIMARY KEY(context_key,decision_ref),
 FOREIGN KEY(context_key,decision_ref) REFERENCES dubsar_exact_records.decisions(context_key,decision_ref),
 FOREIGN KEY(context_key,session_id) REFERENCES dubsar_human.sessions(context_key,session_id)
);
CREATE FUNCTION dubsar_human.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'immutable human binding' USING ERRCODE='23514'; END $$;
CREATE TRIGGER human_links_immutable BEFORE UPDATE OR DELETE ON dubsar_human.decision_sessions
 FOR EACH ROW EXECUTE FUNCTION dubsar_human.immutable();
CREATE FUNCTION dubsar_human.session_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-'revoked') <> (to_jsonb(OLD)-'revoked') OR (OLD.revoked AND NOT NEW.revoked)
 THEN RAISE EXCEPTION 'immutable human session' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER human_sessions_monotone BEFORE UPDATE ON dubsar_human.sessions
 FOR EACH ROW EXECUTE FUNCTION dubsar_human.session_update();
CREATE FUNCTION dubsar_human.presentation_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['result','idempotency_key']) <> (to_jsonb(OLD)-ARRAY['result','idempotency_key'])
 OR (OLD.result IS NOT NULL AND to_jsonb(NEW) <> to_jsonb(OLD))
 THEN RAISE EXCEPTION 'immutable human presentation' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER human_presentations_immutable BEFORE UPDATE ON dubsar_human.presentations
 FOR EACH ROW EXECUTE FUNCTION dubsar_human.presentation_update();
REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_human FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_human FROM PUBLIC;
GRANT USAGE ON SCHEMA dubsar_human TO dubsar_exact_records_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA dubsar_human TO dubsar_exact_records_runtime;
-- PostgreSQL row locking requires UPDATE on at least one column. This immutable
-- false marker permits locks without granting membership or revocation writes.
GRANT UPDATE(lock_marker) ON dubsar_human.memberships,dubsar_human.sessions TO dubsar_exact_records_runtime;
GRANT INSERT ON dubsar_human.sessions,dubsar_human.presentations,dubsar_human.decision_sessions TO dubsar_exact_records_runtime;
GRANT UPDATE(result,idempotency_key) ON dubsar_human.presentations TO dubsar_exact_records_runtime;
-- Only the administrative owner/port changes mappings and revokes sessions.
