-- Parent/session binding and monotone revocation. No membership writes.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='dubsar_human_lifecycle_runtime')
 THEN CREATE ROLE dubsar_human_lifecycle_runtime NOLOGIN; END IF;
END $$;
CREATE TABLE dubsar_human.portal_parents (
 context_key text NOT NULL, issuer text NOT NULL, parent_id text NOT NULL,
 external_subject text NOT NULL, revoked boolean NOT NULL DEFAULT false,
 lock_marker boolean NOT NULL DEFAULT false CHECK(lock_marker=false),
 PRIMARY KEY(context_key,issuer,parent_id)
);
CREATE TABLE dubsar_human.portal_children (
 context_key text NOT NULL, session_id text NOT NULL, issuer text NOT NULL,
 parent_id text NOT NULL, external_subject text NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(context_key,session_id),
 FOREIGN KEY(context_key,issuer,parent_id) REFERENCES dubsar_human.portal_parents(context_key,issuer,parent_id)
);
CREATE TABLE dubsar_human.lifecycle_requests (
 context_key text NOT NULL, issuer text NOT NULL, request_id text NOT NULL,
 digest text NOT NULL, result jsonb NOT NULL,
 PRIMARY KEY(context_key,issuer,request_id)
);
CREATE TRIGGER portal_children_immutable BEFORE UPDATE OR DELETE ON dubsar_human.portal_children
 FOR EACH ROW EXECUTE FUNCTION dubsar_human.immutable();
CREATE TRIGGER lifecycle_requests_immutable BEFORE UPDATE OR DELETE ON dubsar_human.lifecycle_requests
 FOR EACH ROW EXECUTE FUNCTION dubsar_human.immutable();
CREATE FUNCTION dubsar_human.parent_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'revoked') <> (to_jsonb(OLD)-'revoked') OR (OLD.revoked AND NOT NEW.revoked)
 THEN RAISE EXCEPTION 'immutable portal parent' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER portal_parents_monotone BEFORE UPDATE OR DELETE ON dubsar_human.portal_parents
 FOR EACH ROW EXECUTE FUNCTION dubsar_human.parent_update();
REVOKE ALL ON dubsar_human.portal_parents,dubsar_human.portal_children,dubsar_human.lifecycle_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION dubsar_human.parent_update() FROM PUBLIC;
GRANT USAGE ON SCHEMA dubsar_human TO dubsar_human_lifecycle_runtime;
GRANT SELECT,INSERT ON dubsar_human.portal_parents,dubsar_human.portal_children,dubsar_human.lifecycle_requests TO dubsar_human_lifecycle_runtime;
GRANT UPDATE(revoked,lock_marker) ON dubsar_human.portal_parents TO dubsar_human_lifecycle_runtime;
GRANT SELECT ON dubsar_human.portal_parents,dubsar_human.portal_children TO dubsar_exact_records_runtime;
GRANT UPDATE(lock_marker) ON dubsar_human.portal_parents TO dubsar_exact_records_runtime;
