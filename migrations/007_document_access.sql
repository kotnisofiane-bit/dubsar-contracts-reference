-- Additive documentary policy. Existing effect authorities are untouched.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='dubsar_document_reader') THEN
  CREATE ROLE dubsar_document_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='dubsar_document_admin') THEN
  CREATE ROLE dubsar_document_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
 END IF;
END $$;
CREATE SCHEMA dubsar_document_access;
REVOKE ALL ON SCHEMA dubsar_document_access FROM PUBLIC;
CREATE TABLE dubsar_document_access.contexts (
 tenant_ref text NOT NULL, context_ref text NOT NULL, policy_epoch bigint NOT NULL DEFAULT 1 CHECK(policy_epoch>0),
 lock_marker boolean NOT NULL DEFAULT false CHECK(lock_marker=false), PRIMARY KEY(tenant_ref,context_ref)
);
CREATE TABLE dubsar_document_access.memberships (
 tenant_ref text NOT NULL, context_ref text NOT NULL, issuer text NOT NULL, external_subject text NOT NULL,
 principal text NOT NULL, active_function text NOT NULL, enabled boolean NOT NULL,
 PRIMARY KEY(tenant_ref,context_ref,issuer,external_subject),
 UNIQUE(tenant_ref,context_ref,principal,active_function),
 FOREIGN KEY(tenant_ref,context_ref) REFERENCES dubsar_document_access.contexts
);
CREATE TABLE dubsar_document_access.sessions (
 tenant_ref text NOT NULL, context_ref text NOT NULL, session_ref text NOT NULL, issuer text NOT NULL,
 external_subject text NOT NULL, active_function text NOT NULL, expires_at timestamptz NOT NULL, revoked boolean NOT NULL,
 PRIMARY KEY(tenant_ref,context_ref,session_ref),
 FOREIGN KEY(tenant_ref,context_ref,issuer,external_subject) REFERENCES dubsar_document_access.memberships
);
CREATE TABLE dubsar_document_access.corpora (
 tenant_ref text NOT NULL, context_ref text NOT NULL, corpus_ref text NOT NULL, enabled boolean NOT NULL,
 PRIMARY KEY(tenant_ref,context_ref,corpus_ref),
 FOREIGN KEY(tenant_ref,context_ref) REFERENCES dubsar_document_access.contexts
);
CREATE TABLE dubsar_document_access.resources (
 tenant_ref text NOT NULL, context_ref text NOT NULL, corpus_ref text NOT NULL, document_ref text NOT NULL,
 resource_version text NOT NULL, enabled boolean NOT NULL,
 PRIMARY KEY(tenant_ref,context_ref,corpus_ref,document_ref),
 FOREIGN KEY(tenant_ref,context_ref,corpus_ref) REFERENCES dubsar_document_access.corpora
);
CREATE TABLE dubsar_document_access.grants (
 tenant_ref text NOT NULL, context_ref text NOT NULL, principal text NOT NULL, active_function text NOT NULL,
 corpus_ref text NOT NULL, document_ref text NOT NULL, enabled boolean NOT NULL,
 PRIMARY KEY(tenant_ref,context_ref,principal,active_function,corpus_ref,document_ref),
 -- Historical grants must not prevent a membership from changing function.
 -- The authority intersects the current principal/function on every request.
 FOREIGN KEY(tenant_ref,context_ref) REFERENCES dubsar_document_access.contexts,
 FOREIGN KEY(tenant_ref,context_ref,corpus_ref,document_ref) REFERENCES dubsar_document_access.resources
);
CREATE TABLE dubsar_document_access.decisions (
 tenant_ref text NOT NULL, context_ref text NOT NULL, decision_id text NOT NULL, document jsonb NOT NULL,
 PRIMARY KEY(tenant_ref,context_ref,decision_id),
 FOREIGN KEY(tenant_ref,context_ref) REFERENCES dubsar_document_access.contexts
);
CREATE FUNCTION dubsar_document_access.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'immutable document decision' USING ERRCODE='23514'; END $$;
CREATE TRIGGER immutable_document_decision BEFORE UPDATE OR DELETE ON dubsar_document_access.decisions
 FOR EACH ROW EXECUTE FUNCTION dubsar_document_access.immutable();

-- One mutation per call: epoch always locked first. Readers hold its SHARE lock
-- while checking rows, so no grant/session can change during the final check.
-- Only this closed administrator port can mutate policy; no direct admin DML.
CREATE FUNCTION dubsar_document_access.mutate(t text,c text,kind text,p jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result bigint; expected text[]; actual text[]; k text;
BEGIN
 IF t IS NULL OR c IS NULL OR length(t) NOT BETWEEN 1 AND 256 OR length(c) NOT BETWEEN 1 AND 256
 OR t ~ '[[:cntrl:]*]' OR c ~ '[[:cntrl:]*]' OR jsonb_typeof(p)<>'object' OR p IS NULL
 THEN RAISE EXCEPTION 'invalid documentary policy'; END IF;
 expected := CASE kind
  WHEN 'context' THEN ARRAY[]::text[]
  WHEN 'membership' THEN ARRAY['issuer','external_subject','principal','active_function','enabled']
  WHEN 'session' THEN ARRAY['session_ref','issuer','external_subject','active_function','expires_at','revoked']
  WHEN 'corpus' THEN ARRAY['corpus_ref','enabled']
  WHEN 'resource' THEN ARRAY['corpus_ref','document_ref','resource_version','enabled']
  WHEN 'grant' THEN ARRAY['principal','active_function','corpus_ref','document_ref','enabled'] END;
 IF expected IS NULL THEN RAISE EXCEPTION 'invalid documentary operation'; END IF;
 SELECT coalesce(array_agg(key ORDER BY key),ARRAY[]::text[]) INTO actual FROM jsonb_object_keys(p) key;
 SELECT coalesce(array_agg(v ORDER BY v),ARRAY[]::text[]) INTO expected FROM unnest(expected) v;
 IF actual<>expected THEN RAISE EXCEPTION 'invalid documentary fields'; END IF;
 FOREACH k IN ARRAY actual LOOP
  IF k IN ('enabled','revoked') THEN
   IF jsonb_typeof(p->k)<>'boolean' THEN RAISE EXCEPTION 'invalid boolean'; END IF;
  ELSIF jsonb_typeof(p->k)<>'string' OR length(p->>k) NOT BETWEEN 1 AND 256 OR (p->>k) ~ '[[:cntrl:]*]'
  THEN RAISE EXCEPTION 'invalid documentary identifier'; END IF;
 END LOOP;
 IF kind='context' THEN
  INSERT INTO dubsar_document_access.contexts(tenant_ref,context_ref) VALUES(t,c) ON CONFLICT DO NOTHING;
 END IF;
 SELECT policy_epoch INTO result FROM dubsar_document_access.contexts WHERE tenant_ref=t AND context_ref=c FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown documentary context'; END IF;
 IF kind='membership' THEN
  INSERT INTO dubsar_document_access.memberships VALUES(t,c,p->>'issuer',p->>'external_subject',p->>'principal',p->>'active_function',(p->>'enabled')::boolean)
  ON CONFLICT(tenant_ref,context_ref,issuer,external_subject) DO UPDATE SET enabled=excluded.enabled,principal=excluded.principal,active_function=excluded.active_function;
 ELSIF kind='session' THEN
  -- Never rebind or resurrect a session ID.
  IF EXISTS(SELECT 1 FROM dubsar_document_access.sessions s WHERE s.tenant_ref=t AND s.context_ref=c AND s.session_ref=p->>'session_ref'
    AND (s.issuer<>p->>'issuer' OR s.external_subject<>p->>'external_subject' OR s.active_function<>p->>'active_function'
      OR s.expires_at<>(p->>'expires_at')::timestamptz OR (s.revoked AND NOT (p->>'revoked')::boolean)))
  THEN RAISE EXCEPTION 'immutable documentary session'; END IF;
  INSERT INTO dubsar_document_access.sessions VALUES(t,c,p->>'session_ref',p->>'issuer',p->>'external_subject',p->>'active_function',(p->>'expires_at')::timestamptz,(p->>'revoked')::boolean)
  ON CONFLICT(tenant_ref,context_ref,session_ref) DO UPDATE SET revoked=excluded.revoked;
 ELSIF kind='corpus' THEN
  INSERT INTO dubsar_document_access.corpora VALUES(t,c,p->>'corpus_ref',(p->>'enabled')::boolean)
  ON CONFLICT(tenant_ref,context_ref,corpus_ref) DO UPDATE SET enabled=excluded.enabled;
 ELSIF kind='resource' THEN
  INSERT INTO dubsar_document_access.resources VALUES(t,c,p->>'corpus_ref',p->>'document_ref',p->>'resource_version',(p->>'enabled')::boolean)
  ON CONFLICT(tenant_ref,context_ref,corpus_ref,document_ref) DO UPDATE SET resource_version=excluded.resource_version,enabled=excluded.enabled;
 ELSIF kind='grant' THEN
  INSERT INTO dubsar_document_access.grants VALUES(t,c,p->>'principal',p->>'active_function',p->>'corpus_ref',p->>'document_ref',(p->>'enabled')::boolean)
  ON CONFLICT(tenant_ref,context_ref,principal,active_function,corpus_ref,document_ref) DO UPDATE SET enabled=excluded.enabled;
 END IF;
 UPDATE dubsar_document_access.contexts SET policy_epoch=policy_epoch+1 WHERE tenant_ref=t AND context_ref=c RETURNING policy_epoch INTO result;
 RETURN result;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_document_access FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_document_access FROM PUBLIC;
GRANT USAGE ON SCHEMA dubsar_document_access TO dubsar_document_reader,dubsar_document_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA dubsar_document_access TO dubsar_document_reader;
GRANT UPDATE(lock_marker) ON dubsar_document_access.contexts TO dubsar_document_reader;
GRANT INSERT ON dubsar_document_access.decisions TO dubsar_document_reader;
GRANT EXECUTE ON FUNCTION dubsar_document_access.mutate(text,text,text,jsonb) TO dubsar_document_admin;
