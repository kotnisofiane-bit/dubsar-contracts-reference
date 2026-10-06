CREATE TABLE dubsar_broker.broker_approval_usage (
  approval_digest text PRIMARY KEY,
  approval_id text NOT NULL UNIQUE,
  max_actions integer NOT NULL,
  consumed_actions integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT broker_approval_usage_digest_format CHECK (approval_digest ~ '^sha256:[a-f0-9]{64}$'),
  CONSTRAINT broker_approval_usage_limit_positive CHECK (max_actions > 0),
  CONSTRAINT broker_approval_usage_consumed_bounded CHECK (
    consumed_actions >= 0 AND consumed_actions <= max_actions
  )
);

CREATE TABLE dubsar_broker.broker_actions (
  action_id text PRIMARY KEY,
  proposal_id text NOT NULL UNIQUE,
  proposal_digest text NOT NULL,
  workflow_id text NOT NULL,
  workflow_digest text NOT NULL,
  approval_id text NOT NULL,
  approval_digest text NOT NULL REFERENCES dubsar_broker.broker_approval_usage(approval_digest),
  run_id text NOT NULL,
  step_id text NOT NULL,
  action_digest text NOT NULL,
  payload_digest text NOT NULL,
  workload_id text NOT NULL,
  workload_instance_id text NOT NULL,
  state text NOT NULL DEFAULT 'RECEIVED',
  pending_context jsonb NOT NULL,
  version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT broker_actions_action_id_format CHECK (action_id ~ '^action_[a-z0-9][a-z0-9_-]{7,127}$'),
  CONSTRAINT broker_actions_digest_format CHECK (
    proposal_digest ~ '^sha256:[a-f0-9]{64}$'
    AND workflow_digest ~ '^sha256:[a-f0-9]{64}$'
    AND approval_digest ~ '^sha256:[a-f0-9]{64}$'
    AND action_digest ~ '^sha256:[a-f0-9]{64}$'
    AND payload_digest ~ '^sha256:[a-f0-9]{64}$'
  ),
  CONSTRAINT broker_actions_state_valid CHECK (state IN (
    'AUTHORIZED', 'DENIED', 'EXPIRED', 'FAILED_FINAL', 'FAILED_RETRYABLE',
    'HUMAN_DECISION_REQUIRED', 'INDETERMINATE', 'IN_FLIGHT', 'RECEIVED',
    'RECONCILED_FAILED', 'RECONCILED_SUCCEEDED', 'SUCCEEDED'
  )),
  CONSTRAINT broker_actions_pending_context_object CHECK (jsonb_typeof(pending_context) = 'object'),
  CONSTRAINT broker_actions_version_nonnegative CHECK (version >= 0)
);

CREATE TABLE dubsar_broker.broker_consumed_jtis (
  jti text PRIMARY KEY,
  action_id text NOT NULL,
  kid text NOT NULL,
  consumed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  CONSTRAINT broker_consumed_jtis_jti_format CHECK (jti ~ '^jti_[A-Za-z0-9_-]{32,128}$'),
  CONSTRAINT broker_consumed_jtis_window CHECK (consumed_at < expires_at),
  CONSTRAINT broker_consumed_jtis_action_fk FOREIGN KEY (action_id)
    REFERENCES dubsar_broker.broker_actions(action_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE dubsar_broker.broker_receipts (
  receipt_id text PRIMARY KEY,
  action_id text NOT NULL UNIQUE REFERENCES dubsar_broker.broker_actions(action_id),
  capability_jti text NOT NULL,
  event_digest text NOT NULL UNIQUE,
  receipt_document jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  CONSTRAINT broker_receipts_id_format CHECK (receipt_id ~ '^receipt_[a-z0-9][a-z0-9_-]{7,127}$'),
  CONSTRAINT broker_receipts_digest_format CHECK (event_digest ~ '^sha256:[a-f0-9]{64}$'),
  CONSTRAINT broker_receipts_document_object CHECK (jsonb_typeof(receipt_document) = 'object'),
  CONSTRAINT broker_receipts_document_binding CHECK (
    receipt_document ->> 'receipt_id' = receipt_id
    AND receipt_document ->> 'capability_jti' = capability_jti
    AND receipt_document #>> '{evidence_chain,event_digest}' = event_digest
  )
);

CREATE TABLE dubsar_broker.broker_idempotency (
  idempotency_key text PRIMARY KEY,
  fingerprint text NOT NULL,
  action_id text NOT NULL UNIQUE REFERENCES dubsar_broker.broker_actions(action_id),
  status text NOT NULL,
  receipt_id text UNIQUE,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT broker_idempotency_fingerprint_format CHECK (fingerprint ~ '^sha256:[a-f0-9]{64}$'),
  CONSTRAINT broker_idempotency_status_valid CHECK (status IN ('in_flight', 'completed')),
  CONSTRAINT broker_idempotency_receipt_state CHECK (
    (status = 'in_flight' AND receipt_id IS NULL)
    OR (status = 'completed' AND receipt_id IS NOT NULL)
  ),
  CONSTRAINT broker_idempotency_receipt_fk FOREIGN KEY (receipt_id)
    REFERENCES dubsar_broker.broker_receipts(receipt_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE dubsar_broker.broker_action_transitions (
  action_id text NOT NULL REFERENCES dubsar_broker.broker_actions(action_id),
  sequence integer NOT NULL,
  transition_id text NOT NULL UNIQUE,
  from_state text NOT NULL,
  to_state text NOT NULL,
  actor_authority text NOT NULL,
  actor_identity_ref text NOT NULL,
  reason_code text NOT NULL,
  observed_at timestamptz NOT NULL,
  transition_document jsonb NOT NULL,
  PRIMARY KEY (action_id, sequence),
  CONSTRAINT broker_transitions_sequence_positive CHECK (sequence > 0),
  CONSTRAINT broker_transitions_document_object CHECK (jsonb_typeof(transition_document) = 'object'),
  CONSTRAINT broker_transitions_document_binding CHECK (
    transition_document ->> 'transition_id' = transition_id
    AND transition_document ->> 'action_id' = action_id
    AND transition_document ->> 'from_state' = from_state
    AND transition_document ->> 'to_state' = to_state
  ),
  CONSTRAINT broker_transitions_allowed CHECK (
    (from_state = 'AUTHORIZED' AND to_state = 'IN_FLIGHT')
    OR (from_state = 'INDETERMINATE' AND to_state IN ('HUMAN_DECISION_REQUIRED', 'RECONCILED_FAILED', 'RECONCILED_SUCCEEDED'))
    OR (from_state = 'IN_FLIGHT' AND to_state IN ('FAILED_FINAL', 'FAILED_RETRYABLE', 'INDETERMINATE', 'SUCCEEDED'))
    OR (from_state = 'RECEIVED' AND to_state IN ('AUTHORIZED', 'DENIED', 'EXPIRED'))
  ),
  CONSTRAINT broker_transitions_authority_allowed CHECK (
    (from_state = 'RECEIVED' AND actor_authority = 'CORE')
    OR (from_state IN ('AUTHORIZED', 'IN_FLIGHT') AND actor_authority = 'BROKER')
    OR (from_state = 'INDETERMINATE' AND to_state = 'HUMAN_DECISION_REQUIRED' AND actor_authority IN ('CORE', 'EVIDENCE_PLANE'))
    OR (from_state = 'INDETERMINATE' AND to_state IN ('RECONCILED_FAILED', 'RECONCILED_SUCCEEDED') AND actor_authority IN ('EVIDENCE_PLANE', 'HUMAN'))
  )
);

CREATE OR REPLACE FUNCTION dubsar_broker.transition_action(
  requested_action_id text,
  requested_to_state text,
  requested_actor_authority text,
  requested_identity_ref text,
  requested_reason_code text,
  requested_observed_at timestamptz
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, dubsar_broker
AS $transition$
DECLARE
  current_state text;
  next_sequence integer;
  generated_transition_id text;
  document jsonb;
BEGIN
  SELECT state INTO current_state
  FROM dubsar_broker.broker_actions
  WHERE action_id = requested_action_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'broker action not found' USING ERRCODE = 'P0002';
  END IF;

  IF NOT (
    (current_state = 'AUTHORIZED' AND requested_to_state = 'IN_FLIGHT')
    OR (current_state = 'INDETERMINATE' AND requested_to_state IN ('HUMAN_DECISION_REQUIRED', 'RECONCILED_FAILED', 'RECONCILED_SUCCEEDED'))
    OR (current_state = 'IN_FLIGHT' AND requested_to_state IN ('FAILED_FINAL', 'FAILED_RETRYABLE', 'INDETERMINATE', 'SUCCEEDED'))
    OR (current_state = 'RECEIVED' AND requested_to_state IN ('AUTHORIZED', 'DENIED', 'EXPIRED'))
  ) THEN
    RAISE EXCEPTION 'broker transition forbidden' USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(MAX(sequence), 0) + 1 INTO next_sequence
  FROM dubsar_broker.broker_action_transitions
  WHERE action_id = requested_action_id;

  generated_transition_id := 'transition_' || substr(requested_action_id, 8) || '_' || lpad(next_sequence::text, 3, '0');
  document := jsonb_build_object(
    'schema', 'dubsar.state-transition.v1',
    'contract_version', '1.0.0',
    'transition_id', generated_transition_id,
    'action_id', requested_action_id,
    'from_state', current_state,
    'to_state', requested_to_state,
    'actor', jsonb_build_object(
      'authority', requested_actor_authority,
      'identity_ref', requested_identity_ref
    ),
    'reason_code', requested_reason_code,
    'observed_at', to_char(requested_observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );

  INSERT INTO dubsar_broker.broker_action_transitions (
    action_id, sequence, transition_id, from_state, to_state,
    actor_authority, actor_identity_ref, reason_code, observed_at, transition_document
  ) VALUES (
    requested_action_id, next_sequence, generated_transition_id, current_state, requested_to_state,
    requested_actor_authority, requested_identity_ref, requested_reason_code, requested_observed_at, document
  );

  UPDATE dubsar_broker.broker_actions
  SET state = requested_to_state,
      version = version + 1,
      updated_at = requested_observed_at
  WHERE action_id = requested_action_id;

  RETURN document;
END
$transition$;

CREATE OR REPLACE FUNCTION dubsar_broker.claim_action(
  requested_action_id text,
  requested_proposal_id text,
  requested_proposal_digest text,
  requested_workflow_id text,
  requested_workflow_digest text,
  requested_approval_id text,
  requested_approval_digest text,
  requested_approval_max_actions integer,
  requested_run_id text,
  requested_step_id text,
  requested_action_digest text,
  requested_payload_digest text,
  requested_workload_id text,
  requested_workload_instance_id text,
  requested_pending_context jsonb,
  requested_jti text,
  requested_kid text,
  requested_capability_expires_at timestamptz,
  requested_idempotency_key text,
  requested_fingerprint text,
  requested_observed_at timestamptz
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, dubsar_broker
AS $claim$
DECLARE
  existing_idempotency record;
  approval_usage record;
BEGIN
  INSERT INTO dubsar_broker.broker_consumed_jtis
    (jti, action_id, kid, consumed_at, expires_at)
  VALUES (
    requested_jti,
    requested_action_id,
    requested_kid,
    requested_observed_at,
    requested_capability_expires_at
  );

  PERFORM pg_advisory_xact_lock(hashtextextended(requested_idempotency_key, 0));
  SELECT i.fingerprint, i.status, i.action_id, r.receipt_document
  INTO existing_idempotency
  FROM dubsar_broker.broker_idempotency i
  LEFT JOIN dubsar_broker.broker_receipts r ON r.receipt_id = i.receipt_id
  WHERE i.idempotency_key = requested_idempotency_key
  FOR UPDATE OF i;

  IF FOUND THEN
    IF existing_idempotency.fingerprint <> requested_fingerprint THEN
      RETURN jsonb_build_object('kind', 'idempotency_conflict');
    END IF;
    IF existing_idempotency.status <> 'completed' OR existing_idempotency.receipt_document IS NULL THEN
      RETURN jsonb_build_object('kind', 'in_flight', 'actionId', existing_idempotency.action_id);
    END IF;
    RETURN jsonb_build_object(
      'kind', 'completed',
      'actionId', existing_idempotency.action_id,
      'receipt', existing_idempotency.receipt_document
    );
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('approval:' || requested_approval_id, 0));
  SELECT approval_digest, max_actions, consumed_actions
  INTO approval_usage
  FROM dubsar_broker.broker_approval_usage
  WHERE approval_id = requested_approval_id
  FOR UPDATE;

  IF NOT FOUND THEN
    INSERT INTO dubsar_broker.broker_approval_usage (
      approval_digest, approval_id, max_actions, consumed_actions, created_at, updated_at
    ) VALUES (
      requested_approval_digest, requested_approval_id, requested_approval_max_actions,
      0, requested_observed_at, requested_observed_at
    );
    SELECT approval_digest, max_actions, consumed_actions
    INTO STRICT approval_usage
    FROM dubsar_broker.broker_approval_usage
    WHERE approval_id = requested_approval_id
    FOR UPDATE;
  END IF;

  IF approval_usage.approval_digest <> requested_approval_digest
    OR approval_usage.max_actions <> requested_approval_max_actions THEN
    RETURN jsonb_build_object('kind', 'approval_conflict');
  END IF;
  IF approval_usage.consumed_actions >= approval_usage.max_actions THEN
    RETURN jsonb_build_object('kind', 'approval_limit');
  END IF;

  UPDATE dubsar_broker.broker_approval_usage
  SET consumed_actions = consumed_actions + 1,
      updated_at = requested_observed_at
  WHERE approval_digest = requested_approval_digest;

  INSERT INTO dubsar_broker.broker_actions (
    action_id, proposal_id, proposal_digest, workflow_id, workflow_digest,
    approval_id, approval_digest, run_id, step_id, action_digest, payload_digest,
    workload_id, workload_instance_id, pending_context, created_at, updated_at
  ) VALUES (
    requested_action_id, requested_proposal_id, requested_proposal_digest,
    requested_workflow_id, requested_workflow_digest, requested_approval_id,
    requested_approval_digest, requested_run_id, requested_step_id,
    requested_action_digest, requested_payload_digest, requested_workload_id,
    requested_workload_instance_id, requested_pending_context,
    requested_observed_at, requested_observed_at
  );

  INSERT INTO dubsar_broker.broker_idempotency (
    idempotency_key, fingerprint, action_id, status, receipt_id, created_at, updated_at
  ) VALUES (
    requested_idempotency_key, requested_fingerprint, requested_action_id,
    'in_flight', NULL, requested_observed_at, requested_observed_at
  );

  PERFORM dubsar_broker.transition_action(
    requested_action_id, 'AUTHORIZED', 'CORE', 'core_governance_001',
    'CAPABILITY_VERIFIED', requested_observed_at
  );
  PERFORM dubsar_broker.transition_action(
    requested_action_id, 'IN_FLIGHT', 'BROKER',
    requested_pending_context #>> '{brokerIdentity,workload_id}',
    'PILOT_EXECUTION_STARTED', requested_observed_at
  );
  RETURN jsonb_build_object('kind', 'claimed', 'actionId', requested_action_id);
END
$claim$;

CREATE OR REPLACE FUNCTION dubsar_broker.finalize_action(
  requested_action_id text,
  requested_to_state text,
  requested_receipt_id text,
  requested_capability_jti text,
  requested_event_digest text,
  requested_receipt_document jsonb,
  requested_reason_code text,
  requested_broker_identity text,
  requested_observed_at timestamptz
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, dubsar_broker
AS $finalize$
DECLARE
  current_state text;
  existing_receipt jsonb;
BEGIN
  SELECT state INTO current_state
  FROM dubsar_broker.broker_actions
  WHERE action_id = requested_action_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'broker action not found' USING ERRCODE = 'P0002';
  END IF;
  IF current_state <> 'IN_FLIGHT' THEN
    SELECT receipt_document INTO existing_receipt
    FROM dubsar_broker.broker_receipts
    WHERE action_id = requested_action_id;
    IF FOUND THEN RETURN existing_receipt; END IF;
    RAISE EXCEPTION 'broker transition forbidden' USING ERRCODE = '23514';
  END IF;

  PERFORM dubsar_broker.transition_action(
    requested_action_id, requested_to_state, 'BROKER', requested_broker_identity,
    requested_reason_code, requested_observed_at
  );
  INSERT INTO dubsar_broker.broker_receipts (
    receipt_id, action_id, capability_jti, event_digest, receipt_document, created_at
  ) VALUES (
    requested_receipt_id, requested_action_id, requested_capability_jti,
    requested_event_digest, requested_receipt_document, requested_observed_at
  );
  UPDATE dubsar_broker.broker_idempotency
  SET status = 'completed', receipt_id = requested_receipt_id, updated_at = requested_observed_at
  WHERE action_id = requested_action_id AND status = 'in_flight';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'broker idempotency state invalid' USING ERRCODE = '23514';
  END IF;
  RETURN requested_receipt_document;
END
$finalize$;

CREATE INDEX broker_actions_state_updated_idx
  ON dubsar_broker.broker_actions(state, updated_at);

CREATE INDEX broker_consumed_jtis_expiry_idx
  ON dubsar_broker.broker_consumed_jtis(expires_at);

REVOKE ALL ON SCHEMA dubsar_broker FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_broker FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA dubsar_broker FROM dubsar_broker_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_broker FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dubsar_broker FROM dubsar_broker_runtime;
GRANT USAGE ON SCHEMA dubsar_broker TO dubsar_broker_runtime;
GRANT SELECT (action_id, state, pending_context, created_at, updated_at, version)
  ON dubsar_broker.broker_actions TO dubsar_broker_runtime;
GRANT SELECT (action_id, sequence, transition_document)
  ON dubsar_broker.broker_action_transitions TO dubsar_broker_runtime;
GRANT SELECT (action_id, receipt_document)
  ON dubsar_broker.broker_receipts TO dubsar_broker_runtime;
GRANT EXECUTE ON FUNCTION dubsar_broker.claim_action(
  text, text, text, text, text, text, text, integer, text, text, text,
  text, text, text, jsonb, text, text, timestamptz, text, text, timestamptz
) TO dubsar_broker_runtime;
GRANT EXECUTE ON FUNCTION dubsar_broker.finalize_action(
  text, text, text, text, text, jsonb, text, text, timestamptz
) TO dubsar_broker_runtime;
