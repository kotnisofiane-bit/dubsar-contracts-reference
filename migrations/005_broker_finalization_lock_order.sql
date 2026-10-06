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
  -- Match claim_action: idempotency before action, including deferred JTI FK checks.
  PERFORM 1 FROM dubsar_broker.broker_idempotency
  WHERE action_id = requested_action_id
  FOR UPDATE;

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
