BEGIN;

CREATE TEMPORARY TABLE dubsar_contract_ci_probe (
  probe_id integer PRIMARY KEY,
  state text NOT NULL CHECK (state IN ('RECEIVED', 'SUCCEEDED'))
);

INSERT INTO dubsar_contract_ci_probe (probe_id, state)
VALUES (1, 'RECEIVED');

UPDATE dubsar_contract_ci_probe
SET state = 'SUCCEEDED'
WHERE probe_id = 1;

DO $proof$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM dubsar_contract_ci_probe
    WHERE probe_id = 1 AND state = 'SUCCEEDED'
  ) THEN
    RAISE EXCEPTION 'transactional PostgreSQL probe failed';
  END IF;
END
$proof$;

ROLLBACK;

DO $cleanup$
BEGIN
  IF to_regclass('pg_temp.dubsar_contract_ci_probe') IS NOT NULL THEN
    RAISE EXCEPTION 'temporary PostgreSQL probe survived rollback';
  END IF;
END
$cleanup$;
