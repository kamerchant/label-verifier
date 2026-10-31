#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/rename-job.sh OLD_ID NEW_ID
# Renames a job card everywhere it is stored (job, scans, Packing QC, lifecycle log,
# audit trail, phone scanner sessions) in the database at RENDER_DATABASE_URL (or prompted).
cd "$(dirname "$0")/.."

if [[ $# -ne 2 ]]; then
  echo "Usage: bash scripts/rename-job.sh OLD_ID NEW_ID" >&2
  exit 1
fi
old=${1//\'/\'\'}
new=${2//\'/\'\'}

if [[ -z "${RENDER_DATABASE_URL:-}" ]]; then
  read -r -s -p "Database URL: " RENDER_DATABASE_URL
  echo
fi

PSQL=${PSQL:-psql}
if ! command -v "$PSQL" >/dev/null 2>&1; then
  PSQL=/opt/homebrew/opt/libpq/bin/psql
fi
run() { "$PSQL" "$RENDER_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }

run -At <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM job_cards WHERE job_card_id = '$old' AND status != 'DELETED') THEN
    RAISE EXCEPTION 'Job % not found', '$old';
  END IF;
  IF EXISTS (SELECT 1 FROM job_cards WHERE job_card_id = '$new' AND status != 'DELETED') THEN
    RAISE EXCEPTION 'A job named % already exists', '$new';
  END IF;
END \$\$;
SQL

read -r -p "Rename job '$1' to '$2'? Type RENAME to continue: " answer
if [[ "$answer" != "RENAME" ]]; then
  echo "Cancelled. Nothing was changed."
  exit 0
fi

run <<SQL
BEGIN;
UPDATE job_cards SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE codes SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE scan_logs SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE packing_qc_logs SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE packing_qc_completions SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE job_lifecycle_logs SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE system_audit_logs SET job_card_id = '$new' WHERE job_card_id = '$old';
UPDATE phone_scanner_sessions SET job_card_id = '$new' WHERE job_card_id = '$old';
INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason)
VALUES ('$new', 'RENAMED', 'System', 'Job card renamed from $old to $new');
INSERT INTO system_audit_logs (category, job_card_id, action, performed_by, details)
VALUES ('JOB_LIFECYCLE', '$new', 'RENAMED', 'System', 'Job card renamed from $old to $new');
COMMIT;
SQL

run -c "SELECT job_card_id, status, total_codes, consumed_codes FROM job_cards WHERE job_card_id IN ('$old', '$new');"
echo "Done."
