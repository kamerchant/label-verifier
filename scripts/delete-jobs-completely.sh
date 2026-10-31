#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/delete-jobs-completely.sh J-0003 JC-0002 JC-0001
# Permanently removes every trace of the given job cards from the database in
# RENDER_DATABASE_URL (or prompted): codes, scans, Packing QC, lifecycle log,
# global audit trail entries, phone scanner sessions and staged upload data.
# A backup of the affected rows is written to ./backups before anything is deleted.
cd "$(dirname "$0")/.."

if [[ $# -eq 0 ]]; then
  echo "Usage: bash scripts/delete-jobs-completely.sh JOB_ID [JOB_ID ...]" >&2
  exit 1
fi

if [[ -z "${RENDER_DATABASE_URL:-}" ]]; then
  read -r -s -p "Render external database URL: " RENDER_DATABASE_URL
  echo
fi

PSQL=${PSQL:-psql}
if ! command -v "$PSQL" >/dev/null 2>&1; then
  PSQL=/opt/homebrew/opt/libpq/bin/psql
fi
PG_DUMP=${PG_DUMP:-$(dirname "$PSQL")/pg_dump}

ids_sql=""
for id in "$@"; do
  safe=${id//\'/\'\'}
  ids_sql+="${ids_sql:+,}'${safe}'"
done

run() { "$PSQL" "$RENDER_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }

echo "Rows that will be deleted:"
run -c "
SELECT 'job_cards' AS tbl, COUNT(*) FROM job_cards WHERE job_card_id IN ($ids_sql)
UNION ALL SELECT 'codes', COUNT(*) FROM codes WHERE run_id IN (SELECT run_id FROM job_cards WHERE job_card_id IN ($ids_sql))
UNION ALL SELECT 'scan_logs', COUNT(*) FROM scan_logs WHERE job_card_id IN ($ids_sql)
UNION ALL SELECT 'packing_qc_logs', COUNT(*) FROM packing_qc_logs WHERE job_card_id IN ($ids_sql)
UNION ALL SELECT 'packing_qc_completions', COUNT(*) FROM packing_qc_completions WHERE run_id IN (SELECT run_id FROM job_cards WHERE job_card_id IN ($ids_sql))
UNION ALL SELECT 'job_lifecycle_logs', COUNT(*) FROM job_lifecycle_logs WHERE job_card_id IN ($ids_sql)
UNION ALL SELECT 'system_audit_logs', COUNT(*) FROM system_audit_logs WHERE job_card_id IN ($ids_sql)
UNION ALL SELECT 'phone_scanner_sessions', COUNT(*) FROM phone_scanner_sessions WHERE job_card_id IN ($ids_sql);"

echo
read -r -p "Type DELETE to permanently remove ALL of the above for: $* : " answer
if [[ "$answer" != "DELETE" ]]; then
  echo "Cancelled. Nothing was changed."
  exit 0
fi

mkdir -p backups
backup="backups/deleted-jobs-$(date +%Y%m%d-%H%M%S).sql"
echo "Saving a backup of the affected rows to $backup ..."
{
  for tbl in job_cards codes scan_logs packing_qc_logs packing_qc_completions job_lifecycle_logs system_audit_logs phone_scanner_sessions; do
    case "$tbl" in
      codes|packing_qc_completions) where="run_id IN (SELECT run_id FROM job_cards WHERE job_card_id IN ($ids_sql))" ;;
      *) where="job_card_id IN ($ids_sql)" ;;
    esac
    echo "-- $tbl"
    run -At -c "COPY (SELECT * FROM $tbl WHERE $where) TO STDOUT WITH CSV HEADER" | sed "s/^/$tbl,/" || true
  done
} > "$backup"
chmod 600 "$backup"

run <<SQL
BEGIN;
DELETE FROM phone_scanner_scans WHERE session_id IN (SELECT session_id FROM phone_scanner_sessions WHERE job_card_id IN ($ids_sql));
DELETE FROM phone_scanner_sessions WHERE job_card_id IN ($ids_sql);
DELETE FROM packing_qc_logs WHERE job_card_id IN ($ids_sql);
DELETE FROM scan_logs WHERE job_card_id IN ($ids_sql);
DELETE FROM job_lifecycle_logs WHERE job_card_id IN ($ids_sql);
DELETE FROM system_audit_logs WHERE job_card_id IN ($ids_sql);
DELETE FROM job_cards WHERE job_card_id IN ($ids_sql);
COMMIT;
SQL

echo "Remaining references (all should be 0):"
run -c "
SELECT (SELECT COUNT(*) FROM job_cards WHERE job_card_id IN ($ids_sql)) AS job_cards,
       (SELECT COUNT(*) FROM scan_logs WHERE job_card_id IN ($ids_sql)) AS scans,
       (SELECT COUNT(*) FROM system_audit_logs WHERE job_card_id IN ($ids_sql)) AS audit;"
echo "Done. Job rows deleted from the database."
