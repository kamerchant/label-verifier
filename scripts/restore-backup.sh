#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/restore-backup.sh <backup.dump> [--yes]
# Replaces the Docker Compose PostgreSQL database with a dump made by scripts/backup-db.sh.
cd "$(dirname "$0")/.."

if [[ $# -lt 1 || ! -f "$1" ]]; then
  echo "Usage: bash scripts/restore-backup.sh <backup.dump> [--yes]" >&2
  exit 2
fi
dump=$1

if [[ "${2:-}" != "--yes" ]]; then
  read -r -p "This DELETES all current data and restores $dump. Type 'restore' to continue: " answer
  [[ "$answer" == "restore" ]] || { echo "Cancelled."; exit 1; }
fi

# Check the file is readable and matches its checksum, when one was saved with it.
if [[ -f "$dump.sha256" ]]; then
  expected=$(cut -d' ' -f1 "$dump.sha256")
  if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$dump" | cut -d' ' -f1); else actual=$(shasum -a 256 "$dump" | cut -d' ' -f1); fi
  [[ "$expected" == "$actual" ]] || { echo "Checksum mismatch: the backup file is damaged." >&2; exit 1; }
fi
docker compose exec -T db pg_restore --list < "$dump" > /dev/null

trap 'docker compose start app >/dev/null' EXIT
docker compose stop app

docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qc "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"' > /dev/null
echo "Restoring (this can take several minutes)..."
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --exit-on-error' < "$dump"

echo "Row counts:"
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F " : " -c "select '"'"'users'"'"', count(*) from users union all select '"'"'job_cards'"'"', count(*) from job_cards union all select '"'"'codes'"'"', count(*) from codes"'
