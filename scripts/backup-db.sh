#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/backup-db.sh
# Writes a verified, compressed PostgreSQL dump to BACKUP_DIR (default ./backups) and deletes dumps older than
# BACKUP_RETENTION_DAYS (default 14). Point your backup software at BACKUP_DIR to copy the files off this machine.
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

retention_days=${BACKUP_RETENTION_DAYS:-14}
if ! [[ "$retention_days" =~ ^[0-9]+$ ]] || (( retention_days < 1 )); then
  echo "BACKUP_RETENTION_DAYS must be a positive whole number." >&2
  exit 2
fi

umask 077
mkdir -p "${BACKUP_DIR:-./backups}"
backup_dir=$(cd "${BACKUP_DIR:-./backups}" && pwd)

# A second run while one is in progress would compete for disk and I/O.
lock="$backup_dir/.backup.lock"
if ! mkdir "$lock" 2>/dev/null; then
  echo "Another backup appears to be running ($lock). Remove the folder if that is not the case." >&2
  exit 1
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
final="$backup_dir/label-verifier-$stamp.dump"
partial="$final.partial"
cleanup() {
  rm -f "$partial"
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT

echo "$(date -u +%FT%TZ) Starting backup to $final"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-acl' > "$partial"

# A dump that cannot be listed is unusable, so it is never kept as a finished backup.
docker compose exec -T db pg_restore --list < "$partial" > /dev/null
mv "$partial" "$final"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$backup_dir" && sha256sum "$(basename "$final")" > "$(basename "$final").sha256")
else
  (cd "$backup_dir" && shasum -a 256 "$(basename "$final")" > "$(basename "$final").sha256")
fi

# Pruning runs only after a successful backup, so a failing job never deletes the last good copy.
find "$backup_dir" -maxdepth 1 -type f \( -name 'label-verifier-*.dump' -o -name 'label-verifier-*.dump.sha256' \) \
  -mtime +"$retention_days" -delete

size=$(du -h "$final" | cut -f1)
echo "$(date -u +%FT%TZ) Backup complete: $final ($size)"
