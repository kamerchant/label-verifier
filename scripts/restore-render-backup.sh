#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/restore-render-backup.sh <path-to-render-backup.dir.tar.gz>
# Replaces the Docker Compose PostgreSQL database with a Render logical backup (pg_dump directory format).
cd "$(dirname "$0")/.."

if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo "Usage: bash scripts/restore-render-backup.sh <backup.dir.tar.gz>" >&2
  exit 2
fi
archive=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")

# The client tools must be at least as new as the Render server (18). Restoring into an older server is supported.
pg_version=${PG_VERSION:-18}

if [[ ! -f .env ]]; then
  echo ".env not found. Create it first (see README)." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

network="$(docker compose ps -q db | head -n1 | xargs docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
if [[ -z "$network" ]]; then
  echo "The db service is not running. Start it with: docker compose up -d" >&2
  exit 1
fi

# The extraction directory must be under $HOME so the container runtime can mount it.
work=$(mktemp -d "$HOME/render-restore.XXXXXX")
cleanup() {
  rm -rf "$work"
  docker compose start app >/dev/null
}
trap cleanup EXIT

echo "Extracting backup..."
tar -xzf "$archive" -C "$work"
toc=$(find "$work" -name toc.dat | head -n1)
if [[ -z "$toc" ]]; then
  echo "toc.dat not found: this is not a pg_dump directory-format backup." >&2
  exit 1
fi
# Render names the folder with colons, which are invalid in a Docker mount specification.
mv "$(dirname "$toc")" "$work/dump"
dump_dir="$work/dump"

# Stop the app so nothing writes while the database is being replaced.
docker compose stop app

# The app creates its own empty tables at startup; clear them so the Render schema is restored exactly.
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qc "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"' >/dev/null

export TARGET_URL="postgresql://${POSTGRES_USER:-label_verifier}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB:-label_verifier}"

echo "Restoring (this can take several minutes)..."
# Newer-server settings such as transaction_timeout are reported as errors on an older server but are harmless;
# the row counts below decide whether the restore succeeded.
rc=0
docker run --rm --network "$network" -v "$dump_dir":/dump:ro -e TARGET_URL \
  "docker.io/library/postgres:${pg_version}" \
  pg_restore --no-owner --no-acl -j 4 -d "$TARGET_URL" /dump || rc=$?
# Exit codes 125-127 mean docker itself failed, not pg_restore.
if (( rc >= 125 )); then
  echo "Docker failed to run the restore (exit $rc)." >&2
  exit "$rc"
elif (( rc != 0 )); then
  echo "pg_restore finished with warnings (exit $rc); check the counts below."
fi

echo "Row counts:"
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F " : " -c "
  select relname, n_live_tup from pg_stat_user_tables order by relname" ; psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "
  select '"'"'users (exact)'"'"', count(*) from users
  union all select '"'"'job_cards (exact)'"'"', count(*) from job_cards
  union all select '"'"'codes (exact)'"'"', count(*) from codes"' | sed 's/|/ : /'
