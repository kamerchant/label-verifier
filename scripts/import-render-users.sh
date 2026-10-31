#!/usr/bin/env bash
set -euo pipefail

# Usage: bash scripts/import-render-users.sh
# Copies only the users table from Render into the Docker Compose PostgreSQL service.
# Existing local users are replaced. Job and scan data are not touched.
cd "$(dirname "$0")/.."

# The client tools must be at least as new as the Render server (18).
pg_version=${PG_VERSION:-18}

if [[ ! -f .env ]]; then
  echo ".env not found. Create it first (see README)." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z "${RENDER_DATABASE_URL:-}" ]]; then
  read -r -s -p "Render external database URL: " RENDER_DATABASE_URL
  echo
fi

network="$(docker compose ps -q db | head -n1 | xargs docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
if [[ -z "$network" ]]; then
  echo "The db service is not running. Start it with: docker compose up -d" >&2
  exit 1
fi

# Stop the app so nothing writes while users are being replaced.
docker compose stop app
trap 'docker compose start app >/dev/null' EXIT

export SOURCE_URL="$RENDER_DATABASE_URL"
export TARGET_URL="postgresql://${POSTGRES_USER:-label_verifier}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB:-label_verifier}"

copy_command='set -euo pipefail
# Column inserts keep the load independent of column order. The whole load runs in one transaction.
{
  echo "BEGIN;"
  echo "TRUNCATE users RESTART IDENTITY;"
  pg_dump --data-only --column-inserts --no-owner --no-acl -t public.users "$SOURCE_URL" \
    | grep -v -E "^(SET|SELECT pg_catalog.set_config)"
  echo "SELECT setval(pg_get_serial_sequence('"'"'users'"'"', '"'"'id'"'"'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM users;"
  echo "COMMIT;"
} | psql -v ON_ERROR_STOP=1 -q -o /dev/null "$TARGET_URL"
s=$(psql "$SOURCE_URL" -Atc "select count(*) from users")
d=$(psql "$TARGET_URL" -Atc "select count(*) from users")
if [ "$s" = "$d" ]; then echo "users render=$s local=$d OK"; else echo "users render=$s local=$d MISMATCH"; exit 1; fi'

# Variables are passed by name so the credentials never appear in the process list.
docker run --rm --network "$network" -e SOURCE_URL -e TARGET_URL \
  "docker.io/library/postgres:${pg_version}" /bin/bash -c "$copy_command"
