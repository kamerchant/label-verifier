#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: RENDER_DATABASE_URL='postgresql://...' bash scripts/migrate-render-to-azure.sh <resource-group>" >&2
  exit 2
fi

resource_group=$1
# The client tools must be at least as new as the Render server (18). Restoring into the older Azure server is supported.
pg_version=${PG_VERSION:-18}

if [[ -z "${RENDER_DATABASE_URL:-}" ]]; then
  read -r -s -p "Render external database URL: " RENDER_DATABASE_URL
  echo
fi

az provider register --namespace Microsoft.ContainerInstance --wait

app_name=$(az webapp list -g "$resource_group" --query "[0].name" -o tsv)
# Stop the Azure app so nothing writes to the database while it is being replaced.
az webapp stop -g "$resource_group" -n "$app_name"
trap 'az webapp start -g "$resource_group" -n "$app_name" --output none' EXIT
location=$(az group show -n "$resource_group" --query location -o tsv)
target_url=$(az webapp config appsettings list -g "$resource_group" -n "$app_name" \
  --query "[?name=='DATABASE_URL'].value | [0]" -o tsv)

if [[ -z "$app_name" || -z "$target_url" ]]; then
  echo "Could not find the app or its DATABASE_URL in $resource_group." >&2
  exit 1
fi

# Dump is streamed Render -> Azure; nothing is written to disk. Counts are printed for verification.
copy_command='set -o pipefail
# The app creates its own empty tables at startup; remove them so the Render schema is restored exactly.
for t in $(psql "$TARGET_URL" -Atc "select tablename from pg_tables where schemaname = current_schema()"); do
  psql "$TARGET_URL" -qc "DROP TABLE IF EXISTS public.\"$t\" CASCADE"
done
pg_dump --no-owner --no-acl -Fc "$SOURCE_URL" | pg_restore --no-owner --no-acl -d "$TARGET_URL"
echo "pipeline exit: $? (harmless warnings about newer settings can make this non-zero; the counts decide)"
bad=0
for t in users job_cards codes scan_logs packing_qc_logs packing_qc_completions job_lifecycle_logs system_audit_logs phone_scanner_sessions job_code_duplicate_rows; do
  s=$(psql "$SOURCE_URL" -Atc "select count(*) from $t" 2>&1)
  d=$(psql "$TARGET_URL" -Atc "select count(*) from $t" 2>&1)
  if [ "$s" = "$d" ]; then r=OK; else r=MISMATCH; bad=1; fi
  echo "$t render=$s azure=$d $r"
done
exit $bad'

job=label-verifier-migrate
az container delete -g "$resource_group" -n "$job" --yes >/dev/null 2>&1 || true

az container create \
  --resource-group "$resource_group" \
  --name "$job" \
  --location "$location" \
  --image "docker.io/library/postgres:${pg_version}" \
  --os-type Linux --cpu 1 --memory 2 \
  --restart-policy Never \
  --vnet label-qc-vnet --subnet tools \
  --secure-environment-variables SOURCE_URL="$RENDER_DATABASE_URL" TARGET_URL="$target_url" \
  --command-line "/bin/bash -c '$copy_command'" \
  --output none

echo "Migration running in Azure..."
while true; do
  state=$(az container show -g "$resource_group" -n "$job" --query "containers[0].instanceView.currentState.state" -o tsv)
  [[ "$state" == "Terminated" ]] && break
  sleep 15
done

az container logs -g "$resource_group" -n "$job"
exit_code=$(az container show -g "$resource_group" -n "$job" --query "containers[0].instanceView.currentState.exitCode" -o tsv)
az container delete -g "$resource_group" -n "$job" --yes --output none
echo "Migration container finished with exit code $exit_code and was removed."
