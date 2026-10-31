#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash scripts/azure-sql.sh <resource-group> \"<SQL statement>\"" >&2
  exit 2
fi

resource_group=$1
sql=$2

az provider register --namespace Microsoft.ContainerInstance --wait

app_name=$(az webapp list -g "$resource_group" --query "[0].name" -o tsv)
location=$(az group show -n "$resource_group" --query location -o tsv)
target_url=$(az webapp config appsettings list -g "$resource_group" -n "$app_name" \
  --query "[?name=='DATABASE_URL'].value | [0]" -o tsv)

if [[ -z "$app_name" || -z "$target_url" ]]; then
  echo "Could not find the app or its DATABASE_URL in $resource_group." >&2
  exit 1
fi

job=label-verifier-sql
az container delete -g "$resource_group" -n "$job" --yes >/dev/null 2>&1 || true

az container create \
  --resource-group "$resource_group" \
  --name "$job" \
  --location "$location" \
  --image docker.io/library/postgres:16 \
  --os-type Linux --cpu 1 --memory 1 \
  --restart-policy Never \
  --vnet label-qc-vnet --subnet tools \
  --secure-environment-variables TARGET_URL="$target_url" SQL="$sql" \
  --command-line '/bin/bash -c "psql \"$TARGET_URL\" -c \"$SQL\""' \
  --output none

while true; do
  state=$(az container show -g "$resource_group" -n "$job" --query "containers[0].instanceView.currentState.state" -o tsv)
  [[ "$state" == "Terminated" ]] && break
  sleep 5
done

az container logs -g "$resource_group" -n "$job"
az container delete -g "$resource_group" -n "$job" --yes --output none
