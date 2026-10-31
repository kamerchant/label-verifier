#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash scripts/deploy-azure.sh <resource-group> <azure-region>" >&2
  exit 2
fi

resource_group=$1
location=$2
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI (az) is required. Install it from https://aka.ms/installazureclimacos." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required to generate deployment secrets." >&2
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "Sign in to Azure first by running: az login" >&2
  exit 1
fi

az provider register --namespace Microsoft.Web --wait
az provider register --namespace Microsoft.Network --wait
az provider register --namespace Microsoft.DBforPostgreSQL --wait
az provider register --namespace Microsoft.ContainerRegistry --wait
az group create --name "$resource_group" --location "$location" --output none

postgres_password=$(python3 -c 'import secrets,string; chars=string.ascii_letters+string.digits; print("".join(secrets.choice(chars) for _ in range(48)))')
session_secret=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

deployment=$(az deployment group create \
  --resource-group "$resource_group" \
  --name label-verifier \
  --template-file "$repo_root/infra/azure.bicep" \
  --parameters location="$location" postgresAdminPassword="$postgres_password" sessionSecret="$session_secret" \
             appPlanSku="${APP_PLAN_SKU:-B1}" \
             postgresSkuName="${POSTGRES_SKU_NAME:-Standard_B1ms}" postgresSkuTier="${POSTGRES_SKU_TIER:-Burstable}" \
  --output json)

acr_name=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["properties"]["outputs"]["acrName"]["value"])' <<<"$deployment")
app_name=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["properties"]["outputs"]["appName"]["value"])' <<<"$deployment")
app_url=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["properties"]["outputs"]["appUrl"]["value"])' <<<"$deployment")

az acr build \
  --registry "$acr_name" \
  --image label-verifier:latest \
  "$repo_root"

az webapp restart --resource-group "$resource_group" --name "$app_name"

printf '\nDeployment complete.\nApp URL: %s\nResource group: %s\nApp Service: %s\nRegistry: %s\n' \
  "$app_url" "$resource_group" "$app_name" "$acr_name"
printf 'Create the first administrator by following the Azure setup instructions in README.md.\n'
