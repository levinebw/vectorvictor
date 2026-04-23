#!/usr/bin/env bash
# Cycode API gate — fail the build if Open violations exist for $REPO_NAME.
#
# Required env:
#   CYCODE_CLIENT_ID, CYCODE_CLIENT_SECRET
#   REPO_NAME     — BARE repo name as stored in Cycode's RIG (e.g. "vectorvictor",
#                   NOT "AppSecHQ/vectorvictor"). Check the Violations UI to confirm.
#
# Optional env (any combination):
#   SEVERITY_MIN     Critical | High | Medium | Low        (inclusive threshold)
#   CATEGORY         SAST | SCA | Secrets | IaC | ContainerScanning
#   RISK_SCORE_MIN   0–100
#
# Exit codes:
#   0  no Open violations matching the filters
#   1  one or more Open violations found → build should fail
#   2  invalid input
#   10 auth or API error
set -euo pipefail

: "${CYCODE_CLIENT_ID:?CYCODE_CLIENT_ID is required}"
: "${CYCODE_CLIENT_SECRET:?CYCODE_CLIENT_SECRET is required}"
: "${REPO_NAME:?REPO_NAME is required (e.g. 'AppSecHQ/vectorvictor')}"

SEVERITY_MIN="${SEVERITY_MIN:-}"
CATEGORY="${CATEGORY:-}"
RISK_SCORE_MIN="${RISK_SCORE_MIN:-}"

API_BASE="https://api.cycode.com"

echo "Cycode API gate: checking Open violations for ${REPO_NAME}"

# --- Authenticate ---------------------------------------------------------
AUTH_RESP=$(curl -sS -X POST "${API_BASE}/api/v1/auth/api-token" \
  -H "Content-Type: application/json" \
  -d "{\"clientId\":\"${CYCODE_CLIENT_ID}\",\"secret\":\"${CYCODE_CLIENT_SECRET}\"}") || {
  echo "##vso[task.logissue type=error]Auth request failed"
  exit 10
}

TOKEN=$(jq -r '.token // empty' <<<"$AUTH_RESP")
if [[ -z "$TOKEN" ]]; then
  echo "##vso[task.logissue type=error]Cycode authentication returned no token"
  exit 10
fi

# --- Build filters --------------------------------------------------------
FILTERS=$(jq -n --arg repo "$REPO_NAME" '
  [
    {name:"status", operator:"Eq", value:"Open", type:"String"},
    {name:"detection_details.repository_name", operator:"Eq", value:$repo, type:"String"}
  ]')

if [[ -n "$SEVERITY_MIN" ]]; then
  case "$SEVERITY_MIN" in
    Critical|critical) SEVS="Critical" ;;
    High|high)         SEVS="Critical,High" ;;
    Medium|medium)     SEVS="Critical,High,Medium" ;;
    Low|low)           SEVS="Critical,High,Medium,Low" ;;
    *) echo "Invalid SEVERITY_MIN='$SEVERITY_MIN'"; exit 2 ;;
  esac
  FILTERS=$(jq --arg v "$SEVS" '. + [{name:"severity", operator:"In", value:$v, type:"String"}]' <<<"$FILTERS")
fi

if [[ -n "$CATEGORY" ]]; then
  FILTERS=$(jq --arg v "$CATEGORY" '. + [{name:"category", operator:"Eq", value:$v, type:"String"}]' <<<"$FILTERS")
fi

if [[ -n "$RISK_SCORE_MIN" ]]; then
  FILTERS=$(jq --arg v "$RISK_SCORE_MIN" '. + [{name:"risk_score", operator:"Gte", value:$v, type:"Numeric"}]' <<<"$FILTERS")
fi

BODY=$(jq -n --argjson filters "$FILTERS" '{
  resource_type: "detection",
  filters: [{mode:"And", filters: $filters}],
  sort_by: "risk_score",
  sort_order: "desc",
  limit: -1,
  fast_query: true,
  connections: [], exists: true, is_optional: false, edge_type: "",
  variables: [], edge_filters: [], edge_columns: [],
  parent_resource_type: "", optional_connections_minimum_count: 0
}')

# --- Query RIG ------------------------------------------------------------
RESPONSE=$(curl -sS -X POST \
  "${API_BASE}/graph/api/v1/graph/query?mode=AlertWhen&page_number=0&page_size=200" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$BODY") || {
  echo "##vso[task.logissue type=error]RIG query failed"
  exit 10
}

if ! jq -e '.result' >/dev/null 2>&1 <<<"$RESPONSE"; then
  echo "##vso[task.logissue type=error]Unexpected API response"
  head -c 500 <<<"$RESPONSE"; echo
  exit 10
fi

COUNT=$(jq '.result | length' <<<"$RESPONSE")
HAS_MORE=$(jq -r '.fast_query_has_more // false' <<<"$RESPONSE")
if [[ "$HAS_MORE" == "true" ]]; then
  COUNT_LABEL="at least ${COUNT} (page cap hit)"
else
  COUNT_LABEL="${COUNT}"
fi
echo "Open violations matching filters for ${REPO_NAME}: ${COUNT_LABEL}"

# --- Decision -------------------------------------------------------------
if (( COUNT > 0 )); then
  echo
  echo "Top findings:"
  # Each .result[] item wraps the detection in a .resource object.
  jq -r '.result[] | .resource | "  [\(.severity // "-") / risk \(.risk_score // "-")] \(.source_policy_name // "-") — \(.detection_details.file_path // .detection_details.package_name // .source_entity_name // "-"):\(.detection_details.line // "")"' \
    <<<"$RESPONSE" | head -20
  echo
  echo "##vso[task.logissue type=error]Cycode gate failed: ${COUNT_LABEL} Open violation(s) in ${REPO_NAME}"
  exit 1
fi

echo "Cycode gate passed: no Open violations matched the filters"
