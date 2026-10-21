#!/bin/bash
# php2shell-safe-poc: look up which Cloudflare WAF rule fired
#
# Takes the cf-ray value printed by verify_waf.sh and queries Cloudflare's
# GraphQL Security Events API for the exact rule ID/description that
# blocked it. This is the step that turns "we got a 403" into "the
# documented php2shell rule fired" — cross-reference the printed ruleId
# against whichever rule IDs your WAF provider has explicitly published for
# this CVE (e.g. Cloudflare's own write-up covering PHP2Shell coverage) to
# confirm the block is CVE-specific, not an incidental/generic anomaly rule.
#
# Requires a Cloudflare API token with Zone > Analytics > Read.
# Usage:
#   CF_API_TOKEN=... CF_ZONE_ID=... RAY_ID=<cf-ray value> bash scripts/lookup_cf_rule.sh
set -u

CF_API_TOKEN="${CF_API_TOKEN:?set CF_API_TOKEN (Zone:Analytics:Read)}"
CF_ZONE_ID="${CF_ZONE_ID:?set CF_ZONE_ID}"
RAY_ID="${RAY_ID:?set RAY_ID=<cf-ray value from verify_waf.sh output>}"

# cf-ray looks like "<hex-id>-<colo>"; the GraphQL rayName filter wants just the hex id
RAY_NAME="${RAY_ID%%-*}"

read -r -d '' QUERY <<EOF
{
  "query": "query(\$zoneTag: String!, \$ray: String!) { viewer { zones(filter: {zoneTag: \$zoneTag}) { firewallEventsAdaptive(filter: {rayName: \$ray}, limit: 10, orderBy: [datetime_DESC]) { rayName action ruleId description source datetime clientIP clientRequestPath } } } }",
  "variables": { "zoneTag": "$CF_ZONE_ID", "ray": "$RAY_NAME" }
}
EOF

echo "Querying Cloudflare Security Events for ray $RAY_NAME ..."
curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "$QUERY" | python3 -m json.tool

echo
echo "Next: compare the 'ruleId' / 'description' above against the rule ID(s) your"
echo "WAF provider has explicitly published for CVE-2026-109618/109619. A match"
echo "confirms CVE-specific coverage; a non-matching generic/anomaly rule ID means"
echo "the block was incidental, not purpose-built for this CVE — treat that as a"
echo "weaker guarantee and escalate accordingly."
