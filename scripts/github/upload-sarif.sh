#!/usr/bin/env bash
# Upload every SARIF file of a scan to GitHub code scanning, one category per file
# (several runs of the same tool under one category are rejected by GitHub).
# Usage: upload-sarif.sh <sarif-dir>   (inside GitHub Actions; needs GH_TOKEN with
#        security-events: write). Never fails the job: code scanning is only
#        available on public repos for this account.
set -uo pipefail
dir=${1:?usage: upload-sarif.sh <sarif-dir>}
for f in "$dir"/*.sarif; do
  [ -s "$f" ] || continue
  name=$(basename "$f" .sarif)
  sarif=$(jq -c --arg id "security-scan/$name/" '.runs[].automationDetails = {id: $id}' "$f" | gzip -c | base64 | tr -d '\n')
  if jq -n --arg sha "$GITHUB_SHA" --arg ref "$GITHUB_REF" --arg sarif "$sarif" \
       '{commit_sha: $sha, ref: $ref, sarif: $sarif, tool_name: "security-scan"}' \
     | gh api -X POST "repos/$GITHUB_REPOSITORY/code-scanning/sarifs" --input - >/dev/null; then
    echo "uploaded $name"
  else
    echo "::warning::SARIF upload failed for $name (code scanning unavailable?)"
  fi
done
