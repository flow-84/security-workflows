#!/usr/bin/env bash
# Security scan of one checkout: Betterleaks (secrets), Trivy fs (vuln + misconfig),
# Trivy image (per Dockerfile), OSV-Scanner (dependencies), Opengrep (SAST).
# Same script in GitHub Actions (reusable workflow) and locally (scan-private.sh).
#
# Usage: scan.sh <target-dir> <out-dir>
# Env:   SCAN_IMAGES=1|0   build + scan Dockerfiles (default 1)
#        SCAN_CACHE=<dir>  cache for the opengrep rules (default ~/.cache/security-scan)
# Writes one SARIF file per tool into <out-dir>/sarif/ plus summary.md and summary.tsv.
# Exit 1 when a gate fails: any secret, any HIGH/CRITICAL fixable vulnerability or
# misconfiguration, any OSV advisory with CVSS >= 7, any Opengrep ERROR finding
# outside the low-confidence audit rules.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tools.env
. "$here/tools.env"
target=$(cd "${1:?usage: scan.sh <target-dir> <out-dir>}" && pwd)
out=${2:?usage: scan.sh <target-dir> <out-dir>}
mkdir -p "$out/sarif"; out=$(cd "$out" && pwd)
cache=${SCAN_CACHE:-$HOME/.cache/security-scan}
failed=0
cd "$target"  # relative paths in every report (needed for SARIF upload)
: > "$out/summary.tsv"

sarif_count() { jq '[.runs[]?.results[]?] | length' "$1" 2>/dev/null || echo "?"; }
record() { # tool findings gate(pass|FAIL|skip) note
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" >> "$out/summary.tsv"
  [ "$3" = FAIL ] && failed=1
  return 0
}

# --- Betterleaks: full history when available, working tree otherwise ------------
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = false ]; then mode=git; else mode=dir; fi
betterleaks "$mode" . --no-banner --redact --exit-code 3 \
  -f sarif -r "$out/sarif/betterleaks.sarif" >"$out/betterleaks.log" 2>&1
rc=$?
n=$(sarif_count "$out/sarif/betterleaks.sarif")
case $rc in 0) record betterleaks "$n" pass "$mode" ;; 3) record betterleaks "$n" FAIL "$mode" ;; *) record betterleaks "?" FAIL "error rc=$rc, see betterleaks.log" ;; esac

# --- Trivy fs: dependency vulnerabilities and IaC/config misconfigurations --------
trivy fs . --quiet --scanners vuln,misconfig --severity HIGH,CRITICAL --ignore-unfixed \
  --skip-dirs node_modules --skip-dirs .git --exit-code 3 \
  --format sarif --output "$out/sarif/trivy-fs.sarif" >"$out/trivy-fs.log" 2>&1
rc=$?
n=$(sarif_count "$out/sarif/trivy-fs.sarif")
case $rc in 0) record trivy-fs "$n" pass ;; 3) record trivy-fs "$n" FAIL ;; *) record trivy-fs "?" FAIL "error rc=$rc, see trivy-fs.log" ;; esac

# --- Trivy image: build each Dockerfile, scan the image ---------------------------
dockerfiles=$(find . -path ./node_modules -prune -o -path ./.git -prune -o \
  -type f \( -name Dockerfile -o -name '*.Dockerfile' -o -name 'Dockerfile.*' \) -print 2>/dev/null | sort)
if [ -z "$dockerfiles" ]; then
  record trivy-image 0 skip "no Dockerfile"
elif [ "${SCAN_IMAGES:-1}" != 1 ] || ! docker info >/dev/null 2>&1; then
  record trivy-image "?" skip "image scan disabled or docker unavailable"
else
  i=0
  while IFS= read -r df; do
    i=$((i + 1)); tag="security-scan-local:$i"; ctx=$(dirname "$df")
    if ! docker build -q -f "$df" -t "$tag" "$ctx" >"$out/trivy-image-$i.build.log" 2>&1; then
      record "trivy-image $df" "?" skip "docker build failed, see trivy-image-$i.build.log"
      continue
    fi
    trivy image "$tag" --quiet --severity HIGH,CRITICAL --ignore-unfixed --exit-code 3 \
      --format sarif --output "$out/sarif/trivy-image-$i.sarif" >"$out/trivy-image-$i.log" 2>&1
    rc=$?
    n=$(sarif_count "$out/sarif/trivy-image-$i.sarif")
    case $rc in 0) record "trivy-image $df" "$n" pass ;; 3) record "trivy-image $df" "$n" FAIL ;; *) record "trivy-image $df" "?" FAIL "error rc=$rc" ;; esac
    docker image rm -f "$tag" >/dev/null 2>&1
  done <<< "$dockerfiles"
fi

# --- OSV-Scanner: advisories for every lockfile; gate on CVSS >= 7 ---------------
osv-scanner scan source -r . --format json --output "$out/osv.json" >"$out/osv.log" 2>&1
rc=$?
osv-scanner scan source -r . --format sarif --output "$out/sarif/osv.sarif" >>"$out/osv.log" 2>&1
case $rc in
  0|1)
    total=$(jq '[.results[]?.packages[]?.groups[]?] | length' "$out/osv.json")
    high=$(jq '[.results[]?.packages[]?.groups[]? | (.max_severity // "" | tonumber? // 0) | select(. >= 7)] | length' "$out/osv.json")
    if [ "$high" -gt 0 ]; then record osv-scanner "$total" FAIL "$high with CVSS>=7"; else record osv-scanner "$total" pass "none with CVSS>=7"; fi ;;
  128) record osv-scanner 0 skip "no lockfiles" ;;
  *) record osv-scanner "?" FAIL "error rc=$rc, see osv.log" ;;
esac

# --- Opengrep: SAST with the pinned community rules; gate on ERROR severity -------
rules="$cache/opengrep-rules-$OPENGREP_RULES_SHA"
if [ ! -d "$rules/.git" ]; then
  rm -rf "$rules"; mkdir -p "$rules"
  git -C "$rules" init -q && git -C "$rules" remote add origin https://github.com/opengrep/opengrep-rules.git \
    && git -C "$rules" fetch -q --depth 1 origin "$OPENGREP_RULES_SHA" && git -C "$rules" checkout -q FETCH_HEAD
fi
cfg=(); for d in $OPENGREP_RULE_DIRS; do [ -d "$rules/$d" ] && cfg+=(--config "$rules/$d"); done
opengrep scan "${cfg[@]}" --quiet --exclude node_modules --exclude vendor --exclude dist \
  --sarif-output "$out/sarif/opengrep.sarif" --json-output "$out/opengrep.json" . >"$out/opengrep.log" 2>&1
rc=$?
if [ -s "$out/opengrep.json" ]; then
  total=$(jq '.results | length' "$out/opengrep.json")
  # audit rules are low-confidence hints: reported, never gating
  errs=$(jq '[.results[] | select(.extra.severity == "ERROR" and (.check_id | contains(".audit.") | not))] | length' "$out/opengrep.json")
  if [ "$errs" -gt 0 ]; then record opengrep "$total" FAIL "$errs with severity ERROR"; else record opengrep "$total" pass "no non-audit ERROR"; fi
else
  record opengrep "?" FAIL "error rc=$rc, see opengrep.log"
fi

{
  echo "| Tool | Findings | Gate | Note |"
  echo "| --- | --- | --- | --- |"
  awk -F'\t' '{printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4}' "$out/summary.tsv"
} > "$out/summary.md"
cat "$out/summary.md"
exit $failed
