#!/usr/bin/env bash
# Download the pinned scanners into a bin dir and verify their SHA-256 sums.
# Usage: install-tools.sh <bin-dir>    (linux amd64 or darwin arm64)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tools.env
. "$here/tools.env"
bin=${1:?usage: install-tools.sh <bin-dir>}
mkdir -p "$bin"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) plat=linux_amd64; trivy_os=Linux-64bit; osv_os=linux_amd64; bl_os=linux_x64; og_os=manylinux_x86 ;;
  Darwin-arm64) plat=darwin_arm64; trivy_os=macOS-ARM64; osv_os=darwin_arm64; bl_os=darwin_arm64; og_os=osx_arm64 ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

fetch() { # url sha dest
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch: $1" >&2; exit 1; }
}
sha() { local v="${1}_SHA256_${plat}"; echo "${!v}"; }

fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${trivy_os}.tar.gz" "$(sha TRIVY)" "$work/trivy.tgz"
tar -xzf "$work/trivy.tgz" -C "$work" trivy && install -m 0755 "$work/trivy" "$bin/trivy"

fetch "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${osv_os}" "$(sha OSV)" "$work/osv-scanner"
install -m 0755 "$work/osv-scanner" "$bin/osv-scanner"

fetch "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_${bl_os}.tar.gz" "$(sha BETTERLEAKS)" "$work/bl.tgz"
tar -xzf "$work/bl.tgz" -C "$work" betterleaks && install -m 0755 "$work/betterleaks" "$bin/betterleaks"

fetch "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_${og_os}" "$(sha OPENGREP)" "$work/opengrep"
install -m 0755 "$work/opengrep" "$bin/opengrep"

echo "installed trivy $TRIVY_VERSION, osv-scanner $OSV_VERSION, betterleaks $BETTERLEAKS_VERSION, opengrep $OPENGREP_VERSION to $bin"
