#!/usr/bin/env bash
# Regenerate the VPP binary-API Go bindings under internal/binapi/ (T-204).
#
# Bindings are generated from a VPP source tree's .api files, for the version the
# edge runs (DESIGN.md §1: ghcr.io/fivetime/vpp:master = FDio/vpp master). The
# generated code is committed (vendored), so this script is run only when bumping
# VPP or adding a plugin — not in CI.
#
# Usage:
#   VPP_SRC=/path/to/vpp scripts/gen-binapi.sh
#
# Requirements: python3 + ply (VPP's vppapigen), and binapi-generator at the same
# version as go.mod's go.fd.io/govpp (currently v0.13.0):
#   go install go.fd.io/govpp/cmd/binapi-generator@v0.13.0
set -euo pipefail
cd "$(dirname "$0")/.."

VPP_SRC="${VPP_SRC:?set VPP_SRC to the VPP source tree (FDio/vpp master)}"
PREFIX="github.com/fivetime/sbw-limiter/internal/binapi"
OUT="internal/binapi"

# Plugins the edge-agent uses; their type deps are pulled in automatically and
# the output is pruned to the import closure below.
KEEP="classify ethernet_types interface interface_types ip_types lcp memclnt policer policer_types"

command -v binapi-generator >/dev/null || {
  echo "binapi-generator not found; go install go.fd.io/govpp/cmd/binapi-generator@v0.12.0" >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> compiling .api -> .api.json from $VPP_SRC"
n=0
while IFS= read -r f; do
  base="$(basename "$f" .api)"
  python3 "$VPP_SRC/src/tools/vppapigen/vppapigen" \
    --includedir "$VPP_SRC/src" --input "$f" --outputdir "$tmp" \
    JSON --output "$tmp/${base}.api.json" 2>/dev/null && n=$((n + 1)) || true
done < <(find "$VPP_SRC/src" -name '*.api' -not -path '*/test/*')
echo "    generated $n api.json files"

echo "==> generating Go bindings"
rm -rf "$OUT"/*/
binapi-generator --input "$tmp" --output-dir "$OUT" \
  --import-prefix "$PREFIX" --no-source-path-info

echo "==> pruning to import closure"
removed=0
for d in "$OUT"/*/; do
  pkg="$(basename "$d")"
  case " $KEEP " in
    *" $pkg "*) ;;
    *) rm -rf "$d"; removed=$((removed + 1)) ;;
  esac
done
echo "    removed $removed packages, kept $(find "$OUT" -mindepth 1 -maxdepth 1 -type d | wc -l)"

echo "==> tidy + build"
go mod tidy
go build ./internal/binapi/...
echo "done. Review git diff and update binapi.go VPPVersion if VPP changed."
