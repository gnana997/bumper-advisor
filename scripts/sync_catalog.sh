#!/usr/bin/env bash
# Vendor a fresh snapshot of the catalog from the Go repo into ./data so the image
# build is reproducible and offline. Re-run whenever the Go repo's catalog changes.
#
#   ./scripts/sync_catalog.sh            # uses ../bumper
#   BUMPER_REPO=/path/to/bumper ./scripts/sync_catalog.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
GO_REPO="${BUMPER_REPO:-$(cd "$HERE/.." && pwd)/bumper}"
DATA="$HERE/data"
CATALOG="$GO_REPO/internal/catalog/data"

[ -d "$CATALOG" ] || { echo "ERROR: catalog not found at $CATALOG (set BUMPER_REPO)"; exit 1; }

echo "syncing from $GO_REPO"
mkdir -p "$DATA"

# 1) advisory catalog: copy each source's per-provider json files
for src in trivy checkov kics prowler; do
  if [ -d "$CATALOG/$src" ]; then
    mkdir -p "$DATA/$src"
    cp -f "$CATALOG/$src"/*.json "$DATA/$src/"
    echo "  $src: $(ls "$DATA/$src"/*.json | wc -l | tr -d ' ') files"
  fi
done

# 2) enforced rules: dump from the binary and normalize to the common shape
BIN="$GO_REPO/bumper"
if [ -x "$BIN" ]; then
  DUMP=("$BIN" list --format json)
else
  echo "  (no prebuilt binary; using 'go run')"
  DUMP=(go run "$GO_REPO/cmd/bumper" list --format json)
fi
"${DUMP[@]}" | python3 "$HERE/scripts/normalize_enforced.py" > "$DATA/enforced.json"

echo "done -> $DATA"
