#!/bin/sh
# Source scripts/campaign/worker-env.sh first on the campaign host.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$ROOT/tools/pointer_scan.py" "$@"
