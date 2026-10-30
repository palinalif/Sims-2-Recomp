#!/bin/sh
# Read-only inventory. Exit 78 means missing build prerequisites, not a test pass.
set -eu
TS2_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$TS2_ROOT/tools/android_env_probe.py" "$@"
