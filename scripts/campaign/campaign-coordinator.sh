#!/usr/bin/env bash
# Wrapper: loads the vendored toolchain, then runs the coordinator.
# Usage: scripts/campaign/campaign-coordinator.sh start|status|stop|clear-stop|report [options]
set -u
cd "$(dirname "$0")/../.." 2>/dev/null || exit 64
if [ -z "${TS2_WORKER_ENV_LOADED:-}" ]; then
  # shellcheck disable=SC1091
  . scripts/campaign/worker-env.sh || exit 65
fi
exec "${PYTHON:-python3}" scripts/campaign/campaign-coordinator.py "$@"
