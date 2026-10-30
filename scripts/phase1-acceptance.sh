#!/bin/sh
# Fail-closed bridge to an operator-controlled, read-only Android runtime validator.
# This script deliberately does not treat APK builds or agent-written reports as proof.
set -eu

TS2_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
VALIDATOR=${TS2_TRUSTED_PHASE1_VALIDATOR-}

if [ -z "$VALIDATOR" ]; then
    echo 'Phase 1 BLOCKED: TS2_TRUSTED_PHASE1_VALIDATOR is unset.' >&2
    echo 'See docs/AUTONOMOUS_SETUP.md. A real external emulator/device validator is required.' >&2
    exit 78
fi

case "$VALIDATOR" in
    /*) ;;
    *) echo 'Phase 1 BLOCKED: validator path must be absolute.' >&2; exit 78 ;;
esac

if [ ! -f "$VALIDATOR" ] || [ ! -x "$VALIDATOR" ]; then
    echo 'Phase 1 BLOCKED: trusted validator is missing or not executable.' >&2
    exit 78
fi

# Canonicalize the final file too (not just the directory), to reject symlinks
# leading back into the checkout. Linux/Unraid workers provide readlink -f.
RESOLVED_VALIDATOR=$(readlink -f -- "$VALIDATOR" 2>/dev/null) || {
    echo 'Phase 1 BLOCKED: cannot resolve trusted validator.' >&2
    exit 78
}
case "$RESOLVED_VALIDATOR" in
    "$TS2_ROOT"/*)
        echo 'Phase 1 BLOCKED: validator must live outside the agent-writable checkout.' >&2
        exit 78
        ;;
esac

# The operator must also ensure the external validator is read-only to the agent.
# It must perform actual APK install/launch/gameplay checks and exit nonzero if
# evidence is absent, incomplete, diagnostic-only or otherwise unverified.
exec "$RESOLVED_VALIDATOR" --repo "$TS2_ROOT" --task "$TS2_ROOT/tasks/android-phase1"
