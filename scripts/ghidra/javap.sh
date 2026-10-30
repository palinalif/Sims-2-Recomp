#!/usr/bin/env bash
# Inspect Ghidra 12.2 API signatures before writing query scripts against them.
#
# Ghidra 12 removed methods that 10.x/11.x had (for example Function.getBody()),
# and guessing produces a script that fails to compile inside the headless JVM
# where the error is easy to miss. Verify first:
#
#   scripts/ghidra/javap.sh ghidra.program.model.listing.FunctionManager
#
# Output is the raw javap member list for each requested class.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$REPO/scripts/campaign/worker-env.sh" >/dev/null 2>&1 || true

G="${GHIDRA_DIR:-$REPO/../.local-tools/ghidra-12.2}"
JAVAP="${JAVAP_BIN:-$REPO/../.local-tools/jdk25/bin/javap}"
[ -x "$JAVAP" ] || JAVAP="javap"
[ -d "$G" ] || { echo "Ghidra not found at $G (set GHIDRA_DIR)" >&2; exit 3; }

CP=""
for jar in \
  "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar" \
  "Ghidra/Framework/Utility/lib/Utility.jar" \
  "Ghidra/Framework/Language/lib/Language.jar" \
  "Ghidra/Framework/Generic/lib/Generic.jar" \
  "Ghidra/Features/Base/lib/Base.jar" \
  "Ghidra/Features/Decompiler/lib/Decompiler.jar"
do
  [ -f "$G/$jar" ] && CP="${CP:+$CP:}$G/$jar"
done

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <fully.qualified.Class> [...]" >&2
  exit 2
fi

for CLASS in "$@"; do
  echo "===== $CLASS ====="
  "$JAVAP" -classpath "$CP" "$CLASS" 2>&1 | grep -vE '^\s*$' | head -60
done
