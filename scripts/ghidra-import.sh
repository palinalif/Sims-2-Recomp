#!/usr/bin/env bash
# One-time import of the authorized, hash-verified private Legacy analysis image
# into a PERSISTENT private Ghidra project under ignored work/ghidra/.
#
# The original image is never modified: Ghidra imports a staged copy.
# Routine inspection uses scripts/ghidra-query.sh, never this script.
#
# Overridable: TOOLS_ROOT, GHIDRA_HEADLESS_HOME, JAVA_HOME, GHIDRA_IMPORT_MAXMEM,
# GHIDRA_IMPORT_MAXCPU, GHIDRA_IMPORT_TIMEOUT, SIMS2_ANALYSIS_IMAGE, SIMS2_IMAGE_SHA256.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${TOOLS_ROOT:-$(cd "$REPO/.." && pwd)/.local-tools}"
export JAVA_HOME="${JAVA_HOME:-$TOOLS/jdk25}"
export PATH="$JAVA_HOME/bin:$PATH"
GHIDRA="${GHIDRA_HEADLESS_HOME:-$TOOLS/ghidra-12.2}"

# Evidence (2026-10-22T15:53Z): the first import aborted with
# `java.lang.OutOfMemoryError: Java heap space` using analyzeHeadless's MAXMEM
# default of 2G on this 18 MB / ~14 MB-of-code image, and analyzeHeadless still
# exited 0. 12G is bounded but sufficient on a 35 GB-available host; lower it on
# smaller hosts and expect a longer run.
export GHIDRA_HEADLESS_MAXMEM="${GHIDRA_IMPORT_MAXMEM:-12G}"
MAXCPU="${GHIDRA_IMPORT_MAXCPU:-8}"
TIMEOUT_FILE="${GHIDRA_IMPORT_TIMEOUT:-3600}"

SRC="${SIMS2_ANALYSIS_IMAGE:-$REPO/work/interop-legacy-002/analysis-image.bin}"
EXPECTED="${SIMS2_IMAGE_SHA256:-63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985}"
PROJ="${GHIDRA_PROJECT_DIR:-$REPO/work/ghidra}"
PROJ_NAME="${GHIDRA_PROJECT_NAME:-Sims2Legacy118}"
STAGE="$PROJ/stage"
USERHOME="${GHIDRA_USER_HOME:-$TOOLS/ghidra-user}"
PROGRAM="${GHIDRA_PROGRAM_NAME:-Sims2EP9-1.18.0.187-analysis-image}"

PY="${PY:-$TOOLS/python/bin/python3}"
sha() { "$PY" -c 'import hashlib,sys;h=hashlib.sha256();f=open(sys.argv[1],"rb");
[h.update(b) for b in iter(lambda:f.read(1<<22),b"")];print(h.hexdigest())' "$1"; }
ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

[ -r "$SRC" ] || { echo "ABORT: authorized image not present at $SRC (private transfer required)"; exit 2; }
[ -x "$GHIDRA/support/analyzeHeadless" ] || { echo "ABORT: no analyzeHeadless under $GHIDRA"; exit 2; }

echo "[$(ts)] verifying authorized image hash before import"
GOT=$(sha "$SRC") || { echo "ABORT: cannot hash $SRC"; exit 2; }
echo "  sha256=$GOT"
if [ "$GOT" != "$EXPECTED" ]; then echo "ABORT: hash mismatch, refusing to import"; exit 3; fi

umask 077
mkdir -p "$PROJ" "$STAGE" "$USERHOME" || exit 1
chmod 700 "$PROJ" "$STAGE" "$USERHOME"

COPY="$STAGE/$PROGRAM.bin"
if [ ! -f "$COPY" ]; then
  echo "[$(ts)] staging an import copy (original untouched: $SRC)"
  cp "$SRC" "$COPY" && chmod 600 "$COPY" || exit 1
  echo "  copy sha256=$(sha "$COPY")"
fi

# Decide from real evidence: a SUCCESSFUL Ghidra project can still have a
# 0-byte .gpr, so never judge completeness by file size (that would let a re-run
# delete a good database).
if [ -d "$PROJ/$PROJ_NAME.rep" ]; then
  if [ -f "$PROJ/import.log" ] && grep -q 'REPORT: Import succeeded' "$PROJ/import.log"; then
    echo "[$(ts)] project already imported successfully; not re-importing. Use scripts/ghidra-query.sh."
    ls -la "$PROJ"
    exit 0
  fi
  echo "[$(ts)] existing project has no recorded successful import; discarding it"
  rm -rf "$PROJ/$PROJ_NAME.gpr" "$PROJ/$PROJ_NAME.rep" "$PROJ"/*.lock "$PROJ"/*.lock~
  rm -f "$PROJ/program-name.txt"
fi

# NOTE: the file keeps a valid PE header, so Ghidra's PE loader is used (it
# honours image base 0xA0000000, sections and imports). The detected entry point
# sits in .bind because SteamStub wrapped it; docs/INTEROP_EXPERIMENT.md is
# authoritative for the real game entry, so never treat Ghidra's entry as truth.
echo "[$(ts)] importing + analyzing (bounded: max-cpu $MAXCPU, timeout ${TIMEOUT_FILE}s/file)"
HOME="$USERHOME" "$GHIDRA/support/analyzeHeadless" "$PROJ" "$PROJ_NAME" \
  -import "$COPY" -max-cpu "$MAXCPU" -analysisTimeoutPerFile "$TIMEOUT_FILE" \
  -log "$PROJ/import.log" 2>&1 | sed -u 's/^/  import: /'
echo "[$(ts)] import step exit=$?"

# analyzeHeadless can exit 0 after a fatal analyzer error, so grep the log.
if grep -qE 'OutOfMemoryError|Abort due to Headless analyzer error' "$PROJ/import.log"; then
  echo "[$(ts)] RESULT: FAILED - see the fatal line above (exit code is not trustworthy here)"
  grep -oE 'java.lang.OutOfMemoryError.*|Abort due to Headless analyzer error: [^(]*' "$PROJ/import.log" | tail -2
  exit 4
fi
grep -q 'REPORT: Import succeeded' "$PROJ/import.log" || { echo "[$(ts)] RESULT: FAILED - no success record"; exit 4; }

echo "[$(ts)] RESULT: import succeeded; recording the stored program name for queries"
sed -n 's|.*REPORT: Save succeeded for: \(\/[A-Za-z0-9._-]*\) .*|\1|p' "$PROJ/import.log" \
  | tail -1 > "$PROJ/program-name.txt"
cat "$PROJ/program-name.txt"
ls -la "$PROJ"
