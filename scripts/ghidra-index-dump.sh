#!/usr/bin/env bash
# Build a local, greppable whole-image function index (rva, shape, callers,
# callees, pseudocode) so campaign workers stop paying a headless JVM start per
# Ghidra query. Runs against a disposable COPY of the persistent project: the
# original work/ghidra project and its query lock are never touched, so live
# campaigns keep answering single-address queries while the dump runs.
#
# Usage: scripts/ghidra-index-dump.sh [--max-pseudo N] [--no-decompile]
# resumable: rerun after a crash; work/ghidra-index/cursor.txt continues.
# Output (private, ignored): work/ghidra-index/functions.jsonl (+ cursor/done).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_ROOT="${TOOLS_ROOT:-/workspace/Sims 2 Decomp and Android port/.local-tools}"
GHIDRA_HOME="${GHIDRA_HEADLESS_HOME:-$TOOLS_ROOT/ghidra-12.2}"
export JAVA_HOME="${JAVA_HOME:-$TOOLS_ROOT/jdk25}"
export PATH="$JAVA_HOME/bin:$PATH"

SRC_PROJ_DIR="$REPO_ROOT/work/ghidra"
PROJ_NAME="Sims2Legacy118"
IDX_DIR="$REPO_ROOT/work/ghidra-index"
CP_DIR="$IDX_DIR/proj"
MAX_PSEUDO="600"
DECOMPILE="1"

while [ $# -gt 0 ]; do
  case "$1" in
    --max-pseudo) MAX_PSEUDO="$2"; shift 2 ;;
    --no-decompile) DECOMPILE="0"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PROGRAM="$(head -1 "$SRC_PROJ_DIR/program-name.txt" 2>/dev/null)"
[ -n "$PROGRAM" ] || { echo "no cached program name; run scripts/ghidra-query.sh once" >&2; exit 2; }

mkdir -p "$CP_DIR"
if [ ! -d "$CP_DIR/$PROJ_NAME.rep" ]; then
  echo "copying project to $CP_DIR (one-off, ~350 MB)..."
  cp -a "$SRC_PROJ_DIR/$PROJ_NAME.gpr" "$CP_DIR/" 2>/dev/null || true
  cp -a "$SRC_PROJ_DIR/$PROJ_NAME.rep" "$CP_DIR/" || { echo "project copy failed" >&2; exit 2; }
fi

LOG="$IDX_DIR/dump.$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$IDX_DIR"
HOME="$TOOLS_ROOT/ghidra-user" GHIDRA_HEADLESS_MAXMEM="${GHIDRA_DUMP_MAXMEM:-10G}" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$CP_DIR" "$PROJ_NAME" \
  -process "${PROGRAM#/}" -readOnly -noanalysis \
  -scriptPath "$REPO_ROOT/scripts/ghidra" -postScript Sims2IndexDump.java -- \
  "out=$IDX_DIR" "decompile=$DECOMPILE" "maxPseudoLines=$MAX_PSEUDO" > "$LOG" 2>&1
RC=$?
echo "headless rc=$RC log=$LOG"
[ -f "$IDX_DIR/done.txt" ] && echo "COMPLETE $(cat "$IDX_DIR/done.txt")" \
  || echo "incomplete (cursor=$(cat "$IDX_DIR/cursor.txt" 2>/dev/null)); rerun to resume"
exit $RC
