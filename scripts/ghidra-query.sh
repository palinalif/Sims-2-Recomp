#!/usr/bin/env bash
# Bounded, read-only Ghidra query against the persistent private Legacy project.
#
# Emits ONE JSON object (docs/GHIDRA_WORKFLOW.md "Pi integration" fallback):
# Ghidra's Sims2Query script output wrapped in a provenance envelope. Private
# results stay under ignored work/; never commit them.
#
# Usage:
#   scripts/ghidra-query.sh --rva 1AB665 [--pseudo 40] [--instructions 200]
#   scripts/ghidra-query.sh --va 0xa0001070 [--refs 80] [--callers 20]
# Options: --instructions/--refs/--callers/--callees N, --pseudo N (0 = none),
#          --out FILE, --quiet (path only), --force (ignore lock cache)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_ROOT="${TOOLS_ROOT:-/workspace/Sims 2 Decomp and Android port/.local-tools}"
GHIDRA_HOME="${GHIDRA_HEADLESS_HOME:-$TOOLS_ROOT/ghidra-12.2}"
JAVA_HOME="${JAVA_HOME:-$TOOLS_ROOT/jdk25}"
export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"

PROJ_DIR="$REPO_ROOT/work/ghidra"
PROJ_NAME="Sims2Legacy118"
SOURCE_IMAGE="$REPO_ROOT/work/interop-legacy-002/analysis-image.bin"
OUT_DIR="$PROJ_DIR/query-out"
NAME_CACHE="$PROJ_DIR/program-name.txt"
LOCK_DIR="$PROJ_DIR/.query.lock"
QUERY_SCRIPT_DIR="$REPO_ROOT/scripts/ghidra"

# Queries are read-only, but two headless JVMs against one project database can
# still race the lock file, so serialize locally. Docs require single-owner
# mutations; reads are serialized here as the cheap safe default.
QUERY_MEM="${GHIDRA_QUERY_MAXMEM:-8G}"

RVA=""; VA=""; MAXI=160; MAXR=60; MAXCALL=40; MAXCALLEE=60; MAXP=0
OUT=""; QUIET=0

die() { echo "ghidra-query: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --rva) RVA="${2:-}"; shift 2 ;;
    --va) VA="${2:-}"; shift 2 ;;
    --instructions) MAXI="${2:-}"; shift 2 ;;
    --refs) MAXR="${2:-}"; shift 2 ;;
    --callers) MAXCALL="${2:-}"; shift 2 ;;
    --callees) MAXCALLEE="${2:-}"; shift 2 ;;
    --pseudo) MAXP="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$RVA" ] || [ -n "$VA" ] || die "need --rva <hex> or --va <hex>"
[ -x "$GHIDRA_HOME/support/analyzeHeadless" ] || die "no analyzeHeadless under $GHIDRA_HOME"
[ -d "$PROJ_DIR/$PROJ_NAME.rep" ] || die "no Ghidra project at $PROJ_DIR (run the import first)"

PY="${PY:-$TOOLS_ROOT/python/bin/python3}"
sha_of() { [ -r "$1" ] && "$PY" -c 'import hashlib,sys;h=hashlib.sha256();f=open(sys.argv[1],"rb")
[h.update(b) for b in iter(lambda:f.read(1<<22),b"")];print(h.hexdigest())' "$1" 2>/dev/null; }
NOW="$(date -u +%Y%m%dT%H%M%SZ)"

# ---------------------------------------------------------------- program name
# Preferred order: cache -> recorded successful import -> live -list.
# (Ghidra 12 rejects a bare `-list`; it must accompany -process.)
PROGRAM=""
if [ -s "$NAME_CACHE" ]; then
  PROGRAM="$(head -1 "$NAME_CACHE")"
fi
if [ -z "$PROGRAM" ] && [ -r "$PROJ_DIR/import.log" ]; then
  PROGRAM="$(sed -n 's|.*REPORT: Save succeeded for: \(\/[A-Za-z0-9._-]*\) .*|\1|p' \
    "$PROJ_DIR/import.log" | tail -1)"
  [ -n "$PROGRAM" ] && printf '%s\n' "$PROGRAM" > "$NAME_CACHE"
fi
if [ -z "$PROGRAM" ]; then
  LIST_LOG="$PROJ_DIR/list.$NOW.log"
  HOME="$TOOLS_ROOT/ghidra-user" "$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJ_DIR" "$PROJ_NAME" -process '*' -list > "$LIST_LOG" 2>&1
  PROGRAM="$(sed -n 's|^ *\(\/[A-Za-z0-9._-]*\)[[:space:]]*$|\1|p' "$LIST_LOG" | head -1)"
  if [ -n "$PROGRAM" ]; then
    printf '%s\n' "$PROGRAM" > "$NAME_CACHE"
  else
    die "cannot discover the imported program name in $PROJ_DIR (see $LIST_LOG)"
  fi
fi

KEY="${RVA:-${VA#0x}}"
KEY="$(printf '%s' "$KEY" | tr -dc '0-9a-fA-F')"
[ -n "$KEY" ] || die "address must be hexadecimal"
[ -n "$OUT" ] || OUT="$OUT_DIR/${KEY}.$NOW.json"
mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"
rm -f "$OUT" 2>/dev/null

# ------------------------------------------------------------------- locking
acquire_lock() {
  local waited=0
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    # Stale lock: the holder died. 600s is far longer than any single query.
    if [ -d "$LOCK_DIR" ] && [ -n "$(find "$LOCK_DIR" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then
      rmdir "$LOCK_DIR" 2>/dev/null
      continue
    fi
    sleep 2; waited=$((waited + 2))
    [ "$waited" -lt 300 ] || { echo "ghidra-query: timed out waiting for the project lock" >&2; return 1; }
  done
  printf '%s pid=%s\n' "$(date -u +%FT%TZ)" "$$" > "$LOCK_DIR/owner" 2>/dev/null
  LOCK_HELD=1
}
LOCK_HELD=0
cleanup() { [ "$LOCK_HELD" = 1 ] && rm -rf "$LOCK_DIR" 2>/dev/null; }
trap cleanup EXIT INT TERM
acquire_lock || exit 3

# ------------------------------------------------------------------- run query
# -process wants the program name as stored in the project, without the leading
# project-root slash reported by import/list output.
PROGRAM_ARG="${PROGRAM#/}"
QLOG="$PROJ_DIR/query.$KEY.$NOW.log"
ARGS=(out="$OUT")
[ -n "$RVA" ] && ARGS+=(rva="$KEY") || ARGS+=(va="$KEY")
ARGS+=(maxInstructions="$MAXI" maxRefs="$MAXR" maxCallers="$MAXCALL" maxCallees="$MAXCALLEE")
ARGS+=(maxPseudoLines="$MAXP")

HOME="$TOOLS_ROOT/ghidra-user" GHIDRA_HEADLESS_MAXMEM="$QUERY_MEM" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$PROJ_DIR" "$PROJ_NAME" \
  -process "$PROGRAM_ARG" -readOnly -noanalysis \
  -scriptPath "$QUERY_SCRIPT_DIR" -postScript Sims2Query.java -- \
  "${ARGS[@]}" > "$QLOG" 2>&1
RUN_RC=$?
[ -s "$OUT" ] || { echo "ghidra-query: script produced no output (rc=$RUN_RC), see $QLOG" >&2
  tail -12 "$QLOG" >&2
  # Java script compile diagnostics land in the Ghidra application log, not stdout.
  APP_LOG="$HOME/.config/ghidra/ghidra_12.2_PUBLIC/application.log"
  if [ -r "$APP_LOG" ]; then
    echo "--- last compile errors from $APP_LOG ---" >&2
    grep -E 'Sims2Query.java:[0-9]+: error|COMPILATION' "$APP_LOG" | tail -12 >&2
  fi
  exit 4; }

# ------------------------------------------------------------- wrap envelope
IMG_SHA="$(sha_of "$SOURCE_IMAGE")"
TOOL_VER="$(sed -n 's/^application\.version=//p' "$GHIDRA_HOME/Ghidra/application.properties" 2>/dev/null | head -1)"
[ -n "$TOOL_VER" ] || TOOL_VER="unknown"
WARN_COUNT=$(grep -c 'WARN ' "$QLOG" 2>/dev/null || true)
ERR_COUNT=$(grep -c 'ERROR' "$QLOG" 2>/dev/null || true)
COMPILE_ERR=0
grep -qi 'unable to compile\|COMPILATION ERROR\|error at' "$QLOG" && COMPILE_ERR=1

ENV_OUT="$OUT.env.json"
"$PY" - "$OUT" "$ENV_OUT" "$KEY" "$RVA" "$VA" "$PROGRAM" "$IMG_SHA" "$TOOL_VER" "$QLOG" \
  "${WARN_COUNT:-0}" "${ERR_COUNT:-0}" "$COMPILE_ERR" "$RUN_RC" "$MAXI" "$MAXR" "$MAXCALL" \
  "$MAXCALLEE" "$MAXP" <<'PYEOF'
import json, sys, datetime
(out, env_out, key, rva, va, program, img, ver, qlog, warns, errs, cerr, rc,
 max_i, max_r, max_c, max_cc, max_p) = sys.argv[1:20]
try:
    core = json.load(open(out))
    parse_err = None
except Exception as exc:  # never lose the raw file, but say so loudly
    core = {"error": "script output was not valid JSON", "raw_first_2000": open(out, errors="replace").read()[:2000]}
    parse_err = str(exc)
env = {
  "schema": "sims2-ghidra-query-envelope/1",
  "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
  "provenance": {
    "sourceImageSha256": img or "unavailable",
    "ghidraVersion": ver,
    "project": "work/ghidra/Sims2Legacy118",
    "program": program,
    "mode": "readOnly",
    "analysisPerformed": False,
    "queryLog": qlog,
    "headlessExitCode": int(rc),
    "outputParseError": parse_err,
  },
  "query": {
    "rva": ("0x" + key) if rva else None,
    "va": va or None,
    "limits": {"instructions": int(max_i), "refs": int(max_r), "callers": int(max_c),
               "callees": int(max_cc), "pseudoLines": int(max_p)},
  },
  "queryLogSignals": {
    "warnLines": int(warns or 0),
    "errorLines": int(errs or 0),
    "scriptCompileError": bool(int(cerr)),
  },
  "interpretationPolicy": [
    "Pseudocode, auto names and decompiler types are hypotheses, never source.",
    "Correctness claims require pinned pcrecomp / Unicorn / reference-state comparison.",
    "The recovered PE keeps a wrapped entry point; Ghidra's entry is not the game entry.",
  ],
  "result": core,
}
open(env_out, "w").write(json.dumps(env, indent=2, sort_keys=False) + "\n")
PYEOF

ENVIDX="$("$PY" -c 'import sys;print(sys.argv[1])' "$ENV_OUT")"
# A result we cannot parse is a FAILURE, never a soft warning: downstream agents
# must not be able to read a malformed query as evidence.
if "$PY" -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get('provenance',{}).get('outputParseError') else 1)" "$ENVIDX"; then
  echo "ghidra-query: FATAL the Ghidra script output was not valid JSON" >&2
  exit 5
fi
if [ "$QUIET" = 1 ]; then
  printf '%s\n' "$ENVIDX"
else
  printf 'query result: %s\n' "$ENVIDX"
  "$PY" -c '
import json,sys
d=json.load(open(sys.argv[1]))
r=d.get("result",{})
f=r.get("function") or {}
print("program  :", r.get("program",{}).get("name"), r.get("program",{}).get("languageId"),
      "functions=" + str(r.get("program",{}).get("functionCount")))
print("query    :", d.get("query",{}).get("rva") or d.get("query",{}).get("va"), "->",
      (f.get("entryVa") if f else None), (f.get("resolution") if f else None))
ad = r.get("addressData")
if ad:
    print("data     :", ad.get("dataType"), "len=" + str(ad.get("length")),
          "value=" + str(ad.get("value"))[:70])
if not f or f.get("resolution") == "address-only":
    refs = (f or {}).get("referencesToAddress") or []
    near = (f or {}).get("nearestPrecedingFunction")
    print("address  : mapped=" + str((f or {}).get("mapped")),
          "executable=" + str((f or {}).get("executable")),
          "refs=" + str(len(refs)),
          "nearest=" + (str(near.get("entryRva")) + " (+" + str(near.get("bytesBeforeTarget"))
                       + " bytes)" if near else "none"))
    for rf in refs[:10]:
        print("   ref from", rf.get("fromRva"), rf.get("type"), rf.get("source"))
    for ins in ((f or {}).get("disassembly") or {}).get("items") or []:
        print("      ", ins.get("rva"), ins.get("text"))
    print("trunc    :", json.dumps(r.get("truncation", {}).get("counts")))
    raise SystemExit(0)
print("function :", f.get("name"), "params=", f.get("parameters"), "sig=", str(f.get("signature"))[:70])
print("extent   :", f.get("disassembly",{}).get("instructionCount"), "instr,",
      f.get("disassembly",{}).get("extentBytes"), "bytes,", f.get("disassembly",{}).get("extentEndVa"))
print("callers  :", f.get("callerTotal"), " callees:", f.get("calleeTotal"),
      " refs:", len(f.get("referencesToEntry") or []))
print("trunc    :", json.dumps(r.get("truncation")))
print("warnings :", d.get("queryLogSignals"), r.get("warnings"))
' "$ENVIDX" 2>&1 || cat "$ENV_OUT"
fi
