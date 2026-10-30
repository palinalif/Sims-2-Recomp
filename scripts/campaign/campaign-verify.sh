#!/bin/sh
# Independent verification of the repository between campaign runs.
#
# Why this exists. A Ralph run reports its own progress, and run 3 showed that
# self-report is not evidence: every iteration reported progress while 25 of them
# changed no code at all. Before a campaign director chains another run it needs a
# check that does not trust the workers. This script is that check. It builds from
# scratch, runs every suite, and confirms the gates and protections that must never
# move. It is read-only with respect to tracked files and never talks to the loop.
#
# Usage:
#   scripts/campaign/campaign-verify.sh [--baseline <rev>] [--build-dir <path>]
#                                       [--tests-dir tests] [--quick]
#
#   --baseline  revision to diff protected paths against (default HEAD~0 -> skipped)
#   --build-dir scratch build directory (default work/campaign-verify-build)
#   --quick     skip the CMake/Ninja build and run only the Python suite + checks
#
# Output: exactly ONE JSON object on stdout (the director parses it), progress
# lines on stderr. Exit codes:
#   0 everything passed
#   3 verification failed (build, tests, or a protection check)
#   4 integrity violation (acceptance gate touched, promise claimed, tests deleted)
#   5 environment problem (toolchain missing, build could not be configured)

set -u

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT" || { echo '{"error":"cannot enter repo root"}'; exit 5; }

BASELINE=""
BUILD_DIR="${CAMPAIGN_VERIFY_BUILD_DIR:-work/campaign-verify-build}"
TESTS_DIR="tests"
QUICK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --baseline) BASELINE="$2"; shift 2 ;;
    --build-dir) BUILD_DIR="$2"; shift 2 ;;
    --tests-dir) TESTS_DIR="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    *) echo "campaign-verify: unknown argument: $1" >&2; exit 5 ;;
  esac
done

# shellcheck disable=SC1091
. scripts/campaign/worker-env.sh >/dev/null 2>&1 || true
# NOTE: this repository lives under a path containing spaces and the vendored
# interpreter is inside it, so every interpreter invocation must be quoted. An
# unquoted $PY here ran "/workspace/Sims" and printed no JSON at all.
PY=$(command -v python3 || true)
[ -n "$PY" ] || { echo '{"error":"python3 missing - source scripts/campaign/worker-env.sh"}' ; exit 5; }

emit() {   # emit <json> <exit>
  printf '%s\n' "$1"
  exit "$2"
}

BUILD_OK=false; BUILD_RAN=false; BUILD_DETAIL="skipped"
CTEST_TOTAL=0; CTEST_FAILED=-1
PY_RAN=0; PY_OK=false; PY_DETAIL="skipped"
ACCEPT_EXIT=-1
TESTS_MD=0; TESTS_DEL=0; TESTS_GONE=0; TESTS_MUTED=0
ACCEPT_TOUCHED=false; PROMISE_CLAIMED=false; BRANCH=""; HEAD_SHA=""
DIRTY_TRACKED=0; NOTES=""
STATUS=0

note() { NOTES="$NOTES$1; "; printf 'verify: %s\n' "$1" >&2; }

HEAD_SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
[ -n "$HEAD_SHA" ] || emit '{"error":"not a git checkout"}' 5

# ---------------------------------------------------------------- protections
# These four checks are the ones a motivated worker could quietly break. They are
# checked before anything expensive so an integrity violation is reported fast.
if [ -n "$BASELINE" ]; then
  # Modification is not guilt. A campaign that extends the differential harnesses its
  # own earlier runs added modifies test files on nearly every run, and gating on that
  # ended run 2 of recomp-benchmark-20261023 over +1,000/-2 lines of NEW coverage. What
  # a motivated worker CAN do quietly is make coverage smaller or quieter, so the gate
  # looks for exactly those three moves: a test file deleted, a test function removed, a
  # skip/xfail marker introduced. Plain modification is reported, not punished.
  TESTS_MD=$(git diff --name-status --diff-filter=MD "$BASELINE..HEAD" -- "$TESTS_DIR" testing 2>/dev/null | grep -c . || true)
  TESTS_DEL=$(git diff --name-status --diff-filter=D "$BASELINE..HEAD" -- "$TESTS_DIR" testing 2>/dev/null | grep -c . || true)
  TESTS_GONE=$(git diff "$BASELINE..HEAD" -- "$TESTS_DIR" testing 2>/dev/null | grep -cE '^- *(async )?def test_' || true)
  TESTS_MUTED=$(git diff "$BASELINE..HEAD" -- "$TESTS_DIR" testing 2>/dev/null | grep -cE '^[+][[:space:]]*@([A-Za-z_]+\.)?(skip|skipIf|skipUnless|expectedFailure)' || true)
  if git diff --name-only "$BASELINE..HEAD" -- scripts/phase1-acceptance.sh 2>/dev/null | grep -q .; then
    ACCEPT_TOUCHED=true
  fi
  note "protection: since $BASELINE -> test files deleted=$TESTS_DEL modified=$TESTS_MD, test functions removed=$TESTS_GONE, skip/xfail markers added=$TESTS_MUTED, acceptance touched = $ACCEPT_TOUCHED"
  if [ "$TESTS_DEL" -gt 0 ] || [ "$TESTS_GONE" -gt 0 ] || [ "$TESTS_MUTED" -gt 0 ]; then
    git diff --name-status --diff-filter=D "$BASELINE..HEAD" -- "$TESTS_DIR" testing 2>/dev/null | head -5 | sed 's/^/  | deleted: /' >&2
    git diff "$BASELINE..HEAD" -- "$TESTS_DIR" testing 2>/dev/null \
      | grep -E '^- *(async )?def test_|^[+][[:space:]]*@([A-Za-z_]+\.)?(skip|skipIf|skipUnless|expectedFailure)' \
      | head -8 | sed 's/^/  | /' >&2
  fi
fi

# The completion promise must appear ONLY as the gate's own sentinel string, never
# as a claim of success in a report.
if git grep -l 'TS2_ANDROID_PHASE1_VERIFIED' HEAD -- 'tasks/**/PHASE1_REPORT.md' 'PHASE1_REPORT.md' 2>/dev/null | grep -q .; then
  if grep -qs 'TS2_ANDROID_PHASE1_VERIFIED' tasks/android-phase1/PHASE1_REPORT.md 2>/dev/null &&
     ! grep -qs 'not emitted\|never emitted\|unreachable' tasks/android-phase1/PHASE1_REPORT.md 2>/dev/null; then
    PROMISE_CLAIMED=true
  fi
fi

DIRTY_TRACKED=$(git status --porcelain 2>/dev/null | grep -vc '^??' || true)
DIRTY_TRACKED=${DIRTY_TRACKED:-0}

# The gate must fail closed with EX_CONFIG (78) until a trusted validator exists.
# Its exit code is recorded, never influenced: this script never sets the sentinel.
sh scripts/phase1-acceptance.sh >/dev/null 2>&1
ACCEPT_EXIT=$?
note "acceptance gate exit=$ACCEPT_EXIT (78 = fail-closed, which is the required behaviour)"

if [ "$TESTS_DEL" -gt 0 ] || [ "$TESTS_GONE" -gt 0 ] || [ "$TESTS_MUTED" -gt 0 ] ||
   [ "$ACCEPT_TOUCHED" = true ] || [ "$PROMISE_CLAIMED" = true ]; then
  "$PY" - "$ACCEPT_TOUCHED" "$PROMISE_CLAIMED" "$TESTS_MD" "$ACCEPT_EXIT" "$HEAD_SHA" "$BRANCH" "$DIRTY_TRACKED" \
        "$TESTS_DEL" "$TESTS_GONE" "$TESTS_MUTED" <<'PY'
import json,sys
touched,claimed,tests_md,accept,sha,branch,dirty,tests_del,tests_gone,tests_muted=sys.argv[1:11]
print(json.dumps({
 "build_ok": None, "build_detail": "not reached (integrity check first)",
 "ctest_total": 0, "ctest_failed": -1,
 "python_ran": 0, "python_ok": False, "python_detail": "not reached",
 "acceptance_exit": int(accept),
 "integrity": {
   # integrity_violation is the AUTHORITATIVE answer and the only field a decision-maker
   # should read. tests_modified_or_deleted is kept for report continuity and is
   # INFORMATIONAL: this campaign edits its own test harnesses on every healthy run.
   "integrity_violation": True,
   "tests_modified_or_deleted": int(tests_md),
   "test_files_deleted": int(tests_del),
   "test_functions_removed": int(tests_gone),
   "skip_markers_added": int(tests_muted),
   "acceptance_script_modified": touched == "true",
   "completion_promise_claimed": claimed == "true",
   "dirty_tracked_files": int(dirty),
   "head": sha, "branch": branch,
 },
 "notes": "INTEGRITY VIOLATION", "verdict": "integrity-violation",
}))
PY
  exit 4
fi

# ---------------------------------------------------------------- build + tests
if [ "$QUICK" -eq 0 ]; then
  BUILD_RAN=true
  TC="${TS2_HOST_TOOLCHAIN:-$(cd "$REPO_ROOT/.." && pwd)/.local-tools/toolchain/bin}"
  command -v cmake >/dev/null 2>&1 || { emit '{"error":"cmake missing (source scripts/campaign/worker-env.sh)"}' 5; }
  mkdir -p "$(dirname "$BUILD_DIR")"
  rm -rf "$BUILD_DIR"
  note "configuring clean build in $BUILD_DIR"
  if CMAKE_ASSEMBLY_VERIFY=OFF LTO_JOBS=1 LDFLAGS="-Wl,--undefined-version" \
     cmake -S . -B "$BUILD_DIR" -G Ninja \
       -D CMAKE_C_COMPILER="$TC/zig-cc" -D CMAKE_CXX_COMPILER="$TC/zig-cxx" \
       -D CMAKE_AR="$TC/zig-ar" -D CMAKE_RANLIB="$TC/zig-ranlib" \
       -D CMAKE_MAKE_PROGRAM="$TC/ninja" >"$BUILD_DIR.configure.log" 2>&1 && \
     cmake --build "$BUILD_DIR" -j4 >>"$BUILD_DIR.configure.log" 2>&1; then
    BUILD_OK=true
    BUILD_DETAIL="ok"
  else
    BUILD_OK=false; BUILD_DETAIL="see $BUILD_DIR.configure.log"
    STATUS=3; note "build FAILED ($BUILD_DETAIL)"
  fi
  if [ "$BUILD_OK" = true ]; then
    CTEST_OUT="$BUILD_DIR/ctest.log"
    ctest --test-dir "$BUILD_DIR" --output-on-failure >"$CTEST_OUT" 2>&1 || true
    CTEST_TOTAL=$(grep -Eo 'Total Tests:[[:space:]]*[0-9]+' "$CTEST_OUT" | grep -Eo '[0-9]+' | head -1)
    [ -n "$CTEST_TOTAL" ] || CTEST_TOTAL=$(grep -Ec 'Test +#[0-9]+:.*\.\.\.+ +Passed' "$CTEST_OUT" || true)
    CTEST_FAILED=$(grep -Eo 'Tests Failed:[[:space:]]*[0-9]+' "$CTEST_OUT" | grep -Eo '[0-9]+' | head -1)
    [ -n "$CTEST_FAILED" ] || CTEST_FAILED=$(grep -Ec 'Test +#[0-9]+:.*\.\.\.+ +Failed' "$CTEST_OUT" || true)
    CTEST_TOTAL=${CTEST_TOTAL:-0}; CTEST_FAILED=${CTEST_FAILED:-0}
    [ "$CTEST_FAILED" -gt 0 ] && { STATUS=3; note "ctest FAILED: $CTEST_FAILED of $CTEST_TOTAL"; }
    note "ctest: $CTEST_FAILED failed of $CTEST_TOTAL"
  fi
fi

note "running Python suite in $TESTS_DIR"
PY_OUT=$(mktemp)
# Two suites (guest dispatch smoke, guest loading smoke) exec a host binary and
# deliberately FAIL rather than skip when it is absent. If we do not tell them where
# this clean build put those executables they fall back to build/host, which in a
# long-lived worktree holds binaries from an older build - so a green run could
# validate artefacts this build never produced, and a fresh worktree with no build/
# directory reports a false "test-regression" for a suite that merely cannot find
# its subject. Point them at the build we just made.
SMOKE_ENV=0
if [ "$BUILD_RAN" = true ] && [ "$BUILD_OK" = true ]; then
  ABS_BUILD=$(cd "$BUILD_DIR" && pwd)
  SMOKE_ENV=1
  for exe in ts2_guest_dispatch_smoke ts2_guest_loading_smoke ts2_dbpf_probe; do
    [ -x "$BUILD_DIR/$exe" ] || { note "WARN $exe not produced by this build; suite will fail by design"; }
  done
fi
[ "$BUILD_RAN" = true ] || note "quick mode: no fresh build; smoke suites use whatever build/host already holds (recorded as not-measured build evidence)"
if [ "$SMOKE_ENV" = 1 ]; then
  # These must be quoted prefix assignments, never a string of `env VAR=value` pairs:
  # this repository's path contains spaces, so the old `env $SMOKE_ENV python3 …` word-
  # split into `env TS2_GUEST_DISPATCH_SMOKE=/workspace/Sims 2 Decomp … python3`, `env`
  # tried to execute the word `2`, and the suite died with 127 - which was then filed
  # as a test regression. Assigning in the shell keeps the path intact.
  TS2_GUEST_DISPATCH_SMOKE="$ABS_BUILD/ts2_guest_dispatch_smoke" \
  TS2_GUEST_LOADING_SMOKE="$ABS_BUILD/ts2_guest_loading_smoke" \
  TS2_DBPF_PROBE="$ABS_BUILD/ts2_dbpf_probe" \
    "$PY" -m unittest discover -s "$TESTS_DIR" -p 'test_*.py' >"$PY_OUT" 2>&1
else
  "$PY" -m unittest discover -s "$TESTS_DIR" -p 'test_*.py' >"$PY_OUT" 2>&1
fi
PY_RC=$?
PY_RAN=$(grep -Eo '^Ran [0-9]+ tests' "$PY_OUT" | grep -Eo '[0-9]+' | head -1)
PY_RAN=${PY_RAN:-0}
if grep -q 'OK' "$PY_OUT" && [ "$PY_RC" -eq 0 ]; then PY_OK=true; PY_DETAIL="ok"; elif [ "$PY_RC" = 126 ] || [ "$PY_RC" = 127 ]; then
  # 126/127 mean the interpreter could not be executed at all. That is the harness
  # failing to run the suite, not the suite failing: it must never be classified as a
  # test regression, because the director's response to two regressions is to halt the
  # campaign for a human over what is really a PATH problem. Run 1 of
  # recomp-benchmark-20261023 hit exactly this (bare `python3` under `env`).
  PY_OK=false; PY_DETAIL="interpreter-unavailable (exit $PY_RC)"; STATUS=4
  note "python suite COULD NOT BE EXECUTED (exit $PY_RC): verification unavailable, not a test regression"
  head -3 "$PY_OUT" | sed 's/^/  | /'
elif [ "$PY_RAN" = 0 ]; then
  # Nothing ran but the interpreter worked: usually a collection/import error, which IS
  # a real failure — keep it a regression, but say why so nobody reads it as "0 tests
  # needed".
  PY_OK=false; PY_DETAIL="no tests collected (exit $PY_RC)"; STATUS=3
  note "python suite collected 0 tests (exit $PY_RC) - treated as regression"
  head -5 "$PY_OUT" | sed 's/^/  | /'
else
  PY_OK=false; PY_DETAIL="exit $PY_RC"; STATUS=3; note "python suite FAILED (exit $PY_RC)"
  grep -E '^(FAIL|ERROR): ' "$PY_OUT" | head -10 | sed 's/^/  | /'
fi
# unittest prints one summary line such as "Ran 203 tests in 3.6s (skipped=2)" plus
# per-test notes; counting lines that contain the word is not the number of skipped
# tests, which is what the director and report need.
SKIPS=$(grep -Eo 'skipped=[0-9]+' "$PY_OUT" | grep -Eo '[0-9]+' | head -1)
[ -n "$SKIPS" ] || SKIPS=$(grep -Ec '\.\.\. skipped' "$PY_OUT" || true)
SKIPS=${SKIPS:-0}
note "python: ran=$PY_RAN ok=$PY_OK skips=$SKIPS"

"$PY" - "$BUILD_RAN" "$BUILD_OK" "$BUILD_DETAIL" "$CTEST_TOTAL" "$CTEST_FAILED" "$PY_RAN" "$PY_OK" "$PY_DETAIL" \
      "$ACCEPT_EXIT" "$HEAD_SHA" "$BRANCH" "$TESTS_MD" "$ACCEPT_TOUCHED" "$PROMISE_CLAIMED" "$DIRTY_TRACKED" "$SKIPS" \
      "$TESTS_DEL" "$TESTS_GONE" "$TESTS_MUTED" <<'PY'
import json, sys
b_ran, b_ok, b_det, ct, cf, pr, p_ok, p_det, accept, sha, branch, tmd, at, pc, dirty, skips, tdel, tgone, tmuted = sys.argv[1:20]
b_ran = b_ran == "true"; b_ok = b_ok == "true"; p_ok = p_ok == "true"
# A --quick run has no build evidence at all; that is "not measured", never a
# regression. Reporting it as one made a perfectly healthy tree look broken.
failed = (b_ran and not b_ok) or (not p_ok) or int(cf or 0) > 0
# "Could not execute the suite" is not "the suite failed". Classifying a harness
# problem as a regression halts the campaign for a human over a PATH bug, so it is
# reported as unknown (verification unavailable, which the director already counts and
# bounds separately) with the reason in notes.
env_problem = p_det.startswith("interpreter-unavailable") or p_det == "not reached"
verdict = "pass" if not failed else ("unknown" if env_problem else "test-regression")
print(json.dumps({
    "build_ok": (b_ok if b_ran else None), "build_detail": b_det,
    "ctest_total": int(ct or 0), "ctest_failed": int(cf if cf != "" else -1),
    "python_ran": int(pr or 0), "python_ok": p_ok, "python_detail": p_det,
    "python_skips": int(skips or 0),
    "acceptance_exit": int(accept),
    "integrity": {
        # Authoritative decision field; see the note in the early-exit block above.
        "integrity_violation": (int(tdel or 0) > 0 or int(tgone or 0) > 0
                                or int(tmuted or 0) > 0 or at == "true" or pc == "true"),
        "tests_modified_or_deleted": int(tmd or 0),
        "test_files_deleted": int(tdel or 0),
        "test_functions_removed": int(tgone or 0),
        "skip_markers_added": int(tmuted or 0),
        "acceptance_script_modified": at == "true",
        "completion_promise_claimed": pc == "true",
        "dirty_tracked_files": int(dirty or 0),
        "head": sha, "branch": branch,
    },
    "notes": (p_det if env_problem else None),
    "verdict": verdict,
}))
PY
[ "$STATUS" -eq 0 ] && exit 0
[ "$STATUS" -eq 3 ] && exit 3
exit 5
