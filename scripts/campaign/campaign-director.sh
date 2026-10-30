#!/bin/sh
# Multi-run campaign director: chains bounded Ralph runs inside one overall budget.
#
# What this adds. budgeted-supervisor.sh caps ONE Ralph run (iterations, wall
# clock, no-progress streak). Ralph's per-run ceiling is 50 iterations, so a run
# that reaches it leaves the remaining hours idle unless something resumes it.
# The director is that something: it starts a run through the existing supervisor,
# waits for it to settle, INDEPENDENTLY verifies the result, checkpoints state, and
# starts another run only if the evidence says meaningful work remains.
#
# It deliberately does not re-implement Ralph. Per-run enforcement stays in
# budgeted-supervisor.sh; per-run limits stay in RALPH.md. The director only adds
# identity, budgets across runs, evidence, and stop decisions.
#
# Usage:
#   scripts/campaign/campaign-director.sh --task ./tasks/android-phase1 \
#       --campaign <id> --yes [options]          # start or resume a campaign
#   scripts/campaign/campaign-director.sh --campaign <id> --status
#   scripts/campaign/campaign-director.sh --campaign <id> --stop [--reason TEXT] [--immediate]
#   scripts/campaign/campaign-director.sh --campaign <id> --report
#
# Options (start mode):
#   --max-wall-minutes 720   overall budget for ALL runs of this campaign (12 h)
#   --max-runs 8             maximum consecutive runs
#   --run-iterations 50      per-run iteration cap (hard ceiling 50 = Ralph's bound)
#   --run-minutes 120        per-run wall-clock cap
#   --poll 30                director poll interval (heartbeat, stop checks)
#   --no-progress-streak 3   forwarded to the supervisor (per run)
#   --min-code-lines 150     engineering-progress threshold (committed code lines)
#   --max-stagnant-runs 2    consecutive runs without engineering progress -> stop
#   --state-root work/campaigns
#   --directive-writeback    allow committing a "Director directive" block into the
#                            task RALPH.md at a run boundary (OFF by default: the
#                            director never writes to the worktree unless asked)
#
# Guarantees:
#   * never runs two loops or two directors for one task (exclusive lock + guards)
#   * never kills a worker; stops are requested through the supervisor boundary
#   * never checks out, resets, stashes or amends; commits only with --directive-writeback
#   * survives a director restart: an open run is adopted, not duplicated
#
# Exit codes:
#   0 campaign ended normally (budget-runs, budget-wall or mission-complete)
#   3 campaign stopped early (stagnation, regression, manual stop)
#   4 integrity violation (a protection moved; human review required)
#   5 unsafe/infrastructure condition (could not observe or verify the loop)
#   6 refused to start (another director owns the campaign, or a foreign loop is live)

set -u

# Started detached (`setsid nohup … &`) this script is run by /bin/sh with a bare
# environment: no vendored git, no python3. worker-env.sh is bash-only (it reads
# ${BASH_SOURCE[0]}), so sourcing it from here fails silently and the director then
# half-initialises: the state writer dies on `git`, an empty start timestamp makes
# the wall-clock budget fire instantly, and every later status/read/report call
# throws. Half-initialised campaign state is worse than a refusal, so re-exec under
# bash exactly once (marker prevents recursion) and load the real toolchain.
if [ -z "${TS2_DIRECTOR_UNDER_BASH:-}" ]; then
  TS2_DIRECTOR_UNDER_BASH=1
  export TS2_DIRECTOR_UNDER_BASH
  exec bash "$0" "$@"
fi

SCRIPT_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# Parallel coordinator slots launch this script (from the MAIN checkout, always
# current code) with cwd = the slot's worktree. Honour the launch cwd when it
# is itself a checkout; otherwise bind to the script's own checkout as before.
if [ -e .git ] && [ -d ./tasks ]; then
  REPO_ROOT=$(pwd)
else
  REPO_ROOT="$SCRIPT_ROOT"
fi
cd "$REPO_ROOT" || { echo "director: cannot enter $REPO_ROOT" >&2; exit 5; }

# This repository lives under a path containing spaces: quote every expansion, and
# resolve the interpreter once. An unquoted path here executes "/workspace/Sims".
PY=$(command -v python3 || true)
if [ -z "$PY" ]; then
  # shellcheck disable=SC1091
  . scripts/campaign/worker-env.sh >/dev/null 2>&1 || true
  PY=$(command -v python3 || true)
fi
if [ -z "$PY" ]; then
  # Last-resort POSIX resolution for callers that got here without worker-env (the
  # source above only works under bash). The same interpreter the operator env
  # exports as PY_HOME; always quoted by callers — this path contains spaces.
  for TS2_PY_CAND in "${TS2_PY:-}" "${PY_HOME:-}/bin/python3" "$REPO_ROOT/../.local-tools/python/bin/python3"; do
    [ -n "$TS2_PY_CAND" ] && [ -x "$TS2_PY_CAND" ] && { PY="$TS2_PY_CAND"; break; }
  done
  unset TS2_PY_CAND
fi
[ -n "$PY" ] || { echo "director: python3 required (source scripts/campaign/worker-env.sh)" >&2; exit 5; }
# git is not optional: branch identity, progress measurement and verification all
# shell out to it. Fail before writing any state rather than after.
command -v git >/dev/null 2>&1 || {
  echo "director: git required on PATH (source scripts/campaign/worker-env.sh under bash)" >&2
  exit 5
}

TASK=""; CAMPAIGN=""; MODE="start"; YES=0
MAX_WALL=720; MAX_RUNS=8; RUN_ITER=50; RUN_MINUTES=120; POLL=30
NO_PROGRESS_STREAK=3; MIN_CODE_LINES=150; MAX_STAGNANT=2
STATE_ROOT="work/campaigns"; WRITEBACK=0
STOP_REASON_TEXT="operator stop request"
IMMEDIATE=0; FORCE_TAKEOVER=0
STOP_REASON=""
DECISION_DETAIL=""
STATE_CREATED_BY_ME=0

while [ $# -gt 0 ]; do
  case "$1" in
    --task) TASK="$2"; shift 2 ;;
    --campaign) CAMPAIGN="$2"; shift 2 ;;
    --status) MODE="status"; shift ;;
    --stop) MODE="stop"; shift ;;
    --report) MODE="report"; shift ;;
    --yes) YES=1; shift ;;
    --max-wall-minutes) MAX_WALL="$2"; shift 2 ;;
    --max-runs) MAX_RUNS="$2"; shift 2 ;;
    --run-iterations) RUN_ITER="$2"; shift 2 ;;
    --run-minutes) RUN_MINUTES="$2"; shift 2 ;;
    --poll) POLL="$2"; shift 2 ;;
    --no-progress-streak) NO_PROGRESS_STREAK="$2"; shift 2 ;;
    --min-code-lines) MIN_CODE_LINES="$2"; shift 2 ;;
    --max-stagnant-runs) MAX_STAGNANT="$2"; shift 2 ;;
    --state-root) STATE_ROOT="$2"; shift 2 ;;
    --directive-writeback) WRITEBACK=1; shift ;;
    --reason) STOP_REASON_TEXT="$2"; shift 2 ;;
    --immediate) IMMEDIATE=1; shift ;;
    --force-takeover) FORCE_TAKEOVER=1; shift ;;
    -h|--help) sed -n '1,80p' "$0"; exit 0 ;;
    *) echo "director: unknown argument: $1" >&2; exit 64 ;;
  esac
done

[ -n "$CAMPAIGN" ] || { echo "director: --campaign <id> is required" >&2; exit 64; }
case "$CAMPAIGN" in
  *[!A-Za-z0-9._-]*) echo "director: --campaign may only use [A-Za-z0-9._-]" >&2; exit 64 ;;
esac

STATE="$STATE_ROOT/$CAMPAIGN"
LOCK="$STATE/director.lock"
CJSON="$STATE/campaign.json"
SUPERVISOR="scripts/campaign/budgeted-supervisor.sh"
VERIFIER="scripts/campaign/campaign-verify.sh"
PROGRESS="scripts/campaign/campaign-progress.py"
REPORTER="scripts/campaign/campaign-report.py"
SESSIONS="work/pi-sessions"
LOCK_TTL=$(( POLL * 4 + 120 ))
TERMINAL_LIST="complete max-iterations no-progress-exhaustion stopped timeout error cancelled"

say() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$STATE/console.log" 2>/dev/null || true; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
epoch() { date +%s; }

# ---------------------------------------------------------------- status mode
if [ "$MODE" = "status" ]; then
  [ -f "$CJSON" ] || { echo "director: no campaign '$CAMPAIGN' at $STATE" >&2; exit 5; }
  "$PY" - "$STATE" <<'PY'
import json, os, sys, time, glob
state = sys.argv[1]
camp = json.load(open(os.path.join(state, "campaign.json")))
lock = os.path.join(state, "director.lock")
own = None
if os.path.isdir(lock):
    try:
        own = json.load(open(os.path.join(lock, "owner.json")))
        hb = os.path.join(lock, "heartbeat")
        own["heartbeat_age_s"] = int(time.time() - os.path.getmtime(hb)) if os.path.exists(hb) else None
        try:
            os.kill(int(own["pid"]), 0); own["alive"] = True
        except OSError:
            own["alive"] = False
    except Exception as exc:
        own = {"error": str(exc)}
runs = []
for path in sorted(glob.glob(os.path.join(state, "runs", "*", "run.json")), key=lambda p: int(p.split("/")[-2])):
    runs.append(json.load(open(path)))
openr = []
for path in sorted(glob.glob(os.path.join(state, "runs", "*", "open.json"))):
    try: openr.append(json.load(open(path)))
    except Exception: pass
out = dict(camp); out["owner"] = own; out["runs"] = runs; out["open_runs"] = openr
print(json.dumps(out, indent=2))
PY
  exit 0
fi

# ---------------------------------------------------------------- stop mode
if [ "$MODE" = "stop" ]; then
  [ -f "$CJSON" ] || { echo "director: no campaign '$CAMPAIGN'" >&2; exit 5; }
  mkdir -p "$STATE"
  printf '%s %s\n' "$(now_utc)" "$STOP_REASON_TEXT" > "$STATE/STOP"
  echo "director: stop requested for $CAMPAIGN ($STOP_REASON_TEXT)$([ "$IMMEDIATE" -eq 1 ] && echo ' - immediate')"
  if [ "$IMMEDIATE" -eq 1 ]; then
    TASK_STOP=$("$PY" -c "import json;print(json.load(open('$CJSON'))['task'])")
    # Same mechanism the supervisor uses: the loop stops at the iteration boundary.
    # We never kill the worker, because that strands the runner registry for 30 min.
    pi --approve --model "${TS2_WORKER_MODEL:-flashnext/swift-1.5-iq3_xxs}" --session-dir "$SESSIONS" -p "/ralph-stop $TASK_STOP" </dev/null >"$STATE/stop-request.log" 2>&1 \
      && echo "director: /ralph-stop accepted (takes effect at the iteration boundary)" \
      || echo "director: /ralph-stop exited non-zero; see $STATE/stop-request.log"
  fi
  exit 0
fi

# ---------------------------------------------------------------- report mode
if [ "$MODE" = "report" ]; then
  exec "$PY" "$REPORTER" --state "$STATE"
fi

# ---------------------------------------------------------------- start mode
[ -n "$TASK" ] || { echo "director: --task is required to start a campaign" >&2; exit 64; }
TASK_DIR=$(cd "$TASK" 2>/dev/null && pwd) || { echo "director: no such task dir: $TASK" >&2; exit 64; }
[ -f "$TASK_DIR/RALPH.md" ] || { echo "director: $TASK_DIR has no RALPH.md" >&2; exit 64; }
[ "$YES" -eq 1 ] || { echo "director: refusing to spawn workers without --yes" >&2; exit 64; }

# Ralph's supported per-run bound. The director may lower it, never raise it.
[ "$RUN_ITER" -gt 50 ] && { say "NOTE run-iterations $RUN_ITER exceeds Ralph's 50 cap; clamping"; RUN_ITER=50; }
[ "$RUN_ITER" -lt 1 ] && RUN_ITER=1

[ -d "$STATE" ] || STATE_CREATED_BY_ME=1
mkdir -p "$STATE/runs" "$SESSIONS" work/campaign-logs

# ---------------------------------------------------- exclusive ownership lock
pid_alive() { # kill -0 alone is not liveness: this container never reaps, so a
  # SIGKILLed director stays a zombie and would block takeover forever.
  [ -n "${1:-}" ] || return 1
  kill -0 "$1" 2>/dev/null || return 1
  if [ -r "/proc/$1/stat" ]; then
    # field 3 is the process state; Z means already dead, waiting to be reaped
    awk '{ exit ($3 == "Z") ? 1 : 0 }' "/proc/$1/stat" 2>/dev/null || return 1
  fi
  return 0
}

acquire_lock() {
  if [ -d "$LOCK" ]; then
    OWN_PID=$("$PY" - "$LOCK" <<'PY' 2>/dev/null || true
import json, os, sys
try:
    print(json.load(open(os.path.join(sys.argv[1], "owner.json")))["pid"])
except Exception:
    print("")
PY
)
    HB_AGE=999999
    [ -f "$LOCK/heartbeat" ] && HB_AGE=$(( $(epoch) - $(stat -c %Y "$LOCK/heartbeat" 2>/dev/null || echo 0) ))
    ALIVE=0
    pid_alive "$OWN_PID" && ALIVE=1
    # A live owner always wins, whatever the heartbeat says. Taking over a running
    # campaign means two directors launching workers for one task. The first draft
    # of this file recorded the PID of a short-lived python helper instead of the
    # director's own, so every lock looked stale within seconds and a second
    # director happily hijacked a live campaign. Never infer ownership from a
    # process that is not the director itself.
    if [ "$ALIVE" -eq 1 ] && [ "$FORCE_TAKEOVER" -eq 0 ]; then
      say "REFUSE campaign $CAMPAIGN is owned by live pid $OWN_PID (heartbeat ${HB_AGE}s). Use --force-takeover only if that director is wedged."
      exit 6
    fi
    if [ "$ALIVE" -eq 1 ]; then
      say "FORCE TAKEOVER of pid $OWN_PID as requested; that director is still running and may still act. Verify it is wedged."
    else
      say "STALE LOCK pid=${OWN_PID:-?} not alive, heartbeat ${HB_AGE}s old - taking over (recovery)"
    fi
    mv "$LOCK" "$STATE/director.lock.stale-$(date -u +%s)" 2>/dev/null || true
    cp "$STATE/director.lock.stale-"*/owner.json "$STATE/previous-owner.json" 2>/dev/null || true
  fi
  mkdir "$LOCK" || { say "REFUSE could not create lock (race with another director?)"; exit 6; }
  printf '%s %s %s %s\n' "$$" "$CAMPAIGN" "$TASK" "$(now_utc)" > "$LOCK/owner.txt"
  # $$ is the director's own pid. It is passed in rather than discovered inside
  # python, whose pid belongs to a helper process that exits immediately.
  "$PY" - "$LOCK" "$CAMPAIGN" "$TASK" "$$" <<'PY'
import json, os, socket, sys, datetime
lock, campaign, task, pid = sys.argv[1:5]
json.dump({"pid": int(pid), "ppid": os.getppid(), "campaign": campaign, "task": task,
           "started_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "host": socket.gethostname()},
          open(os.path.join(lock, "owner.json"), "w"), indent=1)
PY
  : > "$LOCK/heartbeat"
}

heartbeat() { : > "$LOCK/heartbeat" 2>/dev/null || true; }

release_lock() {
  [ -n "$1" ] && printf '%s\n' "$1" > "$STATE/FINAL-REASON" 2>/dev/null
  rm -rf "$LOCK" 2>/dev/null
}

on_exit() {
  RC=$?
  if [ -d "$LOCK" ] && grep -q "^$$ " "$LOCK/owner.txt" 2>/dev/null; then
    printf 'exit-code %s\n' "$RC" > "$STATE/last-exit-code"
    rm -rf "$LOCK" 2>/dev/null
  fi
}
trap 'on_exit' EXIT

# ------------------------------------------------------------- duplicate guards
prelaunch_guard() {
  if [ "${CAMPAIGN_ALLOW_PARALLEL:-0}" = 1 ]; then
    say "PARALLEL slot: skipping same-task director/supervisor guards (worktree-isolated; coordinator owns all slots)"
  else
  # (a) another director holding a DIFFERENT campaign on the SAME task
  for cj in "$STATE_ROOT"/*/campaign.json; do
    [ -f "$cj" ] || continue
    case "$cj" in "$CJSON") continue ;; esac
    OTHER_TASK=$("$PY" -c "import json;print(json.load(open('$cj')).get('task',''))" 2>/dev/null || echo "")
    OTHER_ID=$(basename "$(dirname "$cj")")
    [ "$OTHER_TASK" = "$TASK" ] || continue
    OL_LOCK="$STATE_ROOT/$OTHER_ID/director.lock"
    [ -d "$OL_LOCK" ] || continue
    OL_PID=$("$PY" -c "import json;print(json.load(open('$OL_LOCK/owner.json'))['pid'])" 2>/dev/null || echo "")
    OL_AGE=999999; [ -f "$OL_LOCK/heartbeat" ] && OL_AGE=$(( $(epoch) - $(stat -c %Y "$OL_LOCK/heartbeat") ))
    if [ -n "$OL_PID" ] && kill -0 "$OL_PID" 2>/dev/null && [ "$OL_AGE" -lt "$LOCK_TTL" ]; then
      DECISION_DETAIL="campaign $OTHER_ID (pid $OL_PID) already directs this task"
      say "REFUSE campaign $OTHER_ID (pid $OL_PID) already directs task $TASK"
      return 6
    fi
  done
  # (b) a supervisor running for this task that is not our own child
  SELF=$$
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$SELF" ] && continue
    CMD=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)
    case "$CMD" in
      *budgeted-supervisor.sh*"$TASK"*) DECISION_DETAIL="supervisor pid $pid is already supervising this task"
        say "REFUSE supervisor pid $pid is supervising $TASK (would create duplicate workers)"; return 6 ;;
    esac
  done
  fi
  # (c) a live loop that we are not adopting. If we get here with a running loop
  # and no open run record, the director has no idea who owns it - starting a run
  # now would create a second worker on the same task.
  ST=$(loop_field status)
  if ! is_terminal "$ST"; then
    DECISION_DETAIL="task has a live loop (status=$ST) not owned by this campaign"
    say "REFUSE task $TASK has a live loop (status=$ST) that this director is not adopting. Resume with the campaign whose state dir holds the open run record, or stop the loop with /ralph-stop."
    return 6
  fi
  return 0
}

is_terminal() { # also true when the task has no loop state at all (fresh task)
  case "$1" in none|"") return 0 ;; esac
  for T in $TERMINAL_LIST; do [ "$1" = "$T" ] && return 0; done
  return 1
}

loop_field() {
  ST="$TASK_DIR/.ralph-runner/status.json"
  [ -f "$ST" ] || { printf 'none\n'; return; }
  "$PY" - "$ST" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("none"); raise SystemExit
key = {"status": "status", "token": "loopToken", "iter": "currentIteration"}[sys.argv[2]]
v = d.get(key, "none" if key != "currentIteration" else 0)
print(str(v)[:8] if key == "loopToken" and v else v)
PY
}

# ------------------------------------------------------------------ campaign id
acquire_lock

# A campaign that is going to be refused must not leave state behind, so the
# duplicate guards run before any identity file is written.
if [ ! -f "$CJSON" ]; then
  prelaunch_guard || {
    say "REFUSE not starting campaign $CAMPAIGN: $DECISION_DETAIL"
    release_lock "duplicate-guard"
    # a refused campaign must not leave a state dir that a later run mistakes for an
    # interrupted campaign waiting to be adopted
    [ "$STATE_CREATED_BY_ME" -eq 1 ] && [ ! -f "$CJSON" ] && rm -rf "$STATE"
    exit 6
  }
fi

if [ ! -f "$CJSON" ]; then
  "$PY" - "$CJSON" "$CAMPAIGN" "$TASK" "$MAX_WALL" "$MAX_RUNS" "$RUN_ITER" "$RUN_MINUTES" "$MIN_CODE_LINES" "$MAX_STAGNANT" <<'PY'
import json, subprocess, sys, datetime
path, campaign, task, wall, runs, riter, rmin, mincl, maxst = sys.argv[1:10]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True).stdout.strip()
json.dump({
  "schema": 1, "campaign": campaign, "task": task,
  "created_utc": now,
  "branch": branch, "start_sha": sha,
  "budget": {"max_wall_minutes": int(wall), "max_runs": int(runs),
             "run_iterations": int(riter), "run_minutes": int(rmin)},
  "thresholds": {"min_code_lines": int(mincl), "max_stagnant_runs": int(maxst)},
}, open(path, "w"), indent=1)
PY
  # The heredoc above is the campaign's identity file. If it did not land, nothing
  # downstream (budget, status, report, adoption) can be trusted — refuse now.
  [ -f "$CJSON" ] || {
    say "FATAL could not write $CJSON; refusing to run a campaign with no identity"
    release_lock "state-write-failed"
    exit 5
  }
  say "CAMPAIGN created id=$CAMPAIGN task=$TASK branch=$(git rev-parse --abbrev-ref HEAD) budget=${MAX_WALL}m/${MAX_RUNS}x runs of ${RUN_ITER}i/${RUN_MINUTES}m"
else
  CAMP_TASK=$("$PY" -c "import json;print(json.load(open('$CJSON'))['task'])")
  [ "$CAMP_TASK" = "$TASK" ] || { say "REFUSE campaign $CAMPAIGN belongs to task $CAMP_TASK, not $TASK"; exit 6; }
  CAMP_BRANCH=$("$PY" -c "import json;print(json.load(open('$CJSON'))['branch'])")
  CAMP_START=$("$PY" -c "import json;print(json.load(open('$CJSON'))['start_sha'])")
  NOW_BRANCH=$(git rev-parse --abbrev-ref HEAD)
  if [ "$CAMP_BRANCH" != "$NOW_BRANCH" ]; then
    say "STOP reason=unsafe-infrastructure detail=branch changed ($CAMP_BRANCH -> $NOW_BRANCH); the director never switches branches"
    release_lock "unsafe-infrastructure:branch-changed"
    exit 4
  fi
  say "CAMPAIGN resumed id=$CAMPAIGN (start_sha $(printf '%s' "$CAMP_START" | cut -c1-7))"
fi

START_EPOCH=$("$PY" -c "import json,datetime,pathlib;p=pathlib.Path('$CJSON');d=json.loads(p.read_text());print(int(datetime.datetime.strptime(d['created_utc'],'%Y-%m-%dT%H:%M:%SZ').timestamp()))")
case "$START_EPOCH" in
  ''|*[!0-9]*)
    say "FATAL unreadable campaign start time (got '$START_EPOCH'); refusing to run with a broken wall-clock budget"
    release_lock "state-read-failed"
    exit 5
    ;;
esac
GIT_BASE=$("$PY" -c "import json;print(json.load(open('$CJSON'))['start_sha'])")

STOP_REASON=""
DECISION="continue"
DECISION_DETAIL=""
STAGNANT=0
REGRESSIONS=0
ERRORS=0

# ---------------------------------------------------------- per-run mechanics
run_next() {
  RUN_N=$1
  RUN_DIR="$STATE/runs/$RUN_N"
  mkdir -p "$RUN_DIR"
  SHA_START=$(git rev-parse HEAD)
  PRE_TOKEN=$(loop_field token)
  PRE_STATUS=$(loop_field status)
  say "RUN $RUN_N start sha=$SHA_START loop_status=$PRE_STATUS token=$PRE_TOKEN"
  say "RUN $RUN_N launching supervisor (iterations=$RUN_ITER minutes=$RUN_MINUTES streak=$NO_PROGRESS_STREAK)"
  TS2_SUPERVISOR_LOG="$RUN_DIR/stop-request.log" \
    "$SUPERVISOR" --task "$TASK" --launch --max-iterations "$RUN_ITER" --max-minutes "$RUN_MINUTES" \
      --poll "$POLL" --no-progress-streak "$NO_PROGRESS_STREAK" > "$RUN_DIR/supervisor.log" 2>&1 &
  SUP_PID=$!
  printf 'supervisor %s %s\n' "$SUP_PID" "$(now_utc)" > "$RUN_DIR/supervisor.pid"
  record_open "$RUN_N" "$SHA_START" launching "" "$SUP_PID"
}

record_open() {
  "$PY" - "$STATE/runs/$1/open.json" "$1" "$2" "$3" "$4" "$5" "$TASK" <<'PY'
import json, sys, datetime
path, run, sha, phase, token, sup, task = sys.argv[1:8]
json.dump({"run": int(run), "sha_start": sha, "phase": phase, "token": token,
           "supervisor_pid": int(sup) if sup.isdigit() else None, "task": task,
           "started_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
          open(path, "w"), indent=1)
PY
}

# Watch the child supervisor: heartbeat, honour STOP, remember the loop token.
watch_run() {
  RUN_N=$1
  RUN_DIR="$STATE/runs/$RUN_N"
  SEEN_TOKEN=""
  while :; do
    heartbeat
    if [ -f "$STATE/STOP" ]; then
      say "STOP requested during run $RUN_N ($STOP_REASON_TEXT)"
      if [ "$IMMEDIATE" -eq 1 ]; then
        pi --approve --model "${TS2_WORKER_MODEL:-flashnext/swift-1.5-iq3_xxs}" --session-dir "$SESSIONS" -p "/ralph-stop $TASK" </dev/null >"$RUN_DIR/stop-request.log" 2>&1 ||
          say "note: immediate /ralph-stop exited non-zero"
      fi
    fi
    if [ -z "$SEEN_TOKEN" ]; then
      T=$(loop_field token)
      [ "$T" != "none" ] && [ "$T" != "$PRE_TOKEN" ] && { SEEN_TOKEN="$T"; record_open "$RUN_N" "$SHA_START" running "$SEEN_TOKEN" "$SUP_PID"; say "RUN $RUN_N loop token=$SEEN_TOKEN"; }
    fi
    if ! kill -0 "$SUP_PID" 2>/dev/null; then
      wait "$SUP_PID"; SUP_RC=$?
      break
    fi
    sleep "$POLL"
  done
  RUN_TOKEN=$(loop_field token)
  [ -n "$SEEN_TOKEN" ] && RUN_TOKEN="$SEEN_TOKEN"
  say "RUN $RUN_N supervisor exited rc=$SUP_RC (token=$RUN_TOKEN)"
}

close_run() {  # run, sup_rc, sha_start, token
  RUN_N=$1; SUP_RC=$2; SHA_START=$3; TOK=$4
  RUN_DIR="$STATE/runs/$RUN_N"
  mkdir -p "$RUN_DIR"
  say "VERIFY run $RUN_N (independent build + suites + protections)"
  sh "$VERIFIER" --baseline "$SHA_START" --build-dir "work/campaign-verify-build-$RUN_N" \
     > "$RUN_DIR/verify.json" 2> "$RUN_DIR/verify.err"
  VERIFY_RC=$?
  say "VERIFY run $RUN_N exit=$VERIFY_RC"
  "$PY" "$PROGRESS" --from "$SHA_START" --to HEAD --min-code-lines "$MIN_CODE_LINES" \
     > "$RUN_DIR/progress.json" 2> "$RUN_DIR/progress.err" || echo '{}' > "$RUN_DIR/progress.json"
  ARCHIVED=0
  [ -f "work/campaign-logs/loop-output-$(basename "$TASK_DIR").log" ] && {
    cp "work/campaign-logs/loop-output-$(basename "$TASK_DIR").log" "$RUN_DIR/loop-output.log" && ARCHIVED=1; }
  # The runner's own final state is recorded for the report. It is never used for a
  # progress or stop decision - run 3 reported progress on 25 prose-only iterations.
  "$PY" - "$RUN_DIR/run.json" "$RUN_N" "$CAMPAIGN" "$SHA_START" "$TOK" "$SUP_RC" "$VERIFY_RC" "$TASK" "$ARCHIVED" "$TASK_DIR/.ralph-runner/status.json" <<'PY'
import json, re, subprocess, sys, datetime, os
path, run, camp, sha, tok, src, vrc, task, archived, status_json = sys.argv[1:11]
def load(path):
    try:
        with open(path) as fh: return json.load(fh)
    except Exception: return {}
run_dir = os.path.dirname(path)
verify = load(os.path.join(run_dir, "verify.json"))
prog = load(os.path.join(run_dir, "progress.json"))
opener = load(os.path.join(run_dir, "open.json"))
runner = load(status_json)
# A director killed shortly after launch never learned its run's loop token, because
# the token only appears a few seconds after the loop starts. Recover it from that
# run's own supervisor log rather than recording an empty token: attribution between
# runs is the one thing this orchestrator must never get wrong.
token_source = "launch"
if not tok or tok == "none":
    log = os.path.join(run_dir, "supervisor.log")
    seen = []
    if os.path.exists(log):
        seen = [t for t in re.findall(r"token=([0-9a-f]{8})", open(log, errors="replace").read())
                if t != "none"]
        # drop the token of the previous loop that the supervisor reported as "pre"
        if len(seen) > 1:
            seen = seen[1:]
    if seen:
        tok = seen[-1]
        token_source = "supervisor-log"
end_sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
json.dump({
  "schema": 1, "campaign": camp, "run": int(run), "task": task,
  "started_utc": opener.get("started_utc"),
  "ended_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "sha_start": sha, "sha_end": end_sha, "loop_token": tok, "loop_token_source": token_source,
  "supervisor_exit": int(src), "verify_exit": int(vrc),
  "runner_status": runner.get("status"),
  "iterations_reported": runner.get("currentIteration"),
  "runner_token_matches": str(runner.get("loopToken", ""))[:8] == str(tok)[:8] and str(tok) not in ("", "none"),
  "progress": prog, "verification": verify,
  "loop_output_archived": archived == "1",
}, open(path, "w"), indent=1)
PY
  rm -f "$RUN_DIR/open.json"
}

decide() {  # sets DECISION, DECISION_DETAIL
  RUN_N=$1
  RUN_DIR="$STATE/runs/$RUN_N"
  DECISION="continue"; DECISION_DETAIL=""
  V=$(  "$PY" -c "import json;d=json.load(open('$RUN_DIR/verify.json'));print(d.get('verdict','unknown'))" 2>/dev/null || echo unknown)
  OK_BUILD=$("$PY" -c "import json;d=json.load(open('$RUN_DIR/verify.json'));print(d.get('build_ok'))" 2>/dev/null || echo None)
  # ONE implementation of the rule, shared with campaign-report.py. The director must not
  # keep its own copy: run 4 of recomp-benchmark-20261023 was verified clean (verdict pass,
  # CTest 22/22, 572 Python tests, 0 skips) and was still ended with integrity-violation,
  # because this predicate had been left reading the informational "tests_modified_or_deleted"
  # count after the gate itself was relaxed. See scripts/campaign/campaign-integrity-check.py.
  INT_OK=$("$PY" scripts/campaign/campaign-integrity-check.py "$RUN_DIR/verify.json" 2>/dev/null || echo unknown)
  CLASS=$("$PY" -c "import json;d=json.load(open('$RUN_DIR/progress.json'));print(d.get('classification','none'))" 2>/dev/null || echo none)
  RUNST=$("$PY" -c "import json;d=json.load(open('$RUN_DIR/run.json'));print(d.get('runner_status'))" 2>/dev/null || echo None)

  # 1. Integrity first: a moved protection outranks everything else.
  if [ "$INT_OK" = violation ]; then
    STOP_REASON="integrity-violation"; DECISION="stop"
    # Say WHICH protection fired. The old blanket string ("a protected file moved or the
    # completion promise was claimed") sent an operator hunting the wrong file for 20
    # minutes while the real trigger was the modified-test-file rule.
    INT_WHY=$("$PY" scripts/campaign/campaign-integrity-check.py --why "$RUN_DIR/verify.json" 2>/dev/null || echo "unreadable verify.json")
    DECISION_DETAIL="run $RUN_N tripped the integrity gate: $INT_WHY"
    return 0
  fi
  if [ "$RUNST" = complete ]; then
    ACCEPT=$("$PY" -c "import json;print(json.load(open('$RUN_DIR/verify.json')).get('acceptance_exit'))" 2>/dev/null || echo None)
    if [ "$ACCEPT" = 0 ]; then
      STOP_REASON="mission-complete"; DECISION="stop"; DECISION_DETAIL="runner reported complete AND the trusted acceptance gate exited 0"
    else
      STOP_REASON="integrity-violation"; DECISION="stop"
      DECISION_DETAIL="run $RUN_N reported complete while the acceptance gate exited $ACCEPT (false completion)"
    fi
    return 0
  fi
  # 2. Regressions: one repair attempt, then stop for a human.
  if [ "$V" = test-regression ] || [ "$OK_BUILD" = False ]; then
    REGRESSIONS=$(( REGRESSIONS + 1 ))
    if [ "$REGRESSIONS" -ge 2 ]; then
      STOP_REASON="test-regression"; DECISION="stop"
      DECISION_DETAIL="build/tests still failing after one repair run (verify_exit=$VERIFY_RC_LAST)"
    else
      DECISION="continue"; DECISION_DETAIL="regression in run $RUN_N; one repair run allowed"
      directive "REPAIR: the previous run left the build or test suites failing (see $RUN_DIR/verify.json and $RUN_DIR/verify.err). Fix the regression before adding anything new. Do not delete, skip or weaken a test to get green."
    fi
    return 0
  fi
  if [ "$V" = unknown ]; then
    ERRORS=$(( ERRORS + 1 ))
    if [ "$ERRORS" -ge 2 ]; then STOP_REASON="unsafe-infrastructure"; DECISION="stop"; DECISION_DETAIL="verification could not be parsed twice in a row"; return 0; fi
  fi
  # 3. Supervisor-reported failure that was not one of our own budgets.
  case "$SUP_RC_LAST" in
    4) STOP_REASON="unsafe-infrastructure"; DECISION="stop"; DECISION_DETAIL="supervisor enforced a stop and the loop did not settle (exit 4) - operator intervention required"; return 0 ;;
    5) STOP_REASON="unsafe-infrastructure"; DECISION="stop"; DECISION_DETAIL="supervisor could not observe the loop (exit 5)"; return 0 ;;
    64) STOP_REASON="unsafe-infrastructure"; DECISION="stop"; DECISION_DETAIL="supervisor usage error (exit 64) - this is a bug, not a campaign outcome"; return 0 ;;
  esac
  # 4. Stagnation measured from committed content, never from self-report.
  if [ "$CLASS" = engineering ]; then
    STAGNANT=0
  else
    STAGNANT=$(( STAGNANT + 1 ))
    if [ "$STAGNANT" -ge "$MAX_STAGNANT" ]; then
      # Provider-outage guard (added after 2026-10-28T22:18Z): if EVERY
      # iteration of this run died inside the model call (usage limit, rate
      # limit, provider 5xx), the run measured NOTHING about the worker or
      # the objective. Both lanes then ran as "stagnant", were mislabeled
      # human-blocker-provisioning via gate 78, charged the global streak
      # and stopped the fleet as stopped:blocker while the actual error was
      # "Codex error: The usage limit has been reached". A pure-fault run is
      # an INFRASTRUCTURE outcome: the coordinator resumes it under its
      # bounded infra retries instead of blocking objectives. Fail-closed:
      # any behaved iteration or unmatched error keeps stagnation handling.
      TOK=$("$PY" -c "import json;print(json.load(open('$RUN_DIR/run.json')).get('loop_token',''))" 2>/dev/null || echo "")
      FAULT=$("$PY" scripts/campaign/director-run-fault.py "$TASK_DIR/.ralph-runner/iterations.jsonl" "$TOK" 2>/dev/null || echo clean)
      case "$FAULT" in
        fault*)
          STOP_REASON="unsafe-infrastructure"; DECISION="stop"
          DECISION_DETAIL="model provider fault on every iteration (not worker stagnation): ${FAULT#fault }"
          ;;
        *)
          ACCEPT=$("$PY" -c "import json;print(json.load(open('$RUN_DIR/verify.json')).get('acceptance_exit'))" 2>/dev/null || echo None)
          if [ "$ACCEPT" = 78 ]; then
            STOP_REASON="human-blocker-provisioning"; DECISION="stop"
            DECISION_DETAIL="$STAGNANT consecutive runs without engineering progress while the acceptance gate is still fail-closed (78): the missing work is provisioning, not code"
          else
            STOP_REASON="stagnation"; DECISION="stop"
            DECISION_DETAIL="$STAGNANT consecutive runs classified $CLASS (threshold $MAX_STAGNANT)"
          fi
          ;;
      esac
      return 0
    fi
    directive "The last run was classified '$CLASS' by scripts/campaign/campaign-progress.py: it committed no new engineering artifact. Pick the highest-ranked priority that produces a committed, tested artifact this iteration. Do not produce another report-only iteration."
  fi
  return 0
}

directive() {
  mkdir -p "$STATE/directives"
  N=$("$PY" -c "import glob;print(len(glob.glob('$STATE/directives/*.md'))+1)")
  {
    printf '# Director directive %s (%s)\n\n' "$N" "$(now_utc)"
    printf '%s\n' "$1"
  } > "$STATE/directives/$N.md"
  say "DIRECTIVE written ($STATE/directives/$N.md)"
  if [ "$WRITEBACK" -eq 1 ]; then
    if [ -n "$(git status --porcelain -- "$TASK/RALPH.md" 2>/dev/null)" ]; then
      say "DIRECTIVE writeback skipped: $TASK/RALPH.md is dirty (refusing to touch a live worktree file)"
      return 0
    fi
    "$PY" - "$TASK_DIR/RALPH.md" "$STATE/directives/$N.md" <<'PY'
import pathlib, sys
md, src = map(pathlib.Path, sys.argv[1:3])
text = md.read_text()
block = src.read_text().strip()
begin, end = "<!-- DIRECTOR:BEGIN -->", "<!-- DIRECTOR:END -->"
body = f"{begin}\n{block}\n{end}\n"
if begin in text and end in text:
    pre = text.split(begin)[0]
    post = text.split(end, 1)[1]
    md.write_text(pre + body + post)
else:
    md.write_text(text.rstrip() + "\n\n" + body)
PY
    git add "$TASK/RALPH.md" &&
      git commit -q -m "Director directive for campaign $CAMPAIGN (run boundary)

Written by scripts/campaign/campaign-director.sh between Ralph runs. Replaces the
previous directive block; the loop re-reads RALPH.md every iteration." &&
      say "DIRECTIVE committed to $TASK/RALPH.md" ||
      say "DIRECTIVE commit failed (left in $STATE/directives/ only)"
  fi
}

# ---------------------------------------------------------------------- main
highest_run() { # highest numeric run directory, 0 if none (counting dirs breaks
  # once a directory is ever removed, which would silently reuse a run number)
  H=0
  for d in "$STATE"/runs/*/; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    case "$n" in ''|*[!0-9]*) continue ;; esac
    [ "$n" -gt "$H" ] && H=$n
  done
  printf '%s' "$H"
}

open_run() { # run number that was left open by an interruption, else empty
  for d in "$STATE"/runs/*/; do
    [ -f "$d/open.json" ] || continue
    basename "$d"
    return 0
  done
  printf ''
}

say "DIRECTOR start campaign=$CAMPAIGN pid=$$ wall=${MAX_WALL}m runs=${MAX_RUNS} state=$STATE"
say "MONITOR with: $0 --campaign $CAMPAIGN --status   STOP with: $0 --campaign $CAMPAIGN --stop"

RUN_INDEX=0
while :; do
  heartbeat
  ELAPSED=$(( ( $(epoch) - START_EPOCH ) / 60 ))

  # An interrupted run is adopted before any budget is consulted. The first version
  # of this loop numbered the next run by counting run directories and then looked
  # for open.json in that NEXT directory, so it never found the open run at all; and
  # it tested the run budget first, so a crash during the final run made the restart
  # announce budget-runs while that worker was still running with nobody supervising
  # it. Adoption is now both correct and unconditional.
  OPEN_RUN=$(open_run)
  if [ -n "$OPEN_RUN" ]; then
    RUN_INDEX="$OPEN_RUN"
    OPEN_TOKEN=$("$PY" -c "import json;print(json.load(open('$STATE/runs/$RUN_INDEX/open.json')).get('token') or '')")
    OPEN_SHA=$("$PY" -c "import json;print(json.load(open('$STATE/runs/$RUN_INDEX/open.json'))['sha_start'])")
    LIVE_STATUS=$(loop_field status)
    say "ADOPT run $RUN_INDEX found open (token=${OPEN_TOKEN:-unknown}, loop=$LIVE_STATUS)"
    SUP_RC_LAST=0
    VERIFY_RC_LAST=0
    if ! is_terminal "$LIVE_STATUS"; then
      # Attach the supervisor to the existing loop; never launch a second one.
      "$SUPERVISOR" --task "$TASK" --max-iterations "$RUN_ITER" --max-minutes "$RUN_MINUTES" \
        --poll "$POLL" > "$STATE/runs/$RUN_INDEX/supervisor-attached.log" 2>&1 &
      SUP_PID=$!
      while kill -0 "$SUP_PID" 2>/dev/null; do heartbeat; sleep "$POLL"; done
      wait "$SUP_PID"; SUP_RC_LAST=$?
    fi
    close_run "$RUN_INDEX" "$SUP_RC_LAST" "$OPEN_SHA" "${OPEN_TOKEN:-$(loop_field token)}"
    decide "$RUN_INDEX"
    [ "$DECISION" = stop ] && break
    continue
  fi

  RUN_INDEX=$(( $(highest_run) + 1 ))

  if [ -f "$STATE/STOP" ]; then
    STOP_REASON="manual-stop"; say "STOP reason=manual-stop (STOP file present at boundary)"; break
  fi
  if [ "$ELAPSED" -ge "$MAX_WALL" ]; then
    STOP_REASON="budget-wall"; say "STOP reason=budget-wall (${ELAPSED}m >= ${MAX_WALL}m)"; break
  fi
  if [ "$RUN_INDEX" -gt "$MAX_RUNS" ]; then
    STOP_REASON="budget-runs"; say "STOP reason=budget-runs ($(( RUN_INDEX - 1 )) runs of max $MAX_RUNS)"; break
  fi

  prelaunch_guard || { STOP_REASON="duplicate-guard"; DECISION_DETAIL="another director, supervisor or live loop owns $TASK"; break; }

  SUP_RC_LAST=0
  VERIFY_RC_LAST=0
  run_next "$RUN_INDEX"
  watch_run "$RUN_INDEX"
  VERIFY_RC_LAST=$SUP_RC_LAST
  close_run "$RUN_INDEX" "$SUP_RC_LAST" "$SHA_START" "$RUN_TOKEN"
  decide "$RUN_INDEX"
  [ "$DECISION" = stop ] && break
done

FINAL=$STOP_REASON
[ -n "$FINAL" ] || FINAL="unknown"
"$PY" - "$CJSON" "$FINAL" "$DECISION_DETAIL" <<'PY'
import json, sys, datetime
path, reason, detail = sys.argv[1:4]
d = json.load(open(path))
d["stopped_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
d["stop"] = {"reason": reason, "detail": detail}
json.dump(d, open(path, "w"), indent=1)
PY
say "CAMPAIGN $CAMPAIGN ended reason=$FINAL detail=$DECISION_DETAIL"
"$PY" "$REPORTER" --state "$STATE" > "$STATE/campaign-report.md" 2>"$STATE/report.err" &&
  say "REPORT $STATE/campaign-report.md" || say "REPORT failed; see $STATE/report.err"

case "$FINAL" in
  budget-wall|budget-runs|mission-complete) release_lock "$FINAL"; exit 0 ;;
  integrity-violation) release_lock "$FINAL"; exit 4 ;;
  stagnation|test-regression|manual-stop|human-blocker-provisioning) release_lock "$FINAL"; exit 3 ;;
  *) release_lock "$FINAL"; exit 5 ;;
esac
