#!/bin/sh
# External budgeted supervisor for a Ralph campaign.
#
# Rationale. A RALPH.md `max_iterations` bound only stops a single run, and a run
# that is stopped, crashes or hits no-progress has to be resumed by something.
# docs/AUTONOMOUS_SETUP.md asks for an external supervisor that caps total
# budget and proves it stops. This script is that supervisor: it never decides
# what counts as progress (the runner does), it only enforces wall-clock and
# iteration budgets from outside the worker and records every decision.
#
# Usage:
#   scripts/campaign/budgeted-supervisor.sh --task ./tasks/android-phase1 \
#       [--launch] [--max-iterations 10] [--max-minutes 150] [--poll 30] \
#       [--no-progress-streak 3]
#
#   --launch            start the loop first (detached); otherwise attach to a
#                       loop that is already running on --task
#   --max-iterations    stop once the RUNNER reports this iteration number
#   --max-minutes       wall-clock cap measured from supervisor start
#
# Output. One line per poll decision to stdout (tee it to a log). Exit codes:
#   0 loop reached a terminal status on its own
#   3 supervisor enforced a budget stop and the loop then settled
#   4 supervisor enforced a budget stop and the loop did NOT settle in time
#   5 supervisor could not observe the loop (no status.json / unparseable)
#
# Do not run two supervisors for the same task. Stop requests are issued through
# /ralph-stop only; this script never kills the worker process, because killing
# it leaves the runner's registry entry active until its 30-minute TTL expires.

set -u

TASK=""
LAUNCH=0
MAX_ITER=10
MAX_MINUTES=150
POLL=30
# Consecutive iterations with no verified progress before the runner stops itself.
# The runner reads this from RALPH_RUNNER_NO_PROGRESS_STREAK and defaults to 0 =
# disabled, which is how run 2 spent 11 iterations on a task whose workers were
# blocked from iteration 5 onward. Only applied to a loop this supervisor
# launches; an already-running loop keeps whatever it started with.
NO_PROGRESS_STREAK=3
STOP_GRACE_MINUTES=35
# Session dirs live inside the repository. Observed on 2026-10-22: launching with
# --session-dir under /tmp produced an immediate exit, an empty output file and
# no status.json, because Pi derives project trust from the session directory and
# --approve only pre-approves the *current* project — outside the workspace the
# runner extension is never loaded. Under work/ (gitignored) the session root is
# the repo, which is what the manual commands in docs/AUTONOMOUS_SETUP.md use.
SESSIONS="work/pi-sessions"

# Resolve the repo root from this script's location so the supervisor works from
# any cwd and still keeps its session root inside the workspace.
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT" || { echo "supervisor: cannot enter $REPO_ROOT" >&2; exit 5; }

while [ $# -gt 0 ]; do
  case "$1" in
    --task) TASK="$2"; shift 2 ;;
    --launch) LAUNCH=1; shift ;;
    --max-iterations) MAX_ITER="$2"; shift 2 ;;
    --max-minutes) MAX_MINUTES="$2"; shift 2 ;;
    --poll) POLL="$2"; shift 2 ;;
    --no-progress-streak) NO_PROGRESS_STREAK="$2"; shift 2 ;;
    --stop-grace-minutes) STOP_GRACE_MINUTES="$2"; shift 2 ;;
    *) echo "supervisor: unknown argument: $1" >&2; exit 64 ;;
  esac
done

[ -n "$TASK" ] || { echo "supervisor: --task is required" >&2; exit 64; }
case "$NO_PROGRESS_STREAK" in
  ''|*[!0-9]*) echo "supervisor: --no-progress-streak must be an integer (0 disables)" >&2; exit 64 ;;
esac
# IMPORTANT: Ralph's `--path` argument is parsed out of the slash-command string,
# so an ABSOLUTE path containing spaces is silently truncated at the first space
# (observed: `--path /workspace/Sims 2 Decomp ...` produced an immediate exit,
# empty output and no status.json). Pass the task as a path RELATIVE to the repo
# root, exactly like the commands in docs/AUTONOMOUS_SETUP.md and
# scripts/campaign/test-worker-lifecycle.sh. $TASK_REL is used for every pi
# invocation; $TASK_DIR (absolute) only for reading state locally.
TASK_REL="$TASK"
TASK_DIR=$(cd "$TASK" 2>/dev/null && pwd) || { echo "supervisor: no such task dir: $TASK" >&2; exit 64; }
STATUS="$TASK_DIR/.ralph-runner/status.json"
PY=$(command -v python3 || true)
[ -n "$PY" ] || { echo "supervisor: python3 required to read status.json" >&2; exit 5; }

STARTED_AT=$(date +%s)
EXPECT_TOKEN=""
TERMINAL="complete max-iterations no-progress-exhaustion stopped timeout error cancelled"

say() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

# read_status -> "<status> <iteration> <token>", or "UNPARSEABLE ...".
# Field names are read defensively: the runner writes `currentIteration` and
# `loopToken` (verified against a live status.json on 2026-10-22). Reading the
# wrong key here does not crash anything, it silently reports iteration 0 and
# the iteration budget never fires, so the fallbacks are belt-and-braces only.
read_status() {
  [ -f "$STATUS" ] || { printf '\n'; return; }
  "$PY" - "$STATUS" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"UNPARSEABLE {exc}")
    raise SystemExit
it = d.get("currentIteration", d.get("iterations", 0)) or 0
tok = str(d.get("loopToken") or d.get("runToken") or "")[:8]
print(f"{d.get('status','?')} {it} {tok}")
PY
}

# consecutive_no_progress -> completed iterations with progress=false at the tail
# of events.jsonl for the loop being watched. A blocked worker that changes
# nothing lands here; a worker that commits anything does not.
consecutive_no_progress() {
  EVENTS="$TASK_DIR/.ralph-runner/events.jsonl"
  [ -f "$EVENTS" ] || { printf '0\n'; return; }
  "$PY" - "$EVENTS" "${EXPECT_TOKEN:-}" <<'PY'
import json, sys
path, tok = sys.argv[1], sys.argv[2]
flags = []
try:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("type") != "iteration.completed":
                continue
            lt = str(d.get("loopToken") or "")
            if tok and not lt.startswith(tok):
                continue
            flags.append(bool(d.get("progress")))
except OSError:
    print(0)
    raise SystemExit
n = 0
for progressed in reversed(flags):
    if progressed:
        break
    n += 1
print(n)
PY
}

request_stop() {
  REASON="$1"
  say "STOP REQUEST reason=$REASON (via /ralph-stop; takes effect at iteration boundary)"
  # --model pin: never let even a stop request resolve pi's default provider
  # (openai-codex on this host); see the TS2_WORKER_MODEL block in worker-env.sh.
  pi --approve --model "${TS2_WORKER_MODEL:-flashnext/swift-1.5-iq3_xxs}" --session-dir "$SESSIONS" -p "/ralph-stop $TASK_REL" </dev/null >"$STOP_LOG" 2>&1 ||
    say "note: /ralph-stop exited non-zero (a stop request for a finished loop is normal); see $STOP_LOG"
}

wait_terminal() {
  LIMIT=$(( $(date +%s) + STOP_GRACE_MINUTES * 60 ))
  while [ "$(date +%s)" -lt "$LIMIT" ]; do
    LINE=$(read_status)
    set -- $LINE
    ST="${1:-}"; IT="${2:-0}"
    for T in $TERMINAL; do [ "$ST" = "$T" ] && { say "SETTLED status=$ST iterations=$IT"; return 0; }; done
    sleep "$POLL"
  done
  return 1
}

say "START task=$TASK_REL max_iterations=$MAX_ITER max_minutes=$MAX_MINUTES poll=${POLL}s no_progress_streak=$NO_PROGRESS_STREAK"
mkdir -p "$SESSIONS"
STOP_LOG="${TS2_SUPERVISOR_LOG:-work/campaign-logs/supervisor-last-stop.log}"

if [ "$LAUNCH" -eq 1 ]; then
  # Per-task log. `work/campaign-logs/loop-output.log` was a fixed name, so a
  # second supervisor (a smoke validation run while a campaign was live) truncated
  # the campaign's launch output. Never share it between tasks.
  LOOP_LOG="work/campaign-logs/loop-output-$(basename "$TASK_DIR").log"
  # A previous run leaves status.json behind with a TERMINAL status and its old
  # loop token. Judging that file as the current loop made this supervisor print
  # "DONE status=stopped" seconds after launching and exit `enforced=none`, while
  # the loop it had just started ran UNCAPPED (observed 2026-10-22, run 2). So the
  # pre-launch token is recorded and --launch is only considered observed when a
  # DIFFERENT token appears.
  PRE_LINE=$(read_status); set -- $PRE_LINE
  PRE_ST="${1:-none}"; PRE_TOKEN="${3:-none}"
  say "PRELAUNCH status=$PRE_ST token=$PRE_TOKEN"
  # Detached so the campaign survives this shell; --approve is required because
  # the runner is a project package and untrusted packages are refused. Output
  # MUST NOT go to /dev/null: a failed launch has to be diagnosable, and an
  # untrusted-project refusal is otherwise indistinguishable from success.
  # RALPH_RUNNER_NO_PROGRESS_STREAK is an OUTPUT of the runner (runner.ts:835
  # exports the current streak to each worker); it is not a configurable limit,
  # and the runner only labels a run "no-progress-exhaustion" at the END if no
  # iteration in the entire run ever progressed (runner.ts:1233). A run that
  # progresses then stalls — run 2, 11 dead iterations — can never stop itself, so
  # the consecutive-streak rule is enforced here from events.jsonl instead.
  mkdir -p "$(dirname "$LOOP_LOG")" "$SESSIONS" \
    || { say "ABORT cannot create log/session directory for $LOOP_LOG"; exit 5; }
  # Model pin (2026-10-30): the ralph-loop inherits THIS session's model into
  # every RPC worker (pi-ralph-loop src/index.ts modelPattern=ctx.model), so
  # --model here is what each worker runs. Unpinned it resolved to the expired
  # openai-codex subscription and stopped the fleet (quota/auth faults).
  say "LAUNCH model=${TS2_WORKER_MODEL:-flashnext/swift-1.5-iq3_xxs}"
  setsid pi --approve --model "${TS2_WORKER_MODEL:-flashnext/swift-1.5-iq3_xxs}" --session-dir "$SESSIONS" -p "/ralph --path $TASK_REL" </dev/null >"$LOOP_LOG" 2>&1 &
  say "LAUNCH requested (pid $!); session=$SESSIONS log=$LOOP_LOG"
  WAITED=0
  while [ "$WAITED" -lt 420 ]; do
    LINE=$(read_status); set -- $LINE
    ST0="${1:-?}"; TOK0="${3:-none}"
    if [ "$TOK0" != "none" ] && [ "$TOK0" != "$PRE_TOKEN" ]; then
      EXPECT_TOKEN="$TOK0"
      say "LAUNCH OBSERVED status=$ST0 token=$EXPECT_TOKEN after ${WAITED}s"
      break
    fi
    sleep 5; WAITED=$(( WAITED + 5 ))
    if [ "$WAITED" -eq 60 ]; then
      say "NOTE no new loop token after 60s (pre=$PRE_TOKEN); last loop output:"
      tail -5 "$LOOP_LOG" 2>/dev/null | sed 's/^/  | /'
    fi
  done
  if [ -z "$EXPECT_TOKEN" ]; then
    say "FATAL no new loop token within 420s of --launch (pre=$PRE_TOKEN); loop output follows:"
    tail -20 "$LOOP_LOG" 2>/dev/null | sed 's/^/  | /'
    exit 5
  fi
fi

[ -f "$STATUS" ] || { say "FATAL $STATUS missing; start the loop or pass --launch"; exit 5; }

ENFORCED=""
while :; do
  LINE=$(read_status)
  [ -n "$LINE" ] || { say "FATAL status.json disappeared"; exit 5; }
  case "$LINE" in
    UNPARSEABLE*) say "FATAL status.json unparseable: $LINE"; exit 5 ;;
  esac
  set -- $LINE
  ST="$1"; IT="$2"; TOK="$3"
  ELAPSED=$(( ( $(date +%s) - STARTED_AT ) / 60 ))

  # A terminal status carrying a foreign token belongs to a previous run (or a
  # different loop on the same task). Never act on it as if it were ours.
  if [ -n "$EXPECT_TOKEN" ] && [ "$TOK" != "$EXPECT_TOKEN" ]; then
    say "IGNORE status=$ST token=$TOK is not the launched loop (expected $EXPECT_TOKEN)"
    sleep "$POLL"
    continue
  fi

  for T in $TERMINAL; do
    if [ "$ST" = "$T" ]; then
      say "DONE status=$ST iterations=$IT token=$TOK elapsed=${ELAPSED}m enforced=${ENFORCED:-none}"
      [ -n "$ENFORCED" ] && exit 3
      exit 0
    fi
  done

  say "poll status=$ST iterations=$IT token=$TOK elapsed=${ELAPSED}m"

  if [ "$IT" -ge "$MAX_ITER" ]; then ENFORCED="iteration-budget"; request_stop "$ENFORCED"; break; fi
  if [ "$ELAPSED" -ge "$MAX_MINUTES" ]; then ENFORCED="wall-clock-budget"; request_stop "$ENFORCED"; break; fi
  if [ "$NO_PROGRESS_STREAK" -gt 0 ]; then
    STREAK=$(consecutive_no_progress)
    case "$STREAK" in ''|*[!0-9]*) STREAK=0 ;; esac
    if [ "$STREAK" -ge "$NO_PROGRESS_STREAK" ]; then
      say "NO_PROGRESS streak=$STREAK (limit $NO_PROGRESS_STREAK)"
      ENFORCED="no-progress-streak"; request_stop "$ENFORCED"; break
    fi
  fi
  sleep "$POLL"
done

if wait_terminal; then
  say "EXIT 3 (budget enforced, loop settled)"
  exit 3
fi
say "EXIT 4 (budget enforced but loop still not terminal after ${STOP_GRACE_MINUTES}m grace; operator intervention needed, see docs/AUTONOMOUS_SETUP.md crash-recovery notes)"
exit 4
