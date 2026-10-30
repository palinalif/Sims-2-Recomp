#!/usr/bin/env bash
# Worker-lifecycle evidence for Ralph campaigns (OPEN_QUESTIONS P1).
#
# Runs against a DISPOSABLE task directory only. It answers three questions
# that a green smoke test does not:
#   1. Is single-worker ownership enforced across separate Pi processes?
#   2. What happens to a task directory when the runner is SIGKILLed?
#   3. Is that state permanent, or bounded by the registry staleness TTL?
#
# Cost: a handful of small Pi runs, a few minutes wall clock.
# Usage: scripts/campaign/test-worker-lifecycle.sh [--age-only]
#   --age-only  skip phases 1-2 and only re-test the TTL escape hatch on
#               whatever state the last run left behind.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 1
# shellcheck disable=SC1091
. scripts/campaign/worker-env.sh

D=".tools/campaign/smoke-lifecycle"
LOGD="$REPO/work/campaign-logs"
SESS="$REPO/work/pi-sessions"
PY="${PY:-python3}"
ST="$D/.ralph-runner/status.json"
mkdir -p "$D" "$LOGD" "$SESS"

find_pids() { # no ps/pkill on this host: scan /proc
  local pat="$1" p cmd
  for p in /proc/[0-9]*; do
    [ -r "$p/cmdline" ] || continue
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
    case "$cmd" in *"$pat"*) echo "${p#/proc/}" ;; esac
  done
}
# Each live loop drives exactly one "pi --mode rpc" worker, so counting those
# children is a direct read of how many loops are actually executing.
# NOTE ON METRICS: a "count the pi --mode rpc children" proxy was tried here and
# never matched a single process on this host, so it is NOT used as evidence.
# The ownership verdict relies on the loop token, whose behaviour has a positive
# control: phase 4 proves that a genuinely new run mints a NEW token.
rpc_count() { find_pids "--mode rpc" | wc -l | tr -d ' '; }
jval() { "$PY" -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2],"none"))
except Exception: print("unreadable")' "$1" "$2" 2>/dev/null; }

if [ "${1:-}" != "--age-only" ]; then
  rm -rf "$D/.ralph-runner"
  cat > "$D/RALPH.md" <<'EOF'
---
max_iterations: 8
timeout: 300
items_per_iteration: 1
commands:
  - name: slow
    run: 'sleep 8'
    timeout: 60
    acceptance: true
completion_promise: LIFECYCLE_SMOKE_VERIFIED
guardrails: {}
---
# Lifecycle smoke

Reply with exactly LIFECYCLE OK and finish. Do not run git commands. Do not create files.
EOF

  echo "### phase 1: detached run (survives this script's own shell)"
  setsid sh -c "echo \$\$ > '$LOGD/life.pid'; exec pi --approve --model '$TS2_WORKER_MODEL' --session-dir '$SESS' -p '/ralph --path ./$D'" \
    > "$LOGD/life-run1.log" 2>&1 < /dev/null &
  sleep 1
  PG1="$(cat "$LOGD/life.pid")"
  echo "run1 pgid=$PG1"
  sleep 35
  echo "status=$(jval "$ST" status) token=$(jval "$ST" loopToken | cut -c1-8) alive=$(kill -0 "-$PG1" 2>/dev/null && echo yes || echo no)"

  echo
  echo "### phase 2: second concurrent run from a DIFFERENT Pi process"
  # A genuine takeover mints a NEW loop token (phase 4 is the positive control),
  # so "token unchanged" is the ownership signal. Iterations legitimately keep
  # growing because the FIRST loop is still working - that is not a second worker.
  T0=$(jval "$ST" loopToken)
  I0=$(wc -l < "$D/.ralph-runner/iterations.jsonl" 2>/dev/null || echo 0)
  echo "baseline: token=${T0:0:8} iterations=$I0 (rpc-child probe returned $(rpc_count); see metric note above)"
  timeout 200 pi --approve --model "$TS2_WORKER_MODEL" --session-dir "$SESS" -p "/ralph --path ./$D" \
    > "$LOGD/life-run2.log" 2>&1 </dev/null &
  R2=$!
  wait "$R2"
  echo "second run exit=$? (stdout is empty by design: notify is not printed in -p mode)"
  T1=$(jval "$ST" loopToken)
  I1=$(wc -l < "$D/.ralph-runner/iterations.jsonl" 2>/dev/null || echo 0)
  echo "after: token=${T1:0:8} iterations=$I1"
  if [ "$T0" = "$T1" ]; then
    echo "OWNERSHIP ENFORCED: no second loop took ownership (token unchanged; the first loop's own iterations went $I0 -> $I1)"
  else
    echo "OWNERSHIP NOT ENFORCED: token $T0 -> $T1"
  fi
  echo "first run still alive: $(kill -0 "-$PG1" 2>/dev/null && echo yes || echo no)"

  echo
  echo "### phase 3: SIGKILL the whole run group, then try to restart"
  if ! kill -0 "-$PG1" 2>/dev/null; then
    echo "SKIP phase 3: run 1 already reached a terminal state before the kill, so no wedge"
    echo "can be produced here - raise max_iterations (it is 3) or the per-command sleep."
  else
    kill -9 "-$PG1" 2>/dev/null
    sleep 5
    echo "status after kill -9: $(jval "$ST" status) (stale marker expected)"
    timeout 200 pi --approve --model "$TS2_WORKER_MODEL" --session-dir "$SESS" -p "/ralph --path ./$D" \
      > "$LOGD/life-run3.log" 2>&1 </dev/null
    T2=$(jval "$ST" loopToken)
    if [ "$T1" = "$T2" ]; then
      echo "WEDGED AS DOCUMENTED: restart refused while the dead entry is fresh (token $T2)"
    else
      echo "unexpected: restart proceeded immediately (token $T1 -> $T2)"
    fi
    echo "does /ralph-stop clear it? $(timeout 120 pi --approve --model "$TS2_WORKER_MODEL" --session-dir "$SESS" -p "/ralph-stop ./$D" >/dev/null 2>&1; jval "$ST" status)"
    echo "does /ralph-cancel clear it? $(timeout 120 pi --approve --model "$TS2_WORKER_MODEL" --session-dir "$SESS" -p "/ralph-cancel ./$D" >/dev/null 2>&1; jval "$ST" status)"
  fi
fi

echo
echo "### phase 4: age the registry entry past ACTIVE_LOOP_REGISTRY_STALE_AFTER_MS (30 min)"
"$PY" - <<'PY'
import datetime, glob, json
ago = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=31))
stamp = ago.isoformat().replace("+00:00", "Z")
n = 0
for p in glob.glob(".ralph-runner/active-loops/*.json") + glob.glob(".tools/campaign/smoke-lifecycle/.ralph-runner/active-loops/*.json"):
    try:
        d = json.load(open(p))
        if "smoke-lifecycle" not in str(d.get("taskDir", "")):
            continue
        d["updatedAt"] = stamp
        json.dump(d, open(p, "w"), indent=2)
        n += 1
    except Exception as e:
        print("  skip", p, e)
print("  aged %d entr(y|ies) to %s (simulates the TTL elapsing; test state only)" % (n, stamp))
PY
timeout 400 pi --approve --model "$TS2_WORKER_MODEL" --session-dir "$SESS" -p "/ralph --path ./$D" > "$LOGD/life-run4.log" 2>&1 </dev/null
echo "post-TTL start exit=$?"
sleep 5
echo "status=$(jval "$ST" status) token=$(jval "$ST" loopToken | cut -c1-8) iterations=$(wc -l < "$D/.ralph-runner/iterations.jsonl" 2>/dev/null || echo 0)"
echo "leftover loop processes for this task: $(find_pids "rph --path ./$D" | wc -l | tr -d ' ')"
echo "DONE"
