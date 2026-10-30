#!/usr/bin/env bash
# Disposable self-test for scripts/campaign/campaign-coordinator.py.
# Uses a FAKE director (no Ralph, no workers, seconds per campaign) to verify
# the coordinator's decision machine from ACTUAL process state and durable
# logs — never from self-reported success. Runtime state lives under
# work/coord-selftest/ (ignored). Exit 0 = all cases pass.
set -u
cd "$(dirname "$0")/../.." || exit 64
. scripts/campaign/worker-env.sh
PY="${PYTHON:-python3}"
ROOT="work/coord-selftest"
BIN="work/coord-selftest-bin"
FAIL=0
COORD="scripts/campaign/campaign-coordinator.py"

fresh() { rm -rf "$ROOT"; mkdir -p "$ROOT/state" "$ROOT/campaign-logs" "$ROOT/coord"; }
cleanup() { for p in /proc/[0-9]*; do local d cwd c; d="${p#/proc/}"; cwd=$(readlink "$p/cwd" 2>/dev/null); c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue; case "${cwd:-} ${c:-}" in *coord-selftest*) case "$c" in *campaign-coordinator*|*fakedirector*) kill -9 "$d" 2>/dev/null;; esac;; esac; done; sleep 0.5; }
coord() { (cd "$ROOT" && TS2_COORDINATOR_DIRECTOR="$FAKE" "$PY" "../$COORD" --coordinator-root coord --state-root state "$@" ); }
log() { cat "$ROOT/coord/coordinator.log" 2>/dev/null; }
stateval() { "$PY" -c "import json;print(json.load(open('$ROOT/coord/state.json')).get('$1'))" 2>/dev/null; }
ncamp() { ls "$ROOT/coord/campaigns" 2>/dev/null | wc -l; }

# ---------------- fake director ----------------
cat > "$ROOT.fakedirector.py" <<'PYEOF'
import json, os, sys, time
args = sys.argv[1:]
def arg(name, default=None):
    return args[args.index(name)+1] if name in args else default
cid = arg("--campaign"); state_root = arg("--state-root", "state")
sdir = os.path.join(state_root, cid); lock = os.path.join(sdir, "director.lock")
logd = os.path.join(os.path.dirname(os.path.abspath(state_root)), "campaign-logs")
os.makedirs(logd, exist_ok=True)
logf = os.path.join(logd, f"director-{cid}.log")
def say(m):
    with open(logf, "a") as f: f.write(time.strftime("%H:%M:%SZ ") + m + "\n")
if "--stop" in args:
    own = json.load(open(os.path.join(lock, "owner.json")))
    say("STOP requested")
    try: os.kill(int(own["pid"]), 15)
    except Exception: pass
    sys.exit(0)
script = os.environ.get("TS2_FAKE_SCRIPT", "ok")
nfile = os.path.join(state_root, "fake-invocations")
n = int(open(nfile).read()) if os.path.exists(nfile) else 0
open(nfile, "w").write(str(n+1))
token = script.split(",")[min(n, len(script.split(","))-1)]
os.makedirs(lock, exist_ok=True)
with open(os.path.join(lock, "owner.tmp"), "w") as f:
    json.dump({"pid": os.getpid()}, f)
os.replace(os.path.join(lock, "owner.tmp"), os.path.join(lock, "owner.json"))
open(os.path.join(lock, "heartbeat"), "w").write(str(int(time.time())))
def ended(reason, detail): say(f"CAMPAIGN {cid} ended reason={reason} detail={detail}")
def receipt(commits):
    rd = os.path.join(sdir, "runs", "1"); os.makedirs(rd, exist_ok=True)
    json.dump({"progress": {"commits": commits}}, open(os.path.join(rd, "run.json"), "w"))
def bye(sig=None):
    ended("budget-runs", "fake budget exhausted"); raise SystemExit(0)
import signal; signal.signal(signal.SIGTERM, bye)
kind, _, secs = token.partition(":")
if kind == "hang":
    say("fake director hanging"); time.sleep(600); sys.exit(0)
if kind == "crash":
    say("fake director crashing without end record"); time.sleep(float(secs or 1)); sys.exit(1)
dur = float(secs or 2)
if kind == "ok": say("fake run"); time.sleep(dur); receipt(1); ended("budget-runs", "fake budget"); sys.exit(0)
if kind == "stagnant": say("fake stagnation"); time.sleep(dur); ended("human-blocker-provisioning", "fake blocker"); sys.exit(3)
if kind == "regression": say("fake regression"); time.sleep(dur); ended("test-regression", "fake failing check"); sys.exit(3)
if kind == "integrity": say("fake integrity"); time.sleep(dur); ended("integrity-violation", "protection moved"); sys.exit(4)
if kind == "infra": say("fake infra"); time.sleep(dur); ended("unsafe-infrastructure", "cannot observe loop"); sys.exit(5)
if kind == "stopped": say("fake manual stop at boundary"); time.sleep(dur); receipt(1); ended("manual-stop", "STOP file present at boundary"); sys.exit(3)
sys.exit(64)
PYEOF
mkdir -p "$BIN"; mv "$ROOT.fakedirector.py" "$BIN/fakedirector.py" 2>/dev/null || true
export TS2_COORDINATOR_DIRECTOR="$PY $BIN/fakedirector.py"

check() { local name="$1" cond="$2"; if eval "$cond"; then echo "PASS $name"; else echo "FAIL $name"; FAIL=1; fi; }

# ---- 1/2: normal completion + budget handoff, fresh IDs, explicit records ----
cleanup; fresh; TS2_FAKE_SCRIPT=ok,ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 2 --poll 1 --campaign-runs 1 >/dev/null 2>&1
rc=$?
check "1 completion continues (exit0, 2 campaigns)" \
  '[ "$rc" = 0 ] && [ "$(ncamp)" = 2 ] && [ "$(stateval state)" = trial-complete ]'
check "2 fresh campaign IDs + start/end records" \
  '[ "$(ls "$ROOT/coord/campaigns" | sort -u | wc -l)" = 2 ] && grep -q end_utc "$ROOT/coord/campaigns/"*.json'

# ---- 3: one stagnation -> continue with next objective ----
cleanup; fresh; TS2_FAKE_SCRIPT=stagnant,ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 2 --poll 1 >/dev/null 2>&1
check "3 stagnation then continue" \
  'log | grep -q "action=CONTINUE" && log | grep -q "stagnated" && [ "$(stateval state)" = trial-complete ]'

# ---- 4: consecutive stagnation -> stop and request intervention ----
cleanup; fresh; TS2_FAKE_SCRIPT=stagnant,stagnant timeout 180 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 9 --max-stagnation-streak 2 --poll 1 >/dev/null 2>&1
rc=$?
check "4 consecutive stagnation shutdown (exit3, stopped:blocker)" \
  '[ "$rc" = 3 ] && [ "$(stateval state)" = "stopped:blocker" ]'

# ---- 5: regression -> ONE repair campaign -> stop if it fails again ----
cleanup; fresh; TS2_FAKE_SCRIPT=regression,regression timeout 180 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 9 --poll 1 >/dev/null 2>&1
rc=$?
check "5 regression repair then stop (exit3, repair campaign seen)" \
  '[ "$rc" = 3 ] && [ "$(stateval state)" = "stopped:regression" ] && ls "$ROOT/coord/campaigns" | grep -q recomp-repair'

# ---- 6: integrity violation -> immediate stop, never bypass ----
cleanup; fresh; TS2_FAKE_SCRIPT=integrity timeout 60 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 9 --poll 1 >/dev/null 2>&1
rc=$?
check "6 integrity shutdown (exit4, stopped:integrity)" \
  '[ "$rc" = 4 ] && [ "$(stateval state)" = "stopped:integrity" ]'

# ---- 7: coordinator kill -9 -> restart adopts live director (no duplicate) ----
cleanup; fresh; TS2_FAKE_SCRIPT=hang,ok,ok timeout 300 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1 &
CPID=$!; sleep 4
DPID=$(ls -d "$ROOT/state"/recomp-auto*/director.lock 2>/dev/null | head -1 | xargs -I{} "$PY" -c "import json;print(json.load(open('{}/owner.json'))['pid'])")
kill -9 $CPID 2>/dev/null
for p in /proc/[0-9]*; do cwd=$(readlink "$p/cwd" 2>/dev/null); c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); case "${cwd:-} ${c:-}" in *coord-selftest*) case "$c" in *campaign-coordinator*) kill -9 "${p#/proc/}" 2>/dev/null;; esac;; esac; done
wait $CPID 2>/dev/null
sleep 1
timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" --state-root "$ROOT/state" \
  --max-campaigns 1 --poll 1 >/dev/null 2>&1 &
CPID2=$!; sleep 3
kill -TERM $DPID 2>/dev/null   # simulate worker/director ending while coordinator was blind
wait $CPID2; rc=$?
check "7 coordinator restart adopts live director, no duplicate" \
  'log | grep -q "START" && [ "$(grep -c LAUNCH <(log))" -le 2 ] && [ "$(stateval state)" = trial-complete ] && ! grep -qE "State:[[:space:]]*[RSDT]" /proc/$DPID/status 2>/dev/null'

# ---- 8: director crash without end record -> bounded resume, no unbounded loop ----
cleanup; fresh; TS2_FAKE_SCRIPT=crash:1,ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1
check "8 crash resume once then continue" \
  'log | grep -q "action=RESUME" && [ "$(stateval state)" = trial-complete ]'

# ---- 9: duplicate coordinator rejection ----
cleanup; fresh; TS2_FAKE_SCRIPT=hang,ok timeout 60 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1 &
CPID=$!
sleep 3
timeout 20 "$PY" "$COORD" --coordinator-root "$ROOT/coord" --state-root "$ROOT/state" start >/dev/null 2>&1
rc=$?
kill -9 $CPID 2>/dev/null; wait 2>/dev/null
rm -f "$ROOT/coord/STOP"
check "9 duplicate coordinator refused (exit6)" '[ "$rc" = 6 ]'

# ---- 10: manual stop settles children and prevents relaunch until cleared ----
cleanup; fresh; TS2_FAKE_SCRIPT=hang,ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1 &
sleep 3
timeout 20 "$PY" "$COORD" --coordinator-root "$ROOT/coord" --state-root "$ROOT/state" stop --reason selftest >/dev/null 2>&1
wait $!; rc=$?
timeout 20 "$PY" "$COORD" --coordinator-root "$ROOT/coord" --state-root "$ROOT/state" start >/dev/null 2>&1
rc2=$?
timeout 20 "$PY" "$COORD" --coordinator-root "$ROOT/coord" --state-root "$ROOT/state" clear-stop >/dev/null 2>&1
check "10 manual stop sticky (coordinator exit0, relaunch refused 6, clear-stop ok)" \
  '[ "$rc" = 0 ] && [ "$rc2" = 6 ] && [ "$(stateval state)" = stopped-manual ] && [ ! -f "$ROOT/coord/STOP" ]'

# ---- 11: corrupted state file preserved and reinitialized ----
cleanup; fresh; TS2_FAKE_SCRIPT=ok timeout 60 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1
echo '{corrupt' > "$ROOT/coord/state.json"
TS2_FAKE_SCRIPT=ok timeout 60 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1
check "11 corrupt state preserved + recovered" \
  'ls "$ROOT/coord" | grep -q "state.json.corrupt" && log | grep -q CORRUPT'

# ---- 12: infra failure -> bounded resume then stop if repeated ----
cleanup; fresh; TS2_FAKE_SCRIPT=infra,infra,infra timeout 180 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 9 --max-infra-retries 1 --poll 1 >/dev/null 2>&1
rc=$?
check "12 infra retries bounded then stop" \
  '[ "$rc" = 3 ] && [ "$(stateval state)" = "stopped:infra" ] && log | grep -q "action=RESUME"'

# ---- 13: expired deadline / trial-complete -> new start opens FRESH trial ----
cleanup; fresh; TS2_FAKE_SCRIPT=ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1
NC1=$(ncamp)
TS2_FAKE_SCRIPT=ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1
rc=$?
FUT=$("$PY" -c "import json,datetime;d=json.load(open('$ROOT/coord/state.json'));dl=datetime.datetime.strptime(d['trial_deadline_utc'],'%Y-%m-%dT%H:%M:%SZ');print(int(dl>datetime.datetime.utcnow()))")
check "13 expired/trial-complete start re-stamps fresh window + launches (rc0, FRESH-TRIAL, deadline future, campaign +1)" \
  '[ "$rc" = 0 ] && [ "$FUT" = 1 ] && log | grep -q FRESH-TRIAL && [ "$(ncamp)" = "$((NC1+1))" ] && log | grep -q LAUNCH'

# ---- 14: deadline still in the future -> plain start PRESERVES it; --force-new-trial re-stamps ----
cleanup; fresh; mkdir -p "$ROOT/coord"
"$PY" -c "import json,datetime;n=datetime.datetime.utcnow();json.dump({'schema':1,'trial_start_utc':n.strftime('%Y-%m-%dT%H:%M:%SZ'),'trial_deadline_utc':(n+datetime.timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),'history':[]}, open('$ROOT/coord/state.json','w'))"
DL_SEED=$("$PY" -c "import json;print(json.load(open('$ROOT/coord/state.json'))['trial_deadline_utc'])")
TS2_FAKE_SCRIPT=ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 >/dev/null 2>&1
DL_KEEP=$(stateval trial_deadline_utc)
TS2_FAKE_SCRIPT=ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 1 --poll 1 --force-new-trial >/dev/null 2>&1
DL_FORCE=$(stateval trial_deadline_utc)
check "14 live deadline preserved on plain start; --force-new-trial overrides" \
  '[ "$DL_KEEP" = "$DL_SEED" ] && [ "$(log | grep -c FRESH-TRIAL)" = 1 ] && [ "$DL_FORCE" != "$DL_SEED" ] && log | grep -q "forced override"'

# ---- 15: director manual-stop end-reason is classified, not STOP-UNKNOWN ----
cleanup; fresh
TS2_FAKE_SCRIPT=stopped,ok timeout 120 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 2 --poll 1 >/dev/null 2>&1
rc=$?
check "15 manual-stop end-reason -> CONTINUE (rc0, slot released, second campaign launched)" \
  '[ "$rc" = 0 ] && log | grep -q "prior manual stop honored" && ! (log | grep -q STOP-UNKNOWN) && [ "$(log | grep -c LAUNCH)" = 2 ]'

# ---- 16: a LEFTOVER stagnant campaign from the previous trial must not ----
# ---- charge the fresh trial's streak (2026-10-28 fleet-stop root cause) ----
# Repro of production 2026-10-28T09:01:40Z: fresh-trial reset the streak, then
# classifying dead auto40-s1's old human-blocker-provisioning record took it
# to 1, so the NEXT single stagnation stopped the fleet at 2. With the fix,
# one genuine stagnation after the pre-trial record continues (streak 1), and
# the trial completes rc 0. Without it this exits 3 stopped:blocker.
cleanup; fresh
"$PY" - "$ROOT/coord/state.json" "$ROOT/coord/campaigns/recomp-old-s0-pretrial.json" "$ROOT/state/recomp-old-s0-pretrial/director.lock/owner.json" "$ROOT/campaign-logs/director-recomp-old-s0-pretrial.log" <<'PYEOF'
import json, os, sys, datetime
state_f, camp_f, owner_f, log_f = sys.argv[1:5]
n = datetime.datetime.now(datetime.timezone.utc)
os.makedirs(os.path.dirname(state_f), exist_ok=True)
os.makedirs(os.path.dirname(camp_f), exist_ok=True)
os.makedirs(os.path.dirname(owner_f), exist_ok=True)
os.makedirs(os.path.dirname(log_f), exist_ok=True)
json.dump({"schema": 1,
           "trial_start_utc": n.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "trial_deadline_utc": (n + datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "history": [], "active_campaign": None, "streak_stagnation": 0,
           "slots": {"0": "recomp-old-s0-pretrial"}}, open(state_f, "w"))
json.dump({"campaign": "recomp-old-s0-pretrial", "objective": "startup-path",
           "start_utc": (n - datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "end_utc": None, "reason": None, "detail": None, "exit_code": None},
          open(camp_f, "w"))
json.dump({"pid": 999999}, open(owner_f, "w"))
open(log_f, "w").write("00:00:00Z CAMPAIGN recomp-old-s0-pretrial ended reason=human-blocker-provisioning detail=stale blocker from dead trial\n")
PYEOF
TS2_FAKE_SCRIPT=stagnant,ok timeout 180 "$PY" "$COORD" --coordinator-root "$ROOT/coord" \
  --state-root "$ROOT/state" --max-campaigns 2 --max-stagnation-streak 2 --poll 1 >/dev/null 2>&1
rc=$?
check "16 pre-trial stagnant record: streak NOT charged, one fresh stagnation still continues (rc0)" \
  '[ "$rc" = 0 ] && [ "$(stateval state)" = trial-complete ] && log | grep -q "pre-trial record" && log | grep -q "streak not charged" && [ "$(log | grep -c action=CONTINUE)" -ge 2 ]'

# ---- 17: director-run-fault helper — provider outage on every iteration is ----
# ---- infrastructure, NOT worker stagnation; mixed/behaved runs stay clean ----
FIX="$ROOT/fault-fixtures.jsonl"
cat > "$FIX" <<'EOF'
{"iteration":1,"status":"error","loopToken":"tokfault-1","rpcTelemetry":{"error":"Model request failed: Codex error: The usage limit has been reached"}}
{"iteration":2,"status":"error","loopToken":"tokfault-1","rpcTelemetry":{"error":"Model request failed: Codex error: The usage limit has been reached"}}
{"iteration":3,"status":"error","loopToken":"tokfault-1","rpcTelemetry":{"error":"your authentication token has expired"}}
{"iteration":1,"status":"error","loopToken":"tokmixed-1","rpcTelemetry":{"error":"Model request failed: Codex error: The usage limit has been reached"}}
{"iteration":2,"status":"complete","loopToken":"tokmixed-1","rpcTelemetry":{}}
{"iteration":1,"status":"error","loopToken":"tokreal-1","rpcTelemetry":{"error":"agent produced no commit"}}
{"iteration":2,"status":"error","loopToken":"tokreal-1","rpcTelemetry":{"error":"agent produced no commit"}}
{"iteration":1,"status":"error","loopToken":"toksingle-1","rpcTelemetry":{"error":"usage limit"}}
{"iteration":1,"status":"error","loopToken":"toklocal-1","rpcTelemetry":{"error":"Model request failed: flashnext error: Upstream provider error 429 Too Many Requests: rate limit exceeded, retry after 60s"}}
{"iteration":2,"status":"error","loopToken":"toklocal-1","rpcTelemetry":{"error":"Model request failed: flashnext error: 503 model temporarily unavailable"}}
{"iteration":3,"status":"error","loopToken":"toklocal-1","rpcTelemetry":{"error":"Failed to send set_model command: unable to connect to 172.17.0.1:18020 — unauthorized (invalid api key)"}}
EOF
F1=$("$PY" scripts/campaign/director-run-fault.py "$FIX" tokfault | head -c 5)
F2=$("$PY" scripts/campaign/director-run-fault.py "$FIX" tokmixed)
F3=$("$PY" scripts/campaign/director-run-fault.py "$FIX" tokreal)
F4=$("$PY" scripts/campaign/director-run-fault.py "$FIX" toksingle)
F5=$("$PY" scripts/campaign/director-run-fault.py /nonexistent/x.jsonl tokany)
check "17 provider-fault classifier: all-fault run=fault; behaved/other-error/1-iter/missing=clean (fail-closed)" \
  '[ "$F1" = fault ] && [ "$F2" = clean ] && [ "$F3" = clean ] && [ "$F4" = clean ] && [ "$F5" = clean ]'

# ---- 18: the classifier must be PROVIDER-AGNOSTIC. Overnight workers now run ----
# ---- on local Strata Qwen (flashnext/swift-1.5-iq3_xxs, pinned 2026-10-30 in ----
# ---- worker-env.sh / budgeted-supervisor.sh), so production fault lines read ----
# ---- "flashnext error: 429/503 …", not "Codex error". A flashnext-flavoured ----
# ---- all-fault run must still classify as infrastructure. ----
F6=$("$PY" scripts/campaign/director-run-fault.py "$FIX" toklocal | head -c 5)
check "18 flashnext-flavoured provider outage classifies fault (provider-agnostic since 2026-10-30 model switch)" \
  '[ "$F6" = fault ]'

echo; [ "$FAIL" = 0 ] && echo "SELFTEST: ALL PASS" || echo "SELFTEST: FAILURES"
exit $FAIL
