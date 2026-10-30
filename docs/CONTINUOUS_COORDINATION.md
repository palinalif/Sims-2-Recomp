# Continuous Campaign Coordination

The coordinator is the always-on layer **above** the campaign director. It
never runs workers, never edits protected files, and never weakens a gate. It
decides only *when* a bounded campaign runs, *which objective* it pursues, and
*whether durable history permits continuation*. Every campaign it launches is
still bounded by the director/supervisor budgets below.

## Hierarchy

```
campaign-coordinator (always-on, restartable, sticky-stop)
  └─ campaign-director (per campaign: 4h / 3 runs, verifies between runs)
       └─ budgeted-supervisor (per run: 50 iterations / 75 min)
            └─ pi --mode rpc Ralph iteration
```

## Commands

```bash
scripts/campaign/campaign-coordinator.sh start \
  --trial-hours 48 --max-campaigns 12 \
  --campaign-hours 4 --campaign-runs 3 --campaign-run-minutes 75 \
  --max-stagnation-streak 2 --repair-campaigns 1 --max-infra-retries 2 \
  --poll 60 --min-disk-gb 20 --directive-writeback

scripts/campaign/campaign-coordinator.sh status    # JSON state + liveness
scripts/campaign/campaign-coordinator.sh report    # markdown campaign history
scripts/campaign/campaign-coordinator.sh stop --reason "text"   # sticky
scripts/campaign/campaign-coordinator.sh clear-stop             # re-arm
```

Run it detached so it survives the launching shell:

```bash
setsid nohup scripts/campaign/campaign-coordinator.sh start ... \
  >> work/coordinator/coordinator.out 2>&1 < /dev/null &
```

## Behaviour (verified by `scripts/campaign/coordinator-selftest.sh`)

| Situation | Coordinator action |
|---|---|
| Campaign ends on budget (runs/wall) | objective recorded done, next objective, fresh campaign |
| One stagnation / human-blocker stop | objective marked blocked, continue with next |
| Stagnant run whose EVERY iteration died at the model/provider layer (usage limit, rate limit, auth expiry) | director ends the campaign `unsafe-infrastructure` (bounded resume via infra retries) — never charged to the stagnation streak, never blocks the objective (`scripts/campaign/director-run-fault.py`) |
| Leftover stagnant campaign from a PREVIOUS trial classified after a fresh trial opened | CONTINUE without charging the new trial's streak ("pre-trial record; streak not charged") |
| 2 consecutive stagnations | exit 3, state `stopped:blocker` — request intervention |
| Test regression | ONE repair campaign; if it regresses again exit 3 `stopped:regression` |
| Integrity violation | immediate exit 4 `stopped:integrity` — never bypassed |
| Infrastructure failure | bounded resumes (`--max-infra-retries`), then exit 3 |
| Ralph mission-complete | objective closed, continue to next (Phase 1 acceptance still gates "complete") |
| Live campaign already owned (e.g. relaunch) | ADOPT it — never double-launch workers |
| Coordinator killed / host restart | restart re-acquires stale lock, adopts live director, resumes from `state.json` |
| Duplicate coordinator | refused, exit 6 |
| Manual `stop` | settles active campaign via director `--stop`, sticky until `clear-stop` |
| Corrupted `state.json` | preserved as `.corrupt-*`, rebuilt from per-campaign records |
| Disk < `--min-disk-gb` or load > 2.5×CPUs | new launches blocked (active campaign untouched) |

## Durable records (all under ignored `work/`)

- `work/coordinator/state.json` — atomic state machine (tmp+rename+fsync)
- `work/coordinator/coordinator.log` — append-only UTC decision log
- `work/coordinator/campaigns/<id>.json` — explicit start/end record per campaign
- `work/coordinator/coordinator.lock/` — owner.json + heartbeat (stale takeover)
- `work/coordinator/STOP` — sticky manual stop
- `work/coordinator/OBJECTIVE.md` — objective text handed to the next campaign
- `work/coordinator/objective-queue.json` — optional ordered queue
  (`[{"id": "...", "status": "open|done|blocked", "brief": "..."}]`);
  falls back to the built-in chain: batch-verify-easy → init-chain →
  abi-services → upward-graph → android-native → evidence-debt.

## Throughput infrastructure (added 2026-10-25)

- `scripts/ghidra/Sims2IndexDump.java` + `scripts/ghidra-index-dump.sh` — one
  headless pass over the ENTIRE analysis image (43,730 functions) writing
  `work/ghidra-index/functions.jsonl`: pseudocode, callers/callees, size class,
  x86 disassembly per function. Replaces the old ~45-second-per-address Ghidra
  query for routine work (targeted queries remain for hard functions).
  Append-only with cursor; re-runnable after image changes. Output is
  proprietary — stays under ignored `work/`.
- `scripts/frontier-triage.py` — classifies the index and emits
  `work/ghidra-index/triage.json`: functions already called from
  promoted/hosted code are auto-promoted (3,660 found) and everything is cut
  into ~100-function verification batches (413 batches; thunks, leaf
  getters/setters and small leaves first). Workers verify batch-by-batch
  instead of choosing targets by hand.
- Objective queue now leads with `batch-verify-easy`, a templated objective:
  verify every promoted function of one batch per iteration through the
  existing gates (host + AArch64 + x86 differential), no target-picking.

## Parallel mode (Tier 2)

`--parallel N` runs up to N campaigns concurrently. Slot 0 works on the
mainline branch; slots 1..N-1 get their own **git worktree** under
`--worktree-root` (outside the repo) on branch `coord/<campaign>`, sharing the
private `work/` tree via symlink (state, index and campaign state stay single
sources of truth). Objectives are disjoint by construction: one objective at a
time per id, and for batch objectives each slot takes batches with
`index ≡ slot (mod N)` and journals progress under
`work/coord-slots/slot-<n>-progress.json`.

Merge policy: a slot branch is merged (`--merge-on-green`, no-ff) **only** when
its campaign ended with verification passing; with `--post-merge-verify` the
mainline is re-verified after merge and the merge is reverted on failure.
Conflicts are never forced — the branch is preserved for manual review and the
slot continues. Stagnation and repair budgets remain global. Validated in the
selftest harness before production use; single-slot remains the default.

Objective-completion semantics tightened: only `budget-runs` or
`mission-complete` mark an objective done; a `budget-wall` end (possibly an
outage artifact) leaves it open for the queue to revisit.

## Restart survival

- **Pi session restart:** the coordinator is an OS process, not a Pi session;
  it keeps running. Scheduled reports are conveniences, not the engine.
- **Coordinator/container restart:** relaunch `start`; it takes over its stale
  lock, adopts any live director, and continues from `state.json`. A campaign
  interrupted mid-run is resumed once (director adopts the open run).
- **Unraid host restart:** nothing auto-starts (deliberate: no unattended
  boot-time execution). The owner (or a scheduled wake) must relaunch `start`;
  bounded campaigns already committed their work; state is durable.

## 48-hour supervised endurance trial

1. `scripts/campaign/coordinator-selftest.sh` must print `ALL PASS`.
2. Launch with the production flags above (trial deadline = start + 48h).
3. Check `status`/`report` every 8–12h; each check must read **actual process
   state** (`status` liveness fields, director logs, git commits, test runs) —
   a report file existing is never evidence the engine ran.
4. At deadline the coordinator settles the active campaign and exits
   `trial-complete`. Final recommendation is READY / NEEDS MORE TESTING /
   NOT READY based on: no integrity violations, no unresolved regressions,
   ≥1 real verified-function advance, restarts survived, gates intact
   (`phase1-acceptance.sh` still fail-closed at 78).

## Limits

- Never Phase 1 completion: only the trusted validator + real gameplay count.
- Never removes the human: `stopped:blocker|integrity|regression` all demand
  owner intervention; the sticky STOP requires a deliberate `clear-stop`.
- The coordinator adds capability, not permission: standing authorization
  (the owner standing authorization (private record)) and all repository rules apply unchanged.

## Shift bridge (`scripts/campaign/shift-watch.sh`)

An always-on watcher lets a remote shift manager (Hermes) start/stop/
query the fleet through a shared inbox without shell access.

- Inbox layout: `commands/*.sentinel` (in), `commands/done|rejected/`,
  `results/STATUS.json`, `results/REPORT.md`, `results/LAST-<VERB>.rc`.
- Every sentinel is line-authenticated: line 1 = token
  (`work/coordinator/shift-token`), line 2 = human reason. Wrong token
  ⇒ quarantined to `rejected/`.
- Launch: `SHIFT_REPO=<repo> SHIFT_INBOX=/data/shift SHIFT_TOKEN=$(cat
  work/coordinator/shift-token) setsid nohup scripts/campaign/shift-watch.sh &`
  (umask 022 so the shift manager can read results).

### START dispatch contract (fixed 2026-10-28)

The coordinator is an **always-on supervisor**: START must dispatch it
**detached** (`setsid nohup … &`), never under the watcher's
`timeout` — hosting it killed the fleet 10 minutes after every START.

`LAST-START.rc` semantics after the fix:

- `rc 0` = dispatched and **still alive 5 s later** (lock-owner
  fallback if `setsid` forked). It is NOT proof that campaigns run.
- Proof of life = `STATUS.json`/`coordinator.log` showing `state:
  running` plus a `LAUNCH` line newer than the sentinel. rc alone is
  never the proof.
- Coordinator exits that leave no live process (deadline, blocker,
  integrity) surface on the next STATUS/START, not as a START rc.

### End-reason classification note

A director campaign that ended `manual-stop` (previous session's
coordinator settle or `campaign-director.sh --stop`) classifies as
CONTINUE — the stop was already honored when it happened; a fresh
START means the operator wants work resumed (`5ed4175` follow-up).
Unrecognized reasons remain STOP-UNKNOWN by design.

## EXTERNAL REFERENCE — goal planner

`docs/external-reference-chickenrikke.md` (YouTube "I Reverse-Engineered
The Sims 2's Code", Chickenrikke) documents externally-verified facts on
the same 2008 pre-encryption build: tuning-name correlation recovers
identifiers cheaply (setting names sit in the binary next to the loading
code), and the free-will goal planner is deterministic — score,
attenuate, FIRST passing option wins (the dice-roll constant 10 is tuned
to 1: pure argmax, tie-by-order), with a 109-byte scoring function and
vtable-offset call patterns as layout evidence.
**Actionable for objective selection: prefer goal-planner/scoring-family
function families next, and try tuning-name correlation for identifier
recovery.** Treat the claims as hypotheses to reproduce with our own
receipts, not as receipts themselves.

