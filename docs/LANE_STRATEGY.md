# Lane strategy: what the fleet does all day (FAST FORWARD deliverable E)

Status: **strategy synthesis** (2026-10-27), owned by the main agent. Inputs:
`docs/HYBRID_EXECUTION_FEASIBILITY.md` (deliverable D, the executor question),
`docs/STARTUP_CRITPATH.md` (deliverable C, the Lane A graph),
`work/campaign-logs/recompilation-pricing-20261024.md` (the cost model, measured),
factory v1/v1.1/v1.2 measurements in `work/recomp-bench/factory-run-*`, and four days of
coordinator/campaign receipts under `work/campaigns/` and `work/coordinator/`.

This document decides **what the two parallel lanes do** and **what we stop doing**. It
does not change the product architecture (that is deliverable D's question, answered:
keep static recompilation; see D §8.1) and it does not relax any gate.

## 1. The measured shape of the problem

- Verification, not translation, is the cost. Recompilation of a tractable function is
  minutes; the **rig** around it (fixtures, x86 reference, mutation controls, dual-ISA
  execution) measured 40–125 min per function and 23 bespoke rigs produced 46 ledger
  addresses (pricing report `:141-143`; `docs/VERIFIED_LEDGER.md`).
- The factory collapses the *rig* cost to seconds **on the classes it supports**
  (`scripts/verify-factory/`): batch runs of 70–90 candidates finish in ~10–15 minutes
  wall, and every acceptance keeps the full discipline (fresh Unicorn x86 reference,
  host + AArch64, mutation controls, byte pins).
- But the factory's support gate today **excludes calls entirely** — and the startup
  path, the actual critical path to a menu, is made of calls, services, and indirect
  edges. The factory is a Lane B amplifier, not a Lane A answer.
- Class census (43,730 records): thunk 223, leaf-getter 449, leaf-setter 908, small-leaf
  7,517, branchy 30,683, large 3,944. The easy classes are ~2,000 records ≈ **4 % of the
  image** — and the image is not the target; the *startup closure* is, and its size is
  still unknown (D §7.3: the single most valuable missing number in the project).

## 2. Lane A — critical path (mainline slot)

Mission: turn `docs/STARTUP_CRITPATH.md` from SEED into a graph whose frontier is
**services**, not unknowns.

1. **Pathfinder experiment (highest value, needs the one sign-off in D §9 note).** Drive
   the recovered startup prefix offline under the pinned Unicorn reference behind our own
   `GuestMemory`-shaped memory and fail-closed import policy. Deliverable: the two lists
   nobody has ever produced — distinct functions reached and distinct imports demanded,
   in order — written back into the critpath graph as confirmed edges. This is the T2
   measurement of D §8.3 and converts the roadmap from "unknown closure" to a number.
   This is *extended* differential execution of recovered code: bounded, private, ships
   nothing — but needs the owner's one-line acknowledgment that it falls inside the
   standing authorization's "bounded differential execution" (D §9).
2. **Quarantine mining (free, now).** Factory `unicorn-fault` quarantines are functions
   touching guest globals — i.e. real runtime-service dependencies. Each faulting VA is
   an edge candidate for the graph and a Lane B service request. The fleet already
   produces these daily; they must be triaged into the critpath file, not left in logs.
3. **Contract work on the spine** (existing init-chain discipline): lift → differential
   vs fresh x86 → host + AArch64 → receipt. Continues unchanged; the receipts are the
   bank.

Anti-pattern ban (unchanged): the fail-closed acceptance gate (exit 78) is never a
reason to stop dependency work.

## 3. Lane B — throughput (worktree slot)

Mission: keep the ledger growing at factory speed and keep the factory itself improving
against measured rejection tallies — never against anecdotes.

1. **factory-globals** (queued): read-only views of real image regions so the dominant
   quarantine class (global reads) becomes verified instead of quarantined.
2. **Class expansion by tally**: v1 added `imul/shl/shr/sar` after tallies showed ALU
   loss; v2 candidates by measured count: FPU/SSE (`movss`, `fnstcw`), then thunk
   `jmp`-tails. Each expansion keeps comparison set, controls, and pins untouched (only
   the case generator may change).
3. **abi-services** continues: every service the quarantine mining names is its queue.

## 4. What we stop doing

- Re-verifying ledger/banked functions (anti-churn list stands).
- Bespoke one-off rigs for anything the factory covers or can cover with one code
  change; bespoke rigs are now justified **only** for call-containing spine functions.
- Campaign templates with no concrete artifact list (the `upward-graph`/`evidence-debt`
  stagnations were template failures, not worker failures).
- Lane convergence: both lanes must name disjoint artifact sets in their briefs (the
  2026-10-27 auto38 double-work on opener/realloc families is the cautionary receipt).

## 5. Coordination fixes this strategy depends on (all landed 2026-10-27)

- Coordinator drains pending merges before a no-work stop (pre-stop defer, max 3 polls).
- `strict_lane` objectives (need emulator/adb) only dispatch to mainline.
- Zero-commit budget-exhausted campaigns are stagnation, not completion.
- Unmerged lane branches (`coord/*`) are durable and reconcile manually when they
  conflict; conflict-prone families must be named in briefs as belonging to one lane.

## 6. Two-week success test (falsifiable)

- Lane A: critpath graph states a closure size (a number) and an ordered import list;
  otherwise the pathfinder attempt is written up as a negative result with evidence.
- Lane B: strict-ledger total grows by ≥30 T1 addresses through factory paths alone;
  quarantine tally published before/after each factory change.
- Fleet: ≥10 legitimate commits per 4h window on average while objectives are open;
  a coordinator exit that leaves unmerged lane commits is a bug and gets fixed same day.

## 7. Explicit non-claims

Nothing here claims gameplay, a real menu, or Phase 1 progress; the acceptance gate
stays closed at 78 until the trusted independent validator runs. Function counts in the
ledger are verification evidence, not proximity to a playable game.
