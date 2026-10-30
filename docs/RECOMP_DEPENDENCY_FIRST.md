# Dependency-first recompilation: unblock one real caller

Written 2026-10-24 ~04:55Z on owner instruction. Supersedes the measurement-first
priority in `tasks/android-phase1/RALPH.md` **at the next campaign boundary** — no
worker was interrupted and no campaign infrastructure was modified to produce it.

Owner directive, verbatim intent: prioritise *unblocking execution of one currently
unsupported original function* (e.g. `0x1ABD40`) over further repeated measurements of
already-verified leaves; identify the exact missing dependency or ABI contract, establish
its original x86 behaviour where possible, implement the smallest correct supporting
runtime capability, and show measurable progress toward executing it on both native
targets. No fabricated game behaviour, no weakened gates. Progress is tracked by
**newly resolved dependencies, newly executable original behaviour, and runtime
integration** — not artifact counts or repeated green tests.

## 1. The exact blocker, already established by the previous campaign

`work/recomp-bench/run5-057-cache-contract.json` (schema `ts2-cache-contract-preflight/1`)
analysed `0x1ABD40` statically against the authorised analysis image
(`63a545db…`): 88 bytes, 22 instructions, 1 basic block, no indirect calls, no absolute
memory operands. Its contract, recovered from operands (hypothesis until executed):

* receiver in `ECX`, saved to `ESI`; handle read at `[receiver+0x34]`, no null guard;
* five direct calls, arguments pushed before each, **caller** cleans 20 bytes (cdecl-ish);
* results written to `[receiver+0x80 … 0x90]`;
* result `AL = (cache[0x80] != 0)`, upper EAX retains the fifth callee's result.

Its five callees and their status:

| callee | native body | host cases | AArch64 cases | source of evidence |
| --- | --- | --- | --- | --- |
| `0x1240` | yes | 96/96 | 96/96 | `work/interop-legacy-002/group-reference.json` (96 states, sha `5fabc47a…`) |
| `0x1250` | yes | 96/96 | 96/96 | same |
| `0x1270` | yes | 96/96 | 96/96 | same |
| **`0x1290`** | **no** | — | — | `missing_catalog_callee_rvas` |
| **`0x12d0`** | **no** | — | — | `missing_catalog_callee_rvas` |

`coverage.reason`: *"No composed caller reference; unselected callees cannot be silently
translated"*, and its limits list *"Need separate scoped approval for 1290/12D0 before
native-body closure"*. The workers stopped there **correctly**: the campaign's selection
was bounded to 25 sampled functions (`scripts/recomp/select_candidates.py`,
`MAX_FUNCTIONS = 25`) and those two were not in it.

So the missing capability is **not** an unsolved translation problem and **not** an ABI
mystery. It is:

1. **Two missing leaf bodies** (`0x1290`, `0x12d0`) — the same 16-byte-stride neighbourhood
   as the three verified leaves, liftable by the already-pinned pipeline
   (`work/interop-legacy-002/pcrecomp/tools/lift/lift32.py`, `lift32_cpu.py`).
2. **One composed x86 reference for the caller** — the existing 96-state catalogs are
   per-leaf; there is no reference for `0x1ABD40` executing with all five leaves live.
3. **Caller-context binding in the guest harness** — a receiver object with a plausible
   `[+0x34]` handle and `+0x80…0x90` slots inside `GuestMemory`, so the caller runs against
   real callee behaviour instead of an authored response. The previous rig's note
   *"ABI rig uses authored resolver/guard/storage responses, NOT Windows services"* names
   exactly this shortcut; it stays a shortcut, clearly labelled, never a pass.

## 2. Authorisation for this closure (owner directive, 2026-10-24)

The owner's instruction to prioritise unblocking `0x1ABD40` **authorises the dependency
closure of that one caller**: lifting and executing `0x1290` and `0x12d0`, and composing a
reference for `0x1ABD40`. Bounds, unchanged in kind:

* read-only analysis of the already-authorised analysis image (`63a545db…`); the original
  protected executable is never modified, never run, never shipped;
* the 25-function *sampling* bound for the pricing survey stays intact — the closure
  enters as an explicit caller-closure list, so the survey's statistics are not silently
  widened. Record it as `caller_closure: [0x1abd40, 0x1240, 0x1250, 0x1270, 0x1290, 0x12d0]`;
* no DRM/authentication work, no redistribution, nothing leaves ignored `work/` paths
  except non-proprietary summaries.

If a further callee outside this closure turns out to be required, **stop and record it**
rather than expanding scope silently; that is a new bounded decision.

## 3. Milestones (each is a separately verifiable increment)

| # | Milestone | Evidence that counts | Does **not** count |
| --- | --- | --- | --- |
| M1 | `0x1290` and `0x12d0` have native bodies | fresh lift (self-contained, `lift` step exits 0 without reusing a previous source), per-leaf x86 differential cases, same cases re-executed under `scripts/campaign/arm64-run.sh` with `arm64_executed: true` | re-measuring an already-lifted leaf; host-only matches |
| M2 | composed x86 reference for `0x1ABD40` | original caller + all five live leaves executed under the scoped x86 dispatch with a receiver object in `GuestMemory`; final GPRs + full touched pages captured; reference sha pinned | authored/expected outputs written by the harness |
| M3 | `0x1ABD40` executes on both targets | whole-caller lift compiled host + `-target aarch64-linux-musl -static`, run natively and under qemu-aarch64, diffed against the M2 reference; both `matched` recorded | compiling without executing; qemu counted as Android |
| M4 | runtime integration | the caller's five-slot cache write is observable in the guest image after execution and is asserted by a test that would fail on a wrong slot order or wrong cleanup bytes | a test that only checks the harness ran |

`android_executed` is expected to stay **false** for all of this: qemu-aarch64 is a native
AArch64 CPU, not a phone. No claim of Android execution without a real device.

## 4. Metrics (replaces artifact counting)

Report, per iteration and per run:

1. **dependencies newly resolved** — callee RVAs that gained a native body this run (M1-class);
2. **original behaviour newly executable** — RVAs that gained their first executed
   differential comparison on either ISA (M2/M3-class);
3. **runtime integration depth** — whether the behaviour runs against live guest state
   (receiver object, real callees) rather than authored responses;
4. **ISA coverage of the target** — host / AArch64 / Android, reported separately, never merged.

Artifact counts, repeat green runs of an unchanged rig, and further statistics over the
25-leaf survey are **explicitly demoted** to context, not progress. The previous campaign's
last two runs each ended on the no-progress guard after producing artifacts without a new
executable behaviour; that is the pattern this replaces.

## 5. Anti-churn rule

If **three consecutive iterations** produce no new resolved dependency, no newly executable
behaviour, and no new evidence that changes the hypothesis, do not run the same experiment
again. Instead: name the hypothesis that failed and the evidence that killed it, demote the
current approach, and take the next distinct approach from this ordered list —

1. lift the two missing leaves from the pinned source with the proven pipeline (M1);
2. if the lift of a leaf fails, capture the *instruction-level* reason (opcode, operand
   form) that the lifter cannot express, and extend the lifter for that one construct;
3. if lifting works but the composed reference cannot be built, the gap is caller-context
   binding in the guest harness — implement the receiver-object binding next;
4. if the composed reference builds but the lifted caller mismatches, diff the first
   divergent state (register or page byte) and treat that single divergence as the bug;
5. only if all four are exhausted, record the closure as blocked with the exact missing
   capability, and pick a different caller from the selection whose closure is smaller.

Every iteration must add one fact, one exclusion, or one artifact of the above classes.

## 6. Unchanged prohibitions

Never weaken a test or gate; `scripts/phase1-acceptance.sh` keeps exiting 78 until an
independently owned validator exists. Never edit `scripts/campaign/**` while a loop is
live. No fabricated game behaviour presented as a result — any deliberate stand-in callee
is labelled `stub: true` in its artifact and never contributes to a "matched" count for
the function under test. Original bytes, disassembly dumps and decompiler output stay in
ignored `work/` paths. Never amend, rebase or force-push published history.

## 7. Closure decision after the probe (owner, 2026-10-24 09:30Z)

The bounded read-only producer probe authorized above §1 was executed. It resolved the
`0x1290`/`0x12d0` indirect edge to a **static target** (full evidence:
[OBJECT_QUERY_CALLER.md](OBJECT_QUERY_CALLER.md)): both producers store the same thunk VA
`0xA000FCF0`, whose 8 bytes set `arg0 := 0xA0E17AB0` and tail-jump to the leaf at RVA
`0x9550`. The "unresolved nested service contract" is therefore no longer a blocker; it is
an implementation input.

Owner decision recorded here, superseding the stop clause of §2 for exactly these edges:
the caller-closure list becomes
`[0x1abd40, 0x1240, 0x1250, 0x1270, 0x1290, 0x12d0, 0xfcf0, 0x9550]`
— `0xfcf0` (thunk) and `0x9550` (leaf) enter as *verified static targets of the closure's
own indirect edges*, not as new sampling. Dispatch to `0xA000FCF0` must stay exact-VA and
fail-closed; no stub, labelled or otherwise, is authorized on these edges, and M1–M4 in §3
are unchanged apart from this list. The unresolved items listed in
[OBJECT_QUERY_CALLER.md](OBJECT_QUERY_CALLER.md) ("still unknown") remain out of scope and
must be recorded, not assumed, if a milestone touches them.
