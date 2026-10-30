# AGENTS.md — Contributing to the Sims 2 native Android port

## What this project is

A **from-the-executable-up native port of the original PC The Sims 2** (initial target:
Steam Legacy Collection `1.18.0.187`) to Android ARM64. No emulation, no Wine/Box86, no
Winlator: original x86 behaviour is being **reverse-engineered by semantics, re-implemented
cleanly, and proven** — every function must be byte-identical against the original
binary's executed behaviour on real x86 and AArch64 before it counts.

It is **not yet a bootable or playable game.** The Android app in this repo is a diagnostic
shell. Progress is measured in verified functions, not vibes — see `docs/VERIFIED_LEDGER.md`
for what is actually proven and at what confidence tier.

## Before you write any code

Read, in order:

1. `README.md` — build commands and prerequisites.
2. `docs/ROADMAP.md` and `docs/ARCHITECTURE.md` — where this is going and why it's shaped like this.
3. `docs/VERIFICATION.md` — what counts as evidence. This is the law.
4. `docs/VERIFIED_LEDGER.md` — what is already proven. **Never re-prove or overwrite someone else's row.**
5. `docs/EXPERIMENT_LOG.md` — evidence archive of past experiments (read when
   your function touches an area already probed; not a setup doc).

Core documents to respect but not necessarily re-read per change:
`docs/LOCAL_VALIDATION.md`, `docs/OBJECT_QUERY_CALLER.md`,
`docs/RESOURCE_PRECEDENCE.md`, `docs/GHIDRA_WORKFLOW.md`.

## Source readability is a feature (read this twice)

The recompiled engine is meant to be **read, understood and modified by humans** — for
mod-making, debugging, and future engine work, not just for passing tests. Reconstructed
code is a first-class engine codebase, not a scratchpad:

- **Name things after what they mean.** Use recovered semantics (`GetObjectFlags`, not `sub_10A0`). If the meaning isn't recovered yet, the function stays `fun_<rva>` — renaming it *is* recovery work.
- **Cite your receipts in comments.** One line above each re-implemented function: original RVA, evidence pointer (ledger row / PR / receipt path), and behavioural caveats ("path-bounded: only the non-null branch is proven").
- **Idiomatic C++ over transliterated assembly.** Express the *behaviour*, not the register dance. A reviewer must be able to reason about the code without opening a disassembler. Clever macro or goto tricks that mirror x86 quirks are rejected on sight; a comment explaining a quirk is welcome.
- **Small functions, plain control flow, no premature cleverness.** Where the original relies on a compiler artifact (MSVC codegen quirks, hand-rolled SEH frames), isolate it in a small, clearly-labelled adapter marked `HYPOTHESIS:`/`PROVEN:` rather than weaving it through game logic.
- **Comments explain why, docs explain what.** Anything a future modder could get wrong (calling conventions, ownership of guest pointers, tier limitations) gets written down *now*, while you remember.
- A PR that passes every differential but reads like obfuscated assembly will be sent back. **Correct-but-illegible is a failure state in this project.**

## Hardware: what you can usefully contribute with

| You have | Useful work |
|---|---|
| Any x86 PC (CPU only) | Differential harness runs, host validation (`scripts/test-host.sh`), harness/test authoring, Ghidra static analysis, docs |
| 8–12 GB VRAM (e.g. RTX 3070) | All of the above, plus a *helper* LLM (≈14B Q4 class) for drafting — helper output is never accepted as proof; a human reviews before committing |
| ARM64 device + ADB | AArch64 execution arms of the differential rig — genuinely scarce and very welcome |
| Big GPU / API tokens | Long-running analysis agents. Useful, but never bypass the verification rules below |

You do **not** need a GPU or the game's private binaries to start: harness work, tests,
docs and static analysis all run from a plain clone.

## How work is divided (no toe-stepping, by construction)

Work units are individual original functions, addressed by RVA (e.g. `0x1AB665`).

1. **Pick** an unclaimed function: skip anything in `docs/VERIFIED_LEDGER.md` (proven) and
   anything listed on the live claims board (issue #1 / open `claim` issues). Early-game
   candidates are small leaf functions: thunks, getters/setters, tiny helpers.
2. **Claim** it: open an issue titled `Claim <RVA>: <short description>` with the `claim`
   label. First open claim wins; the board is regenerated every 30 minutes. Close your
   issue when your function merges or you abandon it.
3. **Work** on a branch named `recomp/<rva>-<short-name>` (e.g. `recomp/0x10A0-field-reader`).
   One function per branch; stay inside your work's blast radius.
4. **Prove** it: your PR contains the executed evidence — x86 reference run, host run, and
   (for full-tier) AArch64 run — with receipts under the paths described in
   `docs/VERIFICATION.md`. A PR that renames a function is documentation; a PR that
   *claims verification* without receipts will be closed with extreme prejudice.
5. **Merge**: a maintainer reviews, re-runs your receipts, then merges your ledger row
   and closes your claim issue. Tiers are assigned by the reviewer, not the author —
   down-tiering is normal and not an insult.

If you're stuck for more than a few hours, open a draft PR with `BLOCKED:` and exact
evidence of what failed. A precise dead end is worth three vague successes.

## Non-negotiables

- **Never weaken, skip, or special-case a gate or test to make it pass.** Missing/skipped tests are not passes. Faked progress ends participation in this project.
- **The original PE, recovered analysis images, compiled original functions, game resources, saves, credentials and device-identifying logs are private and stay out of Git**, releases, CI, PRs, issues and agent transcripts, permanently. A fresh clone lacking private fixtures is expected — do not invent fixtures.
- **No DRM/authentication bypass. No modifying an owner's installation, running a modified recovered PE, or redistributing copyrighted original code or assets.** Do not broaden sensitive recovery operations without a separate, lawful, scoped decision.
- Never edit `docs/VERIFIED_LEDGER.md` rows you didn't earn, acceptance scripts under `scripts/`, or CI configuration.
- Never push to `main` or force-push anything. Branch + PR, always.
- Pseudocode is hypothesis. Ghidra/decompiler/LLM output is hypothesis. Only executed differentials are evidence. Do not call a diagnostic APK or a green CI build "Phase 1 complete" — acceptance runs `scripts/phase1-acceptance.sh`.

## Machine heartbeat (optional, appreciated)

Contributor machines that run long jobs should heartbeat the public progress board so the
dashboard can show who is doing what:

`POST https://sims2-api.galdrakarl.is/api/worker`

```json
{"worker": "<your-machine-name>", "worker_key": "*** from the owner>",
 "task": "recomp/0x10A0", "model": "local-14b", "gpu": "RTX 3070",
 "iterations": 12, "verified": 2}
```

Every ≤30 minutes while active. This publishes only those fields — post no logs, paths, or
device identifiers. Ask the owner for a `worker_key`.

## Baseline checks before requesting review

```bash
scripts/test-host.sh
```

With JDK 17+ and the pinned Android SDK/NDK:

```bash
scripts/build-android.sh --no-daemon
```

## Working rules (maintainers and autonomous campaign agents)

Human contributors: skim this too — it explains why reviews ask what they ask.

- **Preserve the existing implementation.** Prefer bounded static recompilation plus portable guest/runtime services; investigate a major architectural switch before making one. No Wine/Winlator/Box86 or runtime x86 emulation in the shipped game.
- Existing code/test results validate diagnostic Android execution, selected reconstructed functions, and resource decoding. They do **not** validate the original game's startup, real menu, renderer or simulation.
- Set up and reuse **Ghidra headless** as the persistent, targeted reverse-engineering index for the authorized private Legacy analysis image; see `docs/GHIDRA_WORKFLOW.md`. Never infer correct executable behavior from decompiler pseudocode alone; retain pinned pcrecomp and independent x86/ARM64 comparisons.
- Use small changes with explicit hypotheses and independent comparison against trusted x86 reference behavior where available.
- Phase 1 is an Android **gameplay** smoke test on a compatible emulator or physical device; no device must remain connected for routine work. The current Gradle app packages ARM64 only. Controller-only gameplay is a **later phase**.
- Work on a dedicated branch/worktree. Commit reviewable tested changes; do not automatically push/force-push, publish proprietary artifacts or mutate unrelated host services.
- Maintain concise durable progress and known failures. If blocked, specify what failed, exact evidence, and the next plausible experiment. Never fake progress, alter acceptance criteria, or silently remove unresolved P0/P1 questions.
- Autonomous agents contributing to this project follow exactly these rules: the same ledger, claim, proof and readability standards as human contributors, and coordinators list their held RVAs in claim PRs. Record disagreements between older and newer findings and resolve them by evidence rather than silently rewriting history.

Questions live in the project Discord (#🔷sims-2-recomp).
