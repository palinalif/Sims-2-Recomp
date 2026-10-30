# External reference — Chickenrikke, "I Reverse-Engineered The Sims 2's Code"

Video (YouTube): <https://www.youtube.com/watch?v=bvvuZNxl26k>
(Owner-supplied pointer, recorded 2026-10-29 during the overnight campaign shift.)

Why it matters to us: the analysed target described in the video is the
**original 2008 pre-encryption community build** of the same executable we
recompile. That makes his Ghidra decompilation **directly comparable to our
static-recompilation catalogue** function-for-function — an independent,
externally-produced second opinion on decompiled bodies and identifier
recovery, produced without the Steam Legacy encryption layer in the way.

## Externally-verified facts relevant to our recompile

1. **Comparable target.** His build predates the community-patch encryption
   change, so plain code and strings are present; his decompilation can be
   lined up against our catalogue entries for the same functions without
   accounting for an encryption/obfuscation delta.

2. **Naming-recovery trick (cheap identifier recovery).** Plain-text
   tuning-file setting names sit in the binary **adjacent to the code that
   loads them**. Correlating a global against nearby tuning-file setting
   names recovers function/field identifiers cheaply — no live debugging
   required. This is a direct fit for our factory-globals and
   factory-families objectives, which are global-naming problems.

3. **Free-will goal planner semantics (verified by him with live-game
   values).** Goal options are **scored**, **attenuation is applied**, and
   then the **first option passing the checks wins — there is no
   randomness**. The apparent dice-roll is an artifact: the roll-range
   constant `10` is **overridden to `1` by tuning**, i.e. a "one-sided
   die". Selection is therefore **pure argmax with tie broken by option
   order**. Any recompiled planner family (and `obj_goalworker` /
   free-will scoring) must reproduce deterministic first-pass-wins
   selection, not a weighted random draw.

4. **Walkthrough evidence.** He walks a **109-byte scoring function** and
   shows **virtual-call patterns that confirm C++ class layout** (vtable
   entry offsets) — usable as corroboration for our own vtable-adjacent
   global naming rules (see `scripts/recomp/VTABLE_ADJACENT_GLOBALS.md`).

## Handling rules (unchanged by this reference)

* Facts recorded here are **externally claimed**, not yet independently
  reproduced inside this project. They steer *where to look and what
  hypothesis to test*; they are not receipts. A recompile decision citing
  this file still needs our own differential/runtime evidence per
  `docs/VERIFICATION.md`.
* The video is third-party commentary; do **not** import its decompiled
  code as an implementation source — recompiled functions stay derived from
  our own authorized analysis-image work (AGENTS.md input rules).
