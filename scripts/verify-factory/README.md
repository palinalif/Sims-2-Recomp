# TS2 verification factory (v1)

Class-batched whole-function differential verification. Replaces the
one-rig-per-function pattern (23 bespoke rigs produced 46 ledger functions;
this pipeline produced its first verified function in < 2 minutes of
computation, no hand-written case code).

## What is trusted

Reference states come from executing the **original x86 bytes under Unicorn**,
fresh, on every run — never from the translation, never from saved states.
The lifted C (pinned pcrecomp, same revision/verification as every accepted
receipt) is only ever the **compared** side: 8 GPRs, 7 flags, byte-exact
guest-memory delta, x87 stack depth. Host x86_64 and AArch64 (musl-static,
`scripts/campaign/arm64-run.sh` QEMU) must produce byte-identical run output.
Every candidate additionally passes a **mutation control**: its lifted body is
perturbed and the harness must then FAIL — a harness that cannot fail is
discarded with the candidate.

Pins verified before every run: analysis image SHA-256 and the full pcrecomp
lock (`config/dependencies.lock.json`). Verdicts land in
`work/recomp-bench/factory-*/result.json` and machine rows append to
`work/ghidra-index/verified-ledger.jsonl`.

## Honest limits (v1)

- Support gate is deliberately narrow: full-window decode, `ret` terminator,
  no calls, conditional jumps only inside the function, ALU/mov whitelist.
  Rejection reasons are recorded per candidate (`rejected:<reason>`);
  `thunk` (jmp-tail) and virtual-dispatch classes are NOT supported yet.
- A candidate that faults under Unicorn (dereferences a pointer outside the
  scratch/stack windows) is **quarantined**, not forced through with stubs.
  Widening the case-value distribution is the known remedy.
- `--skip-arm64` receipts are labeled `host-only` and can never be T1.
- Tier mapping: verified-factory with arm64 == ledger T1 discipline
  (whole-function, x86-reference, host + AArch64). `android_executed` stays
  false: QEMU is not Android.

## Use

```sh
python3 scripts/verify-factory/factory.py --class leaf-getter --max 24
# classes come from work/ghidra-index/triage.json; ledger-covered RVAs are
# skipped automatically; output dir is auto-named under work/recomp-bench/.
```

## v1 measured (2026-10-26, batch of 12 head candidates, leaf-getter)

1 verified-factory end-to-end, 0 false acceptances, 6 honest rejections,
5 quarantines with recorded reasons; select+lift 0.0 s, Unicorn reference
0.17 s, compiles < 1 s each. Manual-rig equivalent cost: 40–65 minutes
(pricing doc 2026-10-24).
