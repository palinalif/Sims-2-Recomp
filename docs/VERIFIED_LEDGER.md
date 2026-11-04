# VERIFIED_LEDGER — strict-tier verification ledger

Snapshot: branch `campaign/pi-ghidra-ralph`, HEAD `220cc51` (2026-10-26). One row per
function address, placed in the **highest tier its cited evidence literally claims**.
Generated 2026-10-26 from committed records (`git log`, `docs/VERIFICATION.md`,
the project status archive (private record), the Phase 1 report (private record)) and from the
private gitignored receipt tree `work/recomp-bench/`. Nothing here was built, run,
committed or pushed by this pass; no gate was changed.

## Tier definitions (as used below)

| Tier | Literal requirement |
|---|---|
| **T1** | x86-reference matched **and** executed on host **and** executed on AArch64, **and** the record literally asserts whole-function verification (receipt field `whole_function_verified: true`, or a doc record that pins the whole function byte range and reports the full-function match) |
| **T2** | x86-reference matched, **host execution only** (no AArch64 execution recorded) |
| **T3** | Recorded claim that is partial, path-bounded, fragment/closure/boundary-contract, or compared against an authored model / oracle rather than a whole-function x86 differential — even when it ran on both ISAs |

> **Policy update (2026-11-04):** ARM64/AArch64 execution is retired from the
> tier requirements as of the port-deferral decision. Going forward **T1 =
> whole-function differential proof against the x86 reference** (host or
> emulated execution), and T2 collapses into it; the AArch64 clause in the
> table above applies only to rows earned before this date. No existing row
> is promoted or demoted by this change — the tier column records the
> evidence as earned.

Classification rules applied, and why some rows are lower than their commit subject sounds:

1. A receipt was credited only for what its JSON literally says (`runs.*.executed`,
   `runs.*.matched`, `whole_function_verified`, `stub`, and the named `x86_*` /
   `*_contract_matches` / `original_x86_cases` counters).
2. Where evidence was ambiguous — no `whole_function_verified` field, coverage below
   `total`, "fragment", "boundary", "skip path", "predicted caller frame",
   "authored … APIs", "normalised-cookie oracle" — the address was **dropped to the lower
   tier**, per the strict-tier instruction.
3. `docs/LOCAL_VALIDATION.md`, `docs/OBJECT_QUERY_CALLER.md` and the 2026-10-22/23
   `Verify … ABI` / `Measure …` commits describing **authored service contracts** (PTD
   cleanup, resolver, lock adapter, HeapFree wrappers, etc.) are **out of scope**: they are
   not RVA-addressed original-function differentials. They remain tracked where they live.
4. Every address appears once (highest tier). Superseded attempts are named in the notes.

Meaning of "AArch64" per row: for the 2026-10-21 owner-local rows it is a physical ARM64
Android phone over strict USB-ADB; for `work/recomp-bench` rows it is a native Linux/AArch64
execution (NDK-built or QEMU-aarch64). `android_executed` is `false` in every
`work/recomp-bench` artifact; the first real Android-package runtime execution is recorded
separately in `d644b20` (KVM emulator + `ndk_translation`) and is not per-function proof.

## T1 — whole-function x86 match + host + AArch64 (11 addresses)

| Address | Name / role | Tier | Evidence pointer | Date |
|---|---|---|---|---|
| `0x1070` | 19-byte original object-field helper (recovered caller `0x1AB6C7`) | T1 | `docs/VERIFICATION.md` §"Approved private recovery…", §"Owner-local device and second-function follow-up"; `c78642b`; private bundle output `work/android-arm64-probe/` | 2026-10-21 |
| `0x1240` | startup object-query leaf (three-function group contract) | T1 | `docs/VERIFICATION.md` §"Approved read-only object-query group"; `work/interop-legacy-002/group-bundle/results-03597cf7f40747e2adfd03bb1543f7a3/`; fresh re-measure `work/recomp-bench/run5-054-group-final/result.json` (`286fef6`, 2026-10-24) | 2026-10-21 |
| `0x1250` | 27-byte startup object-query leaf | T1 | `docs/VERIFICATION.md` §"Owner-local device and second-function follow-up" (host 64/64) and §"Approved read-only object-query group" (device 96/96); also `run5-054-group-final`, `run5-053-wrappers-final` | 2026-10-21 |
| `0x1270` | startup object-query leaf (group member) | T1 | same as `0x1240` | 2026-10-21 |
| `0x1AB770` | 28-byte cache wrapper over `0x1250` | T1 | `docs/VERIFICATION.md` §"Cache-wrapper follow-up"; `work/interop-legacy-002/wrapper-bundle/results-ad1bcc650fbc4953b51ccdc76054a0fc/`; `work/recomp-bench/run5-053-wrappers-final/result.json` (`23d43d2`) | 2026-10-21 |
| `0x1AB78C` | 28-byte cache wrapper over `0x1270` | T1 | same as `0x1AB770` | 2026-10-21 |
| `0x1A00` | opener buffer zero-init dependency (`initialization_zero_init_1A00`) | T1 | `work/recomp-bench/iter19-buffer-init/result.json` (`whole_function_verified: true`, host 64/64, arm64 64/64) + `slot9-zero16-final/result.json`; `a0624c3` | 2026-10-26 |
| `0x1A40` | opener zero-init dependency (`initialization_zero_init_1A40`) | T1 | `work/recomp-bench/slot9-zero-init-final/result.json` (whole, host 64/64, arm64 64/64); `8969743` | 2026-10-25 |
| `0x2570` | composed opener initializer (`opener_initializer_2570`, 31/31 blocks) | T1 | `work/recomp-bench/slot9-initializer-final/result.json` + `iter20-opener-verified/result.json` (both whole, 64/64 each ISA); `d759593` | 2026-10-26 |
| `0x102D0` | reflection service size-query dependency | T1 | `work/recomp-bench/size102d0-final/result.json`, `size102d0-audited/result.json` (whole, 64/64 each ISA); `89cceb5` | 2026-10-25 |
| `0x8437C6` | allocator policy / value-query dependency | T1 | `work/recomp-bench/allocator-policy-first/result.json` (whole, 64/64 each ISA, 4 rejecting controls); `52eb892` | 2026-10-26 |

T1 caveats (they do not lower the tier, but they bound it):
- The 2026-10-21-era device rows compared 8 final GPRs + defined flags + stack + tracked
  memory pages against **saved Unicorn x86-32 states**, not a second native x86 run;
  `0x1240`/`0x1270` are verified only inside the three-function group artifact — no single
  artifact records both ISAs for them individually (the project status archive (private record)
  §Pricing checkpoint).
- The five campaign receipts are global/state-word fixtures: their own `limits` say
  "no flags/FP/PC/native transient-write comparison" and "diagnostic
  GuestMemory/exact-VA bridge; no production binding". Whole-function **within that
  fixture**, not game-lifetime proof. `android_executed: false`.

## T2 — host-only x86 match (0 addresses)

No address lands in T2. Every `work/recomp-bench` artifact that records an x86-reference
match on the host also records AArch64 execution for the same case set, and the only two
host-only artifacts are earlier attempts for addresses already listed at T1:

- `work/recomp-bench/auto15-s1-i3-retry-query/result.json` — `0x8437C6`, host 64/64, no
  AArch64 run (2026-10-26) → superseded by `allocator-policy-first`.
- `work/recomp-bench/slot9-zero-init-first/result.json` — `0x1A40`, host 64/64, no AArch64
  run (2026-10-25) → superseded by `slot9-zero-init-final`.
- Historical (superseded) host-only stages are also recorded in `docs/VERIFICATION.md`:
  `0x1250` "had not run on ARM64 at that stage", and `0x1070`'s AArch64 PIE was built but
  not device-executed before `d644b20`-era phone runs.

## T3 — partial / path-bounded / fragment / model-oracle claims (35 addresses)

| Address | Name / role | Tier | Evidence pointer | Date |
|---|---|---|---|---|
| `0x1030` | initialization association helper | T3 | `2b5d7f2` + `work/recomp-bench/association-e6-final/result.json` | 2026-10-24 |
| `0x1090` | initialization callback setter (first) | T3 | `eaea6bc` + `setter-e4-final/result.json` | 2026-10-24 |
| `0x10A0` | second initialization callback setter | T3 | `44e4543` + `setter-e5-final/result.json` | 2026-10-24 |
| `0x10B0` | initialization callback setter | T3 | `a18f9ba` + `setter-e14-final/result.json` | 2026-10-24 |
| `0x10C0` | paired initialization callback setter | T3 | `06099bc` + `paired-e8-final/result.json` | 2026-10-24 |
| `0x10E0` | dual-effect initialization setter | T3 | `357c628` + `dual-e7-final/result.json` | 2026-10-24 |
| `0x1100` | initialization callback setter | T3 | `3938da6` + `setter-e9-final/result.json` | 2026-10-24 |
| `0x1110` | reflection + callback setter | T3 | `f38d961` + `setter-e10-final/result.json` | 2026-10-24 |
| `0x1120` | initialization callback setter | T3 | `785a798` + `setter-e11-final/result.json` | 2026-10-24 |
| `0x1130` | initialization callback setter | T3 | `4beeede` + `setter-e12-final/result.json` | 2026-10-24 |
| `0x1140` | initialization status setter | T3 | `02dcc25` + `setter-e13-final/result.json` | 2026-10-24 |
| `0x1290` | cache accessor — **skip path only** (indirect `[S+0x34]` edge unresolved) | T3 | `b1df7f2` + `closure-c1-final-1290/result.json` (host 64/64, arm64 64/64); the project status archive (private record) §Campaign B | 2026-10-24 |
| `0x12D0` | cache accessor — **skip path only** | T3 | `b1df7f2` + `closure-c1-final-12d0/result.json` | 2026-10-24 |
| `0x1460` | service guard: null-service return fragment + nonnull first-input boundary | T3 | `4177c12`, `cec01d9` + `service1460-final/result.json`, `service-input-final/result.json` (coverage 13/82 blocks) | 2026-10-25 |
| `0x1AF0` | capacity prefix at default allocator boundary | T3 | `work/recomp-bench/capacity-prefix-verified/result.json` (`boundary_contract_matches: 64`, **no host/AArch64 execution recorded**); measuring commit `3e69e34` | 2026-10-26 |
| `0x20D0` | bounded composition of the two real producers (coverage 119/191 blocks) | T3 | `63d42f0`, `284fdba` + `caller20d0-final/result.json`, `input20d0-field-final/result.json` | 2026-10-25 |
| `0x26B0` | handle-input publication helper (writer side) | T3 | `dd2807e` + `handle-input-first/result.json` (`whole_function_verified: false`) | 2026-10-25 |
| `0x2790` | handle-input publication writer | T3 | `dd2807e` + `handle-input-first/result.json` | 2026-10-25 |
| `0x9550` | standalone text leaf incl. invalid-byte arm (49/49 blocks) | T3 | `eab04f6` + `leaf-d1/result.json` (no `whole_function_verified` field; leaf child of `0xFCF0`) | 2026-10-24 |
| `0xFCB0` | module compare / classifier dependency | T3 | `1c25989` + `g1-fcb0-final/result.json` | 2026-10-25 |
| `0xFCF0` | standalone text thunk through the real leaf | T3 | `e504b28` + `thunk-d2/result.json` | 2026-10-24 |
| `0x10700` | initialization classifier — bounded EDI-zero path, then composed scan | T3 | `ae3a5a4`, `8a04344` + `classifier-e16-corrected/result.json`, `g2-scan-verified/result.json` (coverage 4/21 → 44/47) | 2026-10-24/25 |
| `0x10960` | initialization descriptor | T3 | `54aee23` + `descriptor-e15-corrected/result.json` | 2026-10-24 |
| `0x109D0` | initialization producer — real classifier zero path + scan | T3 | `3e8aa70`, `2754dbe` + `producer-e17-corrected/result.json`, `producer-scan-final/result.json` | 2026-10-24/25 |
| `0x10B60` | alternate producer with real classifier closure | T3 | `8e524ef` + `alternate20d0-first/result.json` | 2026-10-25 |
| `0x1AB665` | populated initialization guard **fragment** (coverage 10/83) | T3 | `66a12fa` + `guard-f2-corrected/result.json` (`whole_function_verified: false`, `e3_fragment: true`) | 2026-10-25 |
| `0x1ABD40` | cache caller — composed closure through real guest memory | T3 | `f9f4212` + `closure-c4-poststate/result.json` (closure, not standalone function; 135/136 blocks) | 2026-10-24 |
| `0x8248A3` | startup entry verified to a strict external-tail reference boundary | T3 | `bddd6d7`, `2a3deb7` (no `work/recomp-bench` artifact for it remains) | 2026-10-23 |
| `0x82585C` | startup pair member through decoded call-return ABI seam | T3 | `ce3e914`, `439c4a3` + `work/recomp-bench/run5-009-native/result.json` (320/320 host + arm64; `limits`: "authored deterministic APIs, not Windows", "no final flags/ECX/EDX/FP") | 2026-10-23 |
| `0x8258A9` | startup pair member (same rig) | T3 | `ce3e914` + `run5-009-native/result.json` | 2026-10-23 |
| `0x825BB0` | startup entry through persistent image dispatch | T3 | `734f869` + `run5-022-native-final/result.json` (64/64 both ISAs; `limits`: "caller prefix reference only, NOT translated", "helper model/guard share Capstone") | 2026-10-23 |
| `0x82A47B` | original resource leaf against caller-produced frames | T3 | `e1d89c4`; counted in the project status archive (private record) §Pricing checkpoint (no artifact for it remains under `work/recomp-bench/`) | 2026-10-23 |
| `0x831A6F` | default-allocator success tail through the lifted heap path | T3 | `220cc51` + `work/recomp-bench/default-success-first/result.json` (`whole_function_verified: false`, coverage 26/37) | 2026-10-26 |
| `0x8461F2` | original allocator success path with explicit portable heap boundary | T3 | `b5ff28f` + `heap-success-final/result.json` (`whole_function_verified: false`, coverage 21/32) | 2026-10-26 |
| `0x85217F` | realloc pre-call entry — partial contract only | T3 | no commit; `work/recomp-bench/auto15-s1-i2-realloc-final/result.json`, `auto15-s1-i2-realloc-v2/result.json` (`matched_partial_contract: 128`, no `runs.*.executed`) | 2026-10-26 |

T3 caveats common to the whole block: entry states are synthetic; producers/callees often
not executed; comparisons cover 8 final GPRs plus four 4096-byte pages (or EAX /
non-volatile / SP only); flags, FP/SIMD, native PC and transient writes are not compared;
`android_executed` is `false` in every artifact. Two rows (`0x8248A3`, `0x82A47B`) rest on
committed records whose private artifacts are no longer on disk — they are kept because the
claims are literal in commit messages/docs, and flagged as artifact-lossy.

## Appendix — index hint, unvalidated (no tier)

`work/ghidra-index/triage.json` (`sims2-frontier-triage/1`) carries a
`verified_hint` field per candidate class: **742 hints** over 43,724 index records
(thunk 66, leaf-getter 9, leaf-setter 13, small-leaf 105, branchy 529, large 20; 6 bad
lines skipped). **These are index hints only** — they are not evidence of execution,
matching or whole-function status, and no address is listed here from them. The related
claim that a 132-function selection exists could not be reproduced from any file on disk
(no `work/recomp-inventory-20261023/`), so it is not treated as evidence either.

## Counts

| Tier | Addresses |
|---|---|
| T1 | 11 |
| T2 | 0 |
| T3 | 35 |
| **Total unique addresses** | **46** |

Denominator for context, not progress: 43,724 index records / 44,151 image functions
(the project status archive (private record)). 46/44,151 ≈ 0.10 %. Nothing in this ledger
constitutes Phase 1 acceptance; `scripts/phase1-acceptance.sh` remains the only gate and
was not run by this pass.
