# Existing-lift execution checkpoint

## Opener member initializer `0x122F0` — 2026-10-27

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 122F0 --instructions 12 --quiet
python3 scripts/recomp/execute_initialization_setter.py --rva 122f0 \
  --index work/ghidra/query-out/EXISTING-122F0.json.env.json \
  --output work/recomp-bench/NEW-opener-member
python3 -m unittest discover -s tests -p test_recomp_opener_member_init.py
```

Use the actual envelope path returned by the persistent query; never reimport.
The existing setter runner freshly lifts the complete 25-byte, five-site unit
called by `3A50`, executes 64 original-x86 cases, and requires an independent
full-state oracle before host/Linux-AArch64 comparison and two rejecting controls.
The receiver is the first stack argument. Its `+0` target address, `+8=0`, and
`+12=1` are initialized while `+4` is preserved. Four aligned receiver positions
include the page end. The address is stored as data only, never invoked; its
classification as a table is HYPOTHESIS.
No allocator/producer/lifetime, whole opener/1AB665, flags/FP/PC/transient-write,
production registration or Android claim. See task report for measured evidence.

## Owned-empty chunk realloc composition — 2026-10-26

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_capacity_reallocate.py \
  --indexes work/recomp-bench/capacity-compose-logs/indexes.json \
  --output work/recomp-bench/NEW-capacity-reallocate
python3 -m unittest discover -s tests -p test_recomp_capacity_reallocate.py -v
```

The private index manifest maps RVAs2790/26B0/1AF0/8413B0/85217F to existing
Ghidra envelopes. Reuse the first three from the capacity-growth manifest and
the last two from the standalone realloc receipt's recorded invocation. No
re-import or original bytes in Git. Explicit synthetic ownership: empty active
64-byte chunk plus blocking64-byte allocation; source lengths64–95. The writer
fills the old56-byte usable region before a120-byte moving realloc, then resumes
copying/NUL and rebases publication. Original x86 uses the independent occupancy/
copy model; native uses production GuestHeap. Unknown targets reject. Every
body is freshly lifted by pinned pcrecomp, never authored as a replacement.
The eight registered authored tests reject unchanged-old-payload, header/text/
publication, service-count/request and ABI corruption. See task PHASE1_REPORT.md
for the frozen-source differential receipt and full regression status. Synthetic
ownership is not original upstream producer/lifetime proof; no full allocator,
opener/1AB665, Windows heap execution or Android/gameplay claim.


## Spare chunk consumption (not realloc) — 2026-10-26, iteration5

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_capacity_reuse.py \
  --indexes work/recomp-bench/capacity-growth-logs/indexes.json \
  --output work/recomp-bench/NEW-capacity-reuse
python3 -m unittest discover -s tests -p test_recomp_capacity_reuse.py -v
```

Uses the existing five-entry private index manifest, fresh pinned lifts and
existing scenario runner. Two declared owned64-byte spares; no active chunk.
Descriptor+4 is a mapped spare-chain pointer, NOT an allocator selector. The
original composition consumes its head, clears the active link and publishes
text/cursors; all other bytes are checked. NoAllocation and native endpoint
reject any heap call. Original x86 contract64/64, host/Linux-AArch64 matches64/64
and result/cleanup controls reject64/64 each ISA. Service counts0/64 cases;
coverage63/231, with24/148 sites in1AF0 and no allocator sites executed. No upstream
producer/reset/lifetime, full capacity/opener/1AB665/E3/E4 or Android claim.
See PHASE1_REPORT.md for current-source pins, costs and next realloc hypothesis.

## Empty-descriptor capacity allocation composition — 2026-10-26

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_capacity_success.py \
  --indexes work/recomp-bench/capacity-success-logs/indexes.json \
  --output work/recomp-bench/NEW-capacity-success
python3 -m unittest discover -s tests -p test_recomp_capacity_success.py -v
```

Run the private comparison detached with timeout300 and redirected private logs.
`--indexes` is a private JSON object mapping hex RVAs to persistent Ghidra query
**envelope paths**. Required keys: `2790`, `26b0`, `1af0`, `831a6f`, `8461f2`.
Reuse existing queries; query absent entries narrowly, never re-import. Each
boundary is independently checked against pinned original bytes. Outputs must
be new directories under ignored work/. Public tests need no original image.

Fresh pcrecomp lifts all five bodies. Original x86 uses the independent portable
heap occupancy model; native host/AArch64 uses production GuestHeap through
GuestMemory/exact-VA GuestDispatch. This is NOT Windows HeapAlloc verification.
Only null default allocator and empty old descriptor/ownership fields execute:
one 1032-byte allocation, 8-byte linkage/capacity prefix, 1024 usable bytes.
The original caller publishes usable start at +8 and copies input including NUL.
Source text lives on a separate tracked page outside the exclusive heap arena;
old exploratory fixtures sharing the source/arena page are not ownership evidence.
No whole1AF0/26B0/openers/1AB665/E3/E4 or Android claim. Synthetic IAT/global/token
bindings are not upstream startup or ownership evidence.

The reference runner's opt-in `checked_repeat_copy` validates complete forward
REP MOVSB/MOVSD source/destination spans before execution. Zero count accesses
nothing; default callers still reject REP. Immutable writes, overflowing/crossing
spans, excessive counts, segment/address-size overrides and backward direction
reject. Generated bodies remain
verbatim. Wrong-result perturbs allocation; wrong-cleanup perturbs ONLY the
outer return ABI, so both are final-state behavioral controls. The attempted
inner-service cleanup control aborted without output; that attempt is retained
privately, not counted as a differential match or behavioral difference.

## Calloc successful tail composition — 2026-10-28

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_calloc_success.py \
  --index work/ghidra/query-out/849A00.20261028T090910Z.json.env.json \
  --wrapper-index work/ghidra/query-out/83A371.20261028T090748Z.json.env.json \
  --output work/recomp-bench/NEW-calloc-tail
"$PY" -m unittest discover -s tests -p test_recomp_calloc_success.py -v
```

Run long commands with bounded detached execution/private logs. Optional wrapper
mode freshly lifts83A371→849A00 and preserves both generated bodies and the
original return frame. Without --wrapper-index, isolated849A00 mode remains.
All outputs must be new/ignored/private; missing owner inputs fail closed.

`calloc-tail-first/result.json`:64 original-x86 independent-zeroing contracts,
64/64 host and64/64 Linux/AArch64 QEMU full eight-GPR/six-page matches. Two
controls each reject64/64 per ISA. Coverage33/44, thunk5/5;11 authored tests.
Explicit independent occupancy/zeroing MODEL vs production GuestHeap, NOT Windows
HeapAlloc. Synthetic global/IAT/token, no actual1820 creation, ownership, retry/
overflow/error, flags/FP/PC/native transient-store, E3/E4 or Android proof.
One newly executable success composition, zero all-path dependencies resolved.
Next actual caller-produced1820 creation; do not rerun isolated calloc/no-create.

## Actual default allocator successful tail composition — 2026-10-26

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_heap_success.py \
  --index work/recomp-bench/allocator-f1-logs/query.json.env.json \
  --wrapper-index work/ghidra/query-out/831A6F.20261026T163157Z.json.env.json \
  --output work/recomp-bench/NEW-default-success
python3 -m unittest discover -s tests -p test_recomp_default_allocator.py -v
```

Use exclusive private outputs and bounded detached jobs. Optional wrapper mode
freshly lifts actual831A6F(11B/5) plus8461F2(78B/32). The exact tail jump keeps
the original return frame; unknown pairs reject. Both generated bodies retained
verbatim. Existing non-wrapper mode remains supported. Seven new authored tests
are automatically discovered; no original fixture is required for public tests.

Receipt `default-success-first/result.json`:64/64 original-x86 service-contract,
64/64 host and64/64 Linux/AArch64 QEMU, all eight GPRs/six final pages;26/37
sites, wrapper5/5. Both service result/cleanup controls differ64/64 per ISA.
Reference3.291460s; fresh lifts0.000278s+0.000062s; six compile/execution pairs
38.924310s (warm local timings, not a whole-image estimate).

This is portable-service composition, NOT Windows HeapAlloc verification:
independent x86 occupancy model versus production GuestHeap. Fresh single
allocation/arena per case; synthetic immutable IAT/global/heap-token inputs.
No upstream initialization, retry/errno/exhaustion, full1AF0/26B0/openers,
flags/FP/PC/native transient-store/lifetime, whole1AB665/E3/E4 or Android proof.
One original success path newly executable, zero complete dependencies resolved.

## Real input writer, bounded capacity path — 2026-10-25

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_handle_input.py \
  --index-dir work/recomp-bench/handle-writers-checks \
  --buffer-index work/ghidra/query-out/26B0.20261025T203051Z.json.env.json \
  --output work/recomp-bench/NEW-handle-input
python3 -m unittest discover -s tests -p test_recomp_handle_input.py -v
```

Reuse2790 from the writer cache and the bounded persistent26B0 query above;
if absent, query26B0 with `--instructions 160 --quiet` (no re-import).
Run the private command detached with timeout600 and private logs per AGENTS.md.
Fresh pinned whole-body lifts2790/26B0; ONLY nonnull source and sufficient
capacity execute.64 cases compare eight final GPRs/six full pages to original
x86, host and Linux/AArch64 QEMU; publication/cleanup controls must differ on
both ISAs. No stub: unknown1AF0 call hard-fails. Independent oracle checks
result/nonvolatiles/SP/full non-stack memory. Coverage36/46; flags/FP/PC/native
transient writes, null/allocator/failure and lifetime are not verified.

H+D0 receives the old inline-descriptor cursor after a NUL-inclusive input copy;
both cursor fields advance. This is a measured input-ownership-path increment,
not full20D0/1460/1AB665, E3/E4 registration or Android evidence. Two new native
bodies, zero fully resolved dependencies. Receipt `handle-input-first/result.json`
and complete reproduction/limits in task-local PHASE1_REPORT.md.

## Dependency-directed input writers — 2026-10-25

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/inspect_handle_writers.py \
  --index-dir work/recomp-bench/handle-writers-checks \
  --output work/recomp-bench/NEW-handle-writers
python3 -m unittest discover -s tests -p test_recomp_handle_writers.py -v
```

The private cache contains `<rva>.json.env.json` for20D0,2120,2790,3A50,3C50,
62B0,62F0. Populate from existing bounded persistent queries, not whole-image
JSONL. Query missing entries with `scripts/ghidra-query.sh --rva <rva>
--instructions 256 --refs 8 --callers 8 --callees 16 --out <cache>/<rva>.json
--quiet`; serialize queries and bound the job. Exact initial cache provenance is
in PHASE1_REPORT.md iteration8. Image hash, complete instruction boundaries and
current helper/source pins are retained in the receipt. Exclusive private output.
Static explicit-store candidates only; calls kill all constants and joins retain
only agreeing values. No runtime ABI/object identity/lifetime or absence proof.
Seven bodies/413 instructions/eight candidate stores;2790 exposes a separateD0
mutation path with real26B0 dependency. No new verified translation or execution.
---

## Composed opener initializer 2570 — 2026-10-26, iteration20

`execute_opener_init.py` freshly lifts2570 and actual1A40/1A00, with pinned
image/upstream/body/index/template/bridge/artifact hashes. No generated body
is committed or manually replaced. All31 sites visited; original-x86/full
oracle64/64, host64/64, Linux/AArch64 QEMU64/64. Eight GPRs/six pages including
nested return-slot residue. Both wrong-field/cleanup controls differ64/64 per
ISA. `android_executed=false`, no allocator/callback/lifetime or whole-opener
claim. EDX receiver116-byte span zeroed except word+84=1; EAX1/ECX0/SP+4.
The six direct return PCs are decoded independently and enforced by an ordered,
per-case-reset transport sequence (five calls share one target).

```sh
. scripts/campaign/worker-env.sh
# Existing persistent query copied into iter20-logs/2570.json.env.json;
# leaf envelopes reused from iter19-logs and slot9-checks.
python3 scripts/recomp/execute_opener_init.py \
  --index-dir work/recomp-bench/iter20-logs \
  --output work/recomp-bench/NEW-opener-init
python3 -m unittest discover -s tests -p test_recomp_opener_init.py
```

Exclusive output must be a new ignored directory. Actual receipt:
`work/recomp-bench/iter20-opener-verified/result.json`. Eight registered public
checks use authored states/bodies only; they are not counted as translations.
Next dependency-directed step: full26B0/1AF0 allocation path, not repeat2570.

## Opener dependency 1A00 — 2026-10-25, iteration19

The initialization-unit rig also accepts pinned `1A00` (14 bytes/six sites),
the next recorded dependency behind `2570`. It freshly lifts the original body;
the authored oracle requires exactly16 bytes zeroed through incoming EAX,
ECX=0, ESP+=4 and all remaining tracked state preserved. This is intentionally
different from `1A40`'s20-byte receiver. Six registered public tests check the
span, exact dispatch, malformed frames, neighboring bytes and rejecting controls.

```sh
. scripts/campaign/worker-env.sh
# Reuse this envelope after its first bounded persistent-index query:
scripts/ghidra-query.sh --rva 1a00 --instructions 80 --refs 8 --callers 8 --callees 8 \
  --out work/recomp-bench/iter19-logs/1a00.json --quiet
python3 scripts/recomp/execute_initialization_setter.py --rva 1a00 \
  --index work/recomp-bench/iter19-logs/1a00.json.env.json \
  --output work/recomp-bench/NEW-buffer-init
python3 -m unittest discover -s tests -p test_recomp_buffer_zero_init.py -v
```

Receipt `work/recomp-bench/iter19-buffer-init/result.json`: original x86/oracle,
host and Linux/AArch64 QEMU each64/64; six/six sites; result and cleanup
controls differ64/64 on each ISA. Eight final GPRs and six full pages compared;
no flags/FP/PC/native transient writes, lifetime/invalid-pointer proof,
whole2570/openers/1AB665, production registration or Android execution.

## Opener dependency 1A40 — 2026-10-25

The existing initialization-unit rig now admits the pinned 17-byte/seven-site
`1A40` dependency of `3A50`. Its independent contract
uses an EAX receiver, clears exactly 20 bytes, sets ECX=0 and returns with
ESP+=4; the other GPRs and all other tracked memory must remain unchanged.
No hand-written native replacement is used. The body is freshly lifted by
pinned pcrecomp and retained privately. Public tests exercise the authored
oracle, exact dispatch, receiver bounds and strict comparison, not game bytes.

```sh
. scripts/campaign/worker-env.sh
# For nested coordinator worktrees, set TOOLS_ROOT, DEV_TOOLS and
# TS2_HOST_TOOLCHAIN to the actual operator tools BEFORE sourcing above.
export TS2_HOST_TOOLS="$TOOLS_ROOT"  # existing QEMU root, not an Android OS
python3 scripts/recomp/execute_initialization_setter.py --rva 1a40 \
  --index work/recomp-bench/slot9-checks/1a40.json.env.json \
  --output work/recomp-bench/NEW-opener-zero-init
python3 -m unittest discover -s tests -p test_recomp_opener_zero_init.py -v
```

If the cached envelope is absent, query the existing persistent project once:
`scripts/ghidra-query.sh --rva 1a40 --instructions 32 --refs 8 --callers 8 --callees 8
--out work/recomp-bench/slot9-checks/1a40.json --quiet`.
The rig requires 64/64 original-x86/independent-oracle matches and 64/64
host plus Linux/AArch64-QEMU matches (eight final GPRs/six full pages).
Result/cleanup controls must each produce 64 actual divergences per ISA;
malformed/rejected execution is not a behavioral control success. Four aligned
receiver positions include the exact page-end 20-byte span. No flags, FP,
native store ordering, allocation/lifetime, whole-opener, production binding
or Android execution is established. Receipt and regression results are in
`tasks/android-phase1/PHASE1_REPORT.md`, slot9 iteration1.

## 1460 nonnull first-call ABI prefix — 2026-10-25

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/probe_service_input.py \
  --index work/ghidra/query-out/1460.20261025T192348Z.json.env.json \
  --output work/recomp-bench/NEW-service-input
python3 -m unittest discover -s tests -p test_recomp_service_input.py -v
```

Reuses the pinned persistent1460 query; no convenience JSONL index required.
64 original-x86 prefixes stop BEFORE indirect14B7, including a bounded forward
REP STOSD. Eight GPRs and both complete stack/receiver pages match an independent
boundary oracle; target/order/frame/fill mutations must reject64/64 each.
Seven skip-free public tests include authored REP/call fixtures proving unmapped
callees are never entered, invalid ranges/code identities/budgets reject, and
full boundary state is compared. Inputs use four unmapped marker targets, not
resolved service bodies or authored response stubs. Arguments are [H+E0], incoming
stack arg0, local1024-byte0xFF buffer; H=ESI, target=[H+74], ESP delta=-1068.
No callee response, cleanup, lift, native/AArch64/Android execution, flags/FP,
whole1460/20D0 or production integration is claimed. Detailed sanitized receipt:
PHASE1_REPORT.md iteration6. Do not repeat the settled prefix as a new milestone.

## 102D0 direct dependency — 2026-10-25

`execute_initialization_setter.py --rva 102D0` adds a pinned profile to the
existing lift/x86/GuestMemory/exact-VA two-ISA rig, not a hand-written native
replacement. Reuse the persistent read-only index:

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_initialization_setter.py --rva 102D0 \
  --index work/ghidra/query-out/102D0.20261025T193339Z.json.env.json \
  --output work/recomp-bench/NEW-size102d0
python3 -m unittest discover -s tests -p test_recomp_service_size.py -v
```

The six-byte/two-instruction whole body returns1912, preserves other GPRs
except ESP+=4, and leaves all six tracked pages unchanged.64 cases compare
original x86 with an independent full-state oracle, then freshly lifted native
host and Linux/AArch64 execution; result/cleanup controls must differ on each
ISA. Only this exact target is bound. The size/allocation interpretation is a
HYPOTHESIS; no allocator, nonnull1460, whole20D0, production registration or
Android evidence is implied. Flags/FP/PC/transient writes are not compared.
Public authored tests are registered through normal unittest discovery.
Private receipts and regression evidence: task-local PHASE1_REPORT.md.

## 1460 null-provider fragment — 2026-10-25

`execute_service_guard.py` freshly lifts the complete 279-byte/82-instruction
body, but verifies ONLY `[ESI+0x74] == 0`. ESI is the receiver here (unlike
20D0's incoming EAX); the observed return is EAX=18, EDX=0, ESP+=4, other
GPRs preserved. All non-stack bytes remain unchanged; two saved-register stack
words remain observable. This does not establish what the status means.
HYPOTHESIS: +74 supplies a provider callback; its nonnull identity/ABI is unverified.

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_service_guard.py \
  --index work/ghidra/query-out/1460.20261025T192348Z.json.env.json \
  --output work/recomp-bench/NEW-service1460
python3 -m unittest discover -s tests -p test_recomp_service_guard.py -v
```

Reuse the existing persistent-query envelope; query1460 only if it is missing.
Run the private job detached with a real timeout per AGENTS.md. Original-x86
states plus an independent full final-state oracle are compared to host and
Linux/AArch64 QEMU:64/64 each, all eight GPRs/six full pages. Result and cleanup
controls each differ64/64 per ISA; six public authored tests are discovered by
`scripts/test-host.sh`. The full generated body is retained verbatim. Only1460
is registered; both direct callees and all indirect calls fail closed if reached.

Coverage13/82, zero calls. The REP STOSD/nonzero-provider path, callbacks, heap,
whole20D0/1AB665, ownership, flags/FP/PC/native transient writes, production E4
and Android execution are NOT verified. No fully resolved dependency is counted;
this adds first-executed null-provider behavior, not a whole-function claim.

## Alternate producer10B60 — 2026-10-25

The existing classifier/producer pipeline now accepts exactly `--producer-rva
10b60` as well as its unchanged109D0 default. This is a fresh generated body,
not a hand-written producer replacement. All body/state/binary outputs stay
private; use the bounded detached execution contract for the following job:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 10B60 --instructions 100 --quiet
python3 scripts/recomp/execute_classifier_scan.py \
  --producer-rva 10b60 \
  --producer-index work/ghidra/query-out/10B60.20261025T192426Z.json.env.json \
  --index work/recomp-bench/g2-scan-logs/query.json.env.json \
  --compare-index work/recomp-bench/g1-fcb0-logs/query.json.env.json \
  --output work/recomp-bench/NEW-alternate
python3 -m unittest discover -s tests -p test_recomp_alternate_producer.py -v
```

Use your returned query path. Existing classifier/comparator envelopes and the
hash-pinned private image/upstream are required; absence fails, never skips.
Receipt `work/recomp-bench/alternate20d0-first/result.json`:64/64 host and64/64
Linux/AArch64 QEMU matches against fresh original-x86 states, all eight final
GPRs/six complete pages.18/18 producer instructions covered,21/21 classifier,
23/26 comparator. Result and cleanup controls each differ64/64 per ISA.
Five registered authored tests cover both producer profiles, callback/class/
publication state, failure retention, exact dispatch and strict comparisons.

Synthetic inline storage/valid strings only. Callback addresses are stored,
not invoked; flags/FP/PC/native transient writes, incoming caller ownership,
whole20D0/1460, whole1AB665 and E3/E4 remain unverified. Android execution false.

## 20D0 producer-input boundary — 2026-10-25

`probe_producer_input.py` executes only the original x86 prefix, stopping BEFORE
its first CALL. It does not supply a callee response, lift a body, or execute
native code. All code/state outputs remain private. Run long jobs using the
bounded detached worker path:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 20D0 --instructions 100 --quiet
python3 scripts/recomp/probe_producer_input.py \
  --index work/ghidra/query-out/20D0.20261025T191152Z.json.env.json \
  --output work/recomp-bench/NEW-input20d0
python3 -m unittest discover -s tests -p test_recomp_producer_input.py -v
```

Use the envelope path returned by your query. The receipt compares all26 root
instruction boundaries against the persistent index; independent x86 execution
covers13 prefix instructions.64 cases check both selectors (16 main109D0,
48 alternate10B60), null/non-null input fields and randomized incoming EDI.
Incoming EAX is the receiver; field+D4 selects the producer. Outgoing arguments
are `(receiver+7C, receiver+78, [receiver+D0])`. Incoming EDI survives the prefix,
not necessarily callee entry. All non-stack bytes remain unchanged; four stack
words are checked, including saved incoming ESI. Three boundary mutations each
reject64/64. Eight authored public tests exercise bounds, budgets, unsupported
instructions, code mutation and the partial oracle without original bytes.

This is hypothesis-changing ABI evidence, NOT another verified translation.
Whole20D0,1460,10B60, callback/lifetime and incoming caller field ownership remain
open. Host-native/AArch64/Android execution counts are all zero for this probe.
The old unknown-EDI observation was conservative static evidence, not proof of
producer input: actual argument3 comes from receiver+D0. Do not import the other
opener's zero-input proof here. Next: bind this field into a composed20D0 main
path, resolving1460 and then the alternate producer without stand-ins.

## Producer scan composition — 2026-10-25

Add `--producer-index work/recomp-bench/producer-scan-logs/query.json.env.json`
to the classifier command below (use a NEW private output). Obtain that envelope
with `scripts/ghidra-query.sh --rva 109D0 --instructions 40 --out
work/recomp-bench/producer-scan-logs/query.json` using the persistent index.
Run `python3 -m unittest discover -s tests -p 'test_recomp_*scan.py' -v`.

This mode freshly lifts all three bodies (109D0 → 10700 → FCB0), binds both
exact nested return addresses, and tests inline H+78/H+7C storage with bounded
nonzero string arguments plus one null-input case. Success publishes the
service and class byte; failure returns zero without changing non-stack state.
Eight final GPRs and six full pages match original x86: 64/64 host and 64/64
Linux/AArch64 QEMU; both root result/cleanup faults reject 64/64 per ISA.
Coverage: producer18/18, classifier21/21, comparator23/26 (62/65 total).
Receipt: `work/recomp-bench/producer-scan-final/result.json`.

New behavior is producer nonzero-input success/failure composition, not a new
dependency body. Inputs remain synthetic; incoming 20D0 context, lifetime,
callbacks, allocation, whole1AB665/E3/E4, flags/FP/PC/transient writes and
Android/gameplay remain unverified. Default classifier-only behavior and the
older zero-path harness retain their narrower scope.

## Campaign G2 — composed classifier scan (2026-10-25)

`execute_classifier_scan.py` freshly lifts10700 and its realFCB0 callee,
retaining the pinned image's six-entry table and pointed-to string page.
No table zeroing, relocation, authored callee responses or upstream edits.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 10700 --instructions 60 \
  --out work/recomp-bench/g2-scan-logs/query.json
python3 scripts/recomp/execute_classifier_scan.py \
  --index work/recomp-bench/g2-scan-logs/query.json.env.json \
  --compare-index work/recomp-bench/g1-fcb0-logs/query.json.env.json \
  --output work/recomp-bench/NEW-classifier-scan
python3 -m unittest discover -s tests -p test_recomp_classifier_scan.py -v
```

Use a new private output directory and bounded detached execution for long jobs.
Recorded receipt: `work/recomp-bench/g2-scan-verified/result.json`.
64/64 original-x86 cases satisfy independent result/nonvolatile/ESP and
non-stack-page checks; host64/64 and Linux/AArch64 QEMU64/64 compare all eight
GPRs and all six complete pages. Both root-only result/cleanup controls differ
64/64 per ISA. All21 classifier instructions visited; comparator23/26 here
(standalone G1 covered26/26). Results cover every index0..5, missFFFFFFFF,
and null-input6. Public tests use authored tables only, exercise the explicit
immutable-page reference option, and reject register/page/dispatch faults.

This settles bounded scan behavior, not its caller's input/lifetime contract.
No producer failure, whole1AB665, E3/E4 production registration, flags/FP/PC,
native transient-write, invalid-pointer or Android/gameplay verification.
The unchanged old zero-path harness remains deliberately narrower.

## Campaign G1 — classifier dependency FCB0 (2026-10-25)

Standing authorization replaces the earlier inventory-only scope stops. The
initialization harness now accepts exactly `--rva fcb0`: 51 bytes, 26
instructions, 11 blocks, no calls/imports/globals. Measured bounded behavior:
NUL-terminated byte-string equality with ASCII a–z folding; EAX is Boolean.
This is not an OS module service. Inputs use EAX/EDX guest pointers.

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_initialization_setter.py --rva fcb0 \
  --index work/recomp-bench/g1-fcb0-logs/query.json.env.json \
  --output work/recomp-bench/NEW-fcb0
python3 -m unittest discover -s tests -p test_recomp_module_comparison.py -v
```

Use a new private output directory and the bounded detached worker execution
contract. The recorded persistent query is reused, never re-imported. Fresh
pinned pcrecomp lift, independent x86 reference, host and Linux/AArch64 QEMU
execution, all 26 instructions visited, two rejecting controls per ISA.
Independent oracle checks EAX, nonvolatiles/ESP and six complete pages; native
comparison checks all eight GPRs and all pages against x86. No flags/FP/PC or
native transient writes. No whole-classifier scan, table/module semantics,
production binding, Android execution or gameplay is established. The old
classifier-zero fixture still rejects FCB0 dispatch; it is not silently expanded.

## Campaign E E2 callback setter1110 (2026-10-24)

The fixed initialization inventory now accepts `--rva 1110` (12 bytes/four
instructions). It stores callback data at object+5C; EAX=value, ECX=object,
ESP+=4. It does not invoke the callback. Existing targets/default are unchanged.

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_initialization_setter.py --rva 1110 \
  --index work/recomp-bench/init-e3-logs/1110.json.env.json \
  --output work/recomp-bench/NEW-setter1110
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

Output must be new/private. The cached read-only persistent-index envelope,
pinned image and unchanged pcrecomp are checked before the fresh lift; no body
fallback. Required:64 original-x86/oracle matches, verbatim host and Linux/
AArch64 execution through diagnostic GuestMemory/exact-VA dispatch, and both
wrong-slot and wrong-cleanup controls differing on each ISA. Three new authored
tests cover the full oracle, isolation, edges, placements, register/write/cleanup
faults and exact transport/index contracts. No production binding, callback
invocation, producer/lifetime proof, whole initialization or Android execution.
Current receipt/pins and reflection are in task-local PHASE1_REPORT.md. Prior
units retain historical harness pins; this command executes only1110.

## Campaign E E2 callback setter1100 (2026-10-24)

The fixed initialization harness also accepts `--rva 1100` (12 bytes/four
instructions). It reuses the E1 persistent-index envelope and unchanged pinned
pcrecomp; no arbitrary RVA or slot is accepted. The independent final contract
is object+50=value, EAX=value, ECX=object, ESP+=4. The callback is data only.

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_initialization_setter.py --rva 1100 \
  --index work/recomp-bench/init-e3-logs/1100.json.env.json \
  --output work/recomp-bench/NEW-setter1100
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

Output must be new and private. The harness requires64 original-x86/oracle
matches, verbatim lift execution through diagnostic GuestMemory/exact-VA dispatch
on host and Linux/AArch64, and both wrong-slot and wrong-cleanup controls to
reject on each ISA. Three authored tests cover the complete oracle, edge values,
two placements, isolation, register/write/cleanup faults and exact index/transport
contracts. Current evidence and limitations are in task-local PHASE1_REPORT.md.
Prior unit receipts retain their historical source pins; no settled unit is
re-executed by this command. No producer/lifetime, callback invocation, production
binding, whole initialization or Android execution is implied.

## Campaign E E2 paired callback setter10C0 (2026-10-24)

The fixed initialization harness accepts `--rva 10c0`, preserving existing
unit/default contracts. This19-byte/six-instruction leaf stores two independent
callback arguments at handle+3C/+40. EAX=handle, ECX=first, EDX=second,
ESP+=4. Inputs cover16 equal and48 unequal pairs, edge/random values and
two object/stack placements. Callback addresses are data only, never invoked.

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_initialization_setter.py --rva 10c0 \
  --index work/recomp-bench/init-e3-logs/10c0.json.env.json \
  --output work/recomp-bench/NEW-paired10c0
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

Output must be new and private. The command freshly lifts through unchanged
pinned pcrecomp, checks64 original-x86 cases against an independent oracle,
then executes the verbatim body through diagnostic GuestMemory/exact-VA dispatch
on host and Linux/AArch64 QEMU, with two rejecting behavioral controls per ISA.
Comparison covers eight final GPRs/six full pages, not flags/FP/PC/native
transient writes or store order. Three authored public tests cover both writes,
argument polarity, cleanup, full oracle/isolation, transport and index rejection.
No producer/lifetime proof, callback invocation, production binding, E3/E4 or
Android execution is implied. Actual evidence is in task-local PHASE1_REPORT.md;
older target receipts retain historical harness pins.

## Campaign E E2 dual-effect setter10E0 (2026-10-24)

The fixed initialization harness also accepts `--rva 10e0`; existing default
and target contracts are unchanged. This22-byte/five-instruction unit stores
callback data at handle+44 and sets the separate32-bit state at+110 to1.
Its final register contract differs from1090/10A0: EAX=handle, ECX=input,
ESP+=4. Authored inputs include state0,1,all-ones,2 and random values, two
object/stack placements and edge/random callbacks. Public tests independently
check both writes, register polarity, untouched pages, isolation, transport and
index rejection. Original-derived code stays private, never in these tests.

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_initialization_setter.py --rva 10e0 \
  --index work/recomp-bench/init-e3-logs/10e0.json.env.json \
  --output work/recomp-bench/NEW-dual10e0
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

The command requires a fresh exclusive private output directory. It must freshly
lift through unchanged pinned pcrecomp, independently oracle-match64 original
x86 cases, then match those states on host and Linux/AArch64 QEMU through the
diagnostic GuestMemory/exact-VA bridge. Two negative controls must reject per
ISA; malformed output/crashes never count as behavioral kills. Compared: eight
final GPRs and six full pages, not flags/FP/PC/native transient writes. Synthetic
valid objects and stored pointers do not establish callback invocation,
producer/lifetime contracts, E3/E4, production registration or Android execution.
See task-local PHASE1_REPORT.md for the actual run result and private receipt.
Previous1030/1090/10A0 receipts retain historical source pins.

## Campaign E E2 association1030 (2026-10-24)

`execute_initialization_setter.py --rva 1030` extends the fixed inventory with
one association helper; defaults and the two setter targets are preserved.
Fresh unchanged pinned pcrecomp lift: 28 bytes/11 instructions/three blocks;
64 original-x86 independent-oracle cases, 32 per equality branch. Host and
Linux/AArch64 QEMU each match64/64 through diagnostic GuestMemory/exact-VA
GuestDispatch. Wrong-slot and wrong-cleanup controls each differ64/64 per ISA.
Eight final GPRs/six complete pages compared; not flags/FP/PC/transient writes,
callback invocation, lifetime, production registration or Android execution.
Private receipt `work/recomp-bench/association-e6-final/result.json`.

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_initialization_setter.py --rva 1030 \
  --index work/recomp-bench/init-e3-logs/1030.json.env.json \
  --output work/recomp-bench/NEW-association1030
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

Four new authored public tests cover the conditional association ABI, two
object placements per branch, context retention/write errors, transport and
index/target rejection. Focused14/14. Prior1090/10A0 receipts have historical
harness pins, not current. No settled dependency was re-executed for this increment.

## Campaign E E2 setter10A0 (2026-10-24)

The same bounded harness now accepts `--rva 10a0` (default remains1090).
Only those two pinned E1 targets are accepted; arbitrary addresses/slots fail.
Fresh12-byte/four-instruction10A0 lift:64/64 original-x86 independent oracle,
64/64 host and64/64 Linux/AArch64 QEMU; both fault controls differ64/64 per ISA.
Eight final GPRs and six complete pages compared; flags/FP/PC/transient native
writes excluded. This stores callback data at object+34, not an invocation,
opener composition, production binding or Android runtime. Three new public
checks extend the existing skip-free suite to10 tests. Private final receipt:
`work/recomp-bench/setter-e5-final/result.json`.

```sh
. scripts/campaign/worker-env.sh
"$PY" scripts/recomp/execute_initialization_setter.py --rva 10a0 \
  --index work/recomp-bench/init-e3-logs/10a0.json.env.json \
  --output work/recomp-bench/NEW-setter10a0
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

The1090 receipt below is historical; current harness adds the bounded10A0 target.
Its original source pin belongs to commit eaea6bc, not the current source.

## Campaign E E2 setter1090 (2026-10-24)

`execute_initialization_setter.py` freshly lifts the fixed12-byte setter from
pinned image63a545db through unchanged pcrecomp c0cbd3e. It reuses the E1
persistent Ghidra envelope, checks all four instruction boundaries, and executes
64 bounded original-x86 cases. An independent final-state oracle checks the
callback slot+30, volatile registers and cdecl cleanup. The verbatim lift runs
through the authored diagnostic GuestMemory/exact-VA bridge on host and static
Linux/AArch64 via arm64-run.sh. Wrong-slot and wrong-cleanup controls must produce
complete differing states on both ISAs; crashes/partial/malformed output do not
count as behavioral kills. No callback is invoked or production binding installed.

```sh
. scripts/campaign/worker-env.sh
# Bounded detached job; reuse E1 metadata, fresh exclusive private output.
"$PY" scripts/recomp/execute_initialization_setter.py \
  --index work/recomp-bench/init-e3-logs/1090.json.env.json \
  --output work/recomp-bench/NEW-setter1090
"$PY" -m unittest discover -s tests -p test_recomp_initialization_setter.py -v
```

Compared: eight final GPRs and six full pages; not flags/FP/PC/native transient
writes. Synthetic aligned objects and pointer values are test inputs, not an
opener producer/lifetime contract. Android execution remains false. Private
result.json records source/body/input/reference pins, exact invocation, upstream
file pins, API lift parameters, per-command exit/timings and per-ISA results.
This resolves one setter dependency only, not the opener service frontier.

## Campaign E initialization graph (2026-10-24)

Campaign E renews authority for bounded **read-only** `1AB665` initialization
analysis; the Campaign D scope stop below is historical. `20D0` remains gated.
`inspect_initialization_graph.py` reuses the SHA-pinned `frontier-d3-sibling-final`
root receipt rather than re-auditing that root. It traverses a fixed inventory
of root callees and documented opener/cleanup/producer boundaries (at most22
nodes including the seed, 0x400 bytes per newly inspected body). Already-verified
bodies are reused as inventory only. Unlisted direct/tail targets and unresolved
indirect calls stop at a recorded frontier; they are not translated or stubbed.

The harness serially queries the persistent Ghidra project, caches private
envelopes, checks read-only image provenance and exact full indexed boundaries
where available, and preserves index gaps/caps/log signals. A single entry JMP
is reported as a tail edge, not treated as a returning leaf. Bounds failures
retain partial observed dependencies and never imply a complete graph.

```sh
. scripts/campaign/worker-env.sh
# Use the documented setsid + timeout + private-log execution path.
"$PY" scripts/recomp/inspect_initialization_graph.py \
  --index-dir work/recomp-bench/NEW-init-index \
  --output work/recomp-bench/NEW-init-graph
# Expected exit2: static graph, NOT composed execution readiness.
"$PY" -m unittest discover -s tests -p test_recomp_initialization_graph.py -v
```

Outputs must be private; graph outputs are exclusive, queries are bounded90s
per node. Use a real outer job bound allowing for serial Ghidra startup. Leaf
candidates are **unverified** E2 inputs, not recovered native bodies. No path
feasibility, callback-data target resolution, receiver producer/input/lifetime
contract, Windows service, game startup or Android execution is established.

## Current Campaign D verification map (2026-10-24)

Older sections below are dated experiment records, not an active milestone queue.
M1–M5 and the text-ownership probe are settled at their recorded bounded strength.
`execute_text_leaf.py` verifies standalone `9550`; `--thunk-index` verifies
standalone `FCF0` with the real `9550` tail callee. Both private receipts
(`leaf-d1`, `thunk-d2`) record 64/64 host and 64/64 Linux/AArch64 QEMU, eight GPRs
and six full pages. Leaf coverage49/49; thunk+leaf51/51; six switch destinations
including95c2. Historical135/136 is a composed instruction count, not arm count.
Two bridge faults reject per ISA. Android execution remains false; this is not
production startup, exhaustive encoding semantics, flags/FP/PC or write tracing.

Exact bounded detached lift reproducers and receipt hashes are in the Campaign D
iteration1/2 entries of `tasks/android-phase1/PHASE1_REPORT.md`; use exclusive
new private outputs only when another lift is justified. For the skip-free
public regression check (no private image, lift or original-code execution):

```sh
. scripts/campaign/worker-env.sh
"$PY" -m unittest discover -s tests -p test_recomp_text_leaf.py -v
```

The leaf receipt's harness pin belongs to `eab04f6`, not today's thunk-extended
source. The thunk receipt pins current source at `e504b28`. Do not silently
upgrade historical provenance or count a public authored test as re-execution
of the private original-code differential.

Continuation roots are owner-gated by `37b5218`, as detailed below. After the
permitted documentation/test-debt refresh, request corrected sibling scope or
explicit bounded opener/producer/service contracts; do not repeat settled lifts
or infer callee authority from a root's reported call list.

## Campaign D continuation root-scope audit (not execution)

`inspect_continuation_scope.py` inspects only roots `1AB665` or `20D0`, at most
0x200 bytes each, against the pinned image and a complete persistent-index
instruction inventory. It never reads callee bodies, lifts, or executes code.
Its conservative MOV/XOR full-register constant propagation stops at the first
call on each normal-flow path; branch feasibility and ABI are not established.
Unknown/partial/implicit/arithmetic register writes kill constant knowledge.
Missing inventory or any indirect call returns **2 (blocked)**, not a match.
A zero audit exit is still not authority or whole-caller comparison evidence.

```sh
. scripts/campaign/worker-env.sh
# Run queries/audits detached with a real timeout and ignored logs as documented.
for r in 1ab665 20d0; do
  scripts/ghidra-query.sh --rva "$r" --instructions 128 --refs 8 \
    --callers 8 --callees 24 --out "work/recomp-bench/NEW-index-$r.json" --quiet
  "$PY" scripts/recomp/inspect_continuation_scope.py --rva "$r" \
    --index "work/recomp-bench/NEW-index-$r.json.env.json" \
    --output "work/recomp-bench/NEW-scope-$r"
  # Expected audit status: 2. Do not traverse the reported callees automatically.
done
"$PY" -m unittest discover -s tests -p test_recomp_continuation_scope.py -v
```

Measured roots: `1AB665` has 83 instructions/267 bytes and 14 direct callees,
none the queued wrapper pair; its opener dependencies require a new bounded
closure decision. `20D0` has 26 instructions/68 bytes, an indirect producer
selection (`109D0`/`10B60` prefix possibilities) and direct `1460` dependency.
EDI is unknown at producer entry in this analysis: the other opener's EDI-zero
proof cannot be imported. Ghidra lists the two constant-selected producers as
callees even though neither is a direct CALL operand here. Both indexes agree
on every root instruction boundary; the known log ERROR remains recorded.
Existing verified helper `1070` is explicitly retained in inventory; no claim
that all setters are unverified. No new native bodies or Android execution.

## Campaign C: real static dispatch differential (bounded M1 increment)

`execute_cache_dispatch.py` freshly lifts each authorized accessor, the whole
9550 switch and the FCF0 thunk using unchanged pinned pcrecomp. It binds only the
exact indirect target A000FCF0 and its A0009550 tail hop; other destinations fail.
Six complete checked pages include image-backed jump/class tables. No service
response, original-byte patch or old lifted-source fallback is supplied.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva fcf0 --instructions 8 \
  --out work/recomp-bench/NEW-index-fcf0.json
for r in 1290 12d0; do
  "$PY" scripts/recomp/execute_cache_dispatch.py --rva "$r" --whole-samples \
    --index "work/recomp-bench/closure-b1-logs/index-$r.json.env.json" \
    --switch-index work/recomp-bench/closure-c2-logs/index-9550.json.env.json \
    --thunk-index work/recomp-bench/NEW-index-fcf0.json.env.json \
    --output "work/recomp-bench/NEW-dispatch-$r" || break
done
"$PY" -m unittest discover -s tests -p test_recomp_cache_dispatch.py -v
```

Run detached/bounded with private logs and exclusive new outputs. The historical
accessor/switch indexes above must exist; otherwise query their RVAs into new
private files. FCF0 remains address-only in Ghidra (no indexed instructions);
the two-instruction transfer contract is independently decoded, not indexed
ownership. The generated thunk uses ITAIL, not a direct C call: only the exact
hop from the thunk may tail-dispatch, without pushing another return word.

Measured `closure-c3-tail-{1290,12d0}`: each matches64/64 on host and64/64 on
Linux/AArch64 QEMU. Four skip cases, four dispatched empty ranges and56 nonempty
ranges exercise all six switch arms; one instruction remains uncovered. Eight
GPRs and all six complete pages compare; flags/FP/nativePC/transient writes do
not. This is a fixture, NOT GuestMemory integration, whole-caller execution,
Android, unknown text ownership or a claim that all inputs terminate.

**Failed corpus retained, not counted:** without `--whole-samples`, raw truncated
samples hit the4096-instruction original-x86 budget at case12. Keeping its range
but replacing bytes with ASCII returns; shortening that sample by one byte also
returns; zeroing counters does not. HYPOTHESIS: the truncated sample prevents
advance. Exact encoding semantics remain unknown. The named whole-sample corpus
is a separate bounded domain, not silent omission/retry of that failure. M1 is
conservatively marked incomplete; M2–M4 remain missing. Next: composed original
1ABD40 reference with all five live callees and real guest receiver/handle state,
while retaining the raw-input/termination and lifetime questions.

Unicorn Python callbacks fault on this host even in a tiny authored MOV/RET test;
plain/timed/hook-free single-step variants pass. This harness uses hook-free
prevalidated single-stepping, like the existing rigs, never endpoint responses.
Eight public controls include actual native rejection of wrong call/tail targets,
wrong tail caller and immutable-image mutation. Private audit checks both source
pins, both ISA matches and insertion of every freshly generated body verbatim.

## Campaign C: whole local-switch lift (object evidence only)

`measure_local_switch.py` supplies explicit local target metadata to **unchanged**
pinned pcrecomp for the authorized `9550` dependency. It decodes a bounded graph,
requires table arms to be local independent linear boundaries, rejects calls,
traps, segments and escaping jumps, then preserves the whole emitted body. It
compiles host/AArch64 **objects**, not executables. No reference match, thunk
execution, dispatch integration or completed M1 is claimed.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 9550 --instructions 80 \
  --out work/recomp-bench/NEW-index-9550.json
"$PY" scripts/recomp/measure_local_switch.py \
  --index work/recomp-bench/NEW-index-9550.json.env.json \
  --output work/recomp-bench/NEW-switch
"$PY" -m unittest discover -s tests -p test_recomp_local_switch.py -v
```

Use exclusive private output paths and bounded logged detached execution. A
successful command means only the declared object experiment succeeded; explicit
`m1_complete`, `matched_x86_reference`, `arm64_executed`, `android_executed` remain
false. The six-entry table inventory yields 49 instructions/120 reachable bytes,
including arms beyond the earlier return; the older ~94-byte description is
incomplete for this graph. The persistent index is address-only/capped, agrees
on its 32 available boundaries, retains ERROR1, and does **not** own the extent.
The lifter emits six local cases with an external ITAIL default. No behavior
response or lifter patch is supplied. Eight public controls use authored bytes.

Next: execute the real `FCF0` thunk and whole `9550` body with image-backed table
pages under checked exact-VA dispatch, then fresh nonzero-range x86/native cases.
Table encoding semantics and text-range lifetime remain unknown; do not infer
UTF-8 behavior or count object compilation as dependency resolution.

## Campaign C: fresh accessor lifts, skip-path execution (partial M1)

`execute_cache_skip.py` freshly lifts `1290`/`12D0` in a child process that must
exit **0**. It verifies the pinned image and upstream source, reuses the persistent
Campaign B indexes, and never reads an old lifted body. The whole generated body
is compiled for host and static Linux/AArch64, but **only H+100==0 is validated**.
Reached indirect calls reject, including the authorized target; no response is
supplied. This is not the requested completed M1 dispatch implementation.

```sh
. scripts/campaign/worker-env.sh
"$PY" -m unittest discover -s tests -p test_recomp_cache_skip.py -v
for r in 1290 12d0; do
  "$PY" scripts/recomp/execute_cache_skip.py --rva "$r" \
    --index "work/recomp-bench/closure-b1-logs/index-$r.json.env.json" \
    --output "work/recomp-bench/NEW-skip-$r" || break
done
```

Use exclusive new private output paths and bounded logged execution. Each result
records fresh x86 references, exact commands, source/index hashes, lift exit and
per-ISA matches. Comparison covers eight GPRs and four complete pages, not native
flags/PC/FP/transient writes. Public authored controls compile the rejection path,
reject calls/unmapped reference access, malformed comparisons and unsafe outputs.
Next: exact-VA `FCF0` dispatch and the real `9550` body/table, then nonzero-range
cases; never count these skip-only results as full dependency resolution or M1.
The older unresolved-target stop records below are historical and superseded by
`docs/RECOMP_DEPENDENCY_FIRST.md` §7, not current permission blockers.

## Campaign B: authorized closure encounters unresolved indirect dependency

Owner authorization in `docs/RECOMP_DEPENDENCY_FIRST.md` supersedes the historical
1290/12D0 permission blocker below, separately from the 25-function survey.
However,1290 is **not a simple no-call leaf**: bounded pinned-image decoding finds
an indirect call at12B2 (61 reachable bytes,20 instructions,3 blocks). Persistent
Ghidra and Capstone agree on all20 instruction boundaries/extent; operand behavior
is not established. The target is unresolved, so stop before lifting/executing;
no target outside the authorized closure may be silently supplied.

```sh
. scripts/campaign/worker-env.sh
python3 -m unittest discover -s tests -p test_recomp_cache_closure.py -v
python3 scripts/recomp/inspect_cache_closure.py \
  --output work/recomp-bench/closure-NEW \
  --index-1290 work/recomp-bench/closure-b1-logs/index-1290.json.env.json \
  --index-12d0 work/recomp-bench/closure-b1-logs/index-12d0.json.env.json
# Expected exit2: unresolved/out-of-scope dependency, not a failed correctness test.
```

The new harness is a dependency preflight, not a translator. Indexes were obtained
using two bounded persistent `ghidra-query.sh` calls with `--instructions 40` and
explicit private `--out` paths; no re-import. Final measured artifact:
`work/recomp-bench/closure-b1-indexed/result.json`. Public controls reject
unknown direct targets, indirect calls/tail jumps, non-boundary local jumps and
unsafe/clobbering output paths, and prove stopping before the second body.
HYPOTHESIS: callback/service target provenance and ABI must be resolved before
M1, not merely two additional body lifts. No new body, original execution,
AArch64 or Android evidence; M1–M4 remain incomplete. This is a new exclusion,
not repeated measurement of verified leaves.

### Campaign B iteration 2: callback input provenance (still STOPPED)

`trace_cache_callback.py` follows a bounded symbolic prefix of **1290 only**, up
to its first call/return. It reuses the saved persistent index above; no new body,
index import, lift or execution. Seven public authored controls distinguish nested
service loads, MOV versus LEA, stack saves/arguments, both guard edges, unsupported
side effects, flag invalidation, budgets and exclusive private outputs.

```sh
. scripts/campaign/worker-env.sh
python3 -m unittest discover -s tests -p test_recomp_cache_callback.py -v
python3 scripts/recomp/trace_cache_callback.py \
  --index-1290 work/recomp-bench/closure-b1-logs/index-1290.json.env.json \
  --output work/recomp-bench/callback-NEW
# Expected2, even after a successful inspection: dependency gate NOT cleared.
```

Final private artifact: `work/recomp-bench/closure-b2-provenance-verified/result.json`.
**HYPOTHESIS from static input dependencies:** let H be1290's first stack
argument and S the pointer loaded from H+78. The call at12B2 reads its target
through **S+34**, not a direct H+34 load; the existing handle callback-setter map
cannot bind this nested slot. Runtime equality/inequality of S and H is unproven. The call path follows a nonzero H+100 test. Four pre-call
stack words are S, the values at H+108 and H+100, and the **address** H+1C8.
Those words do not prove callback arity/cleanup, ownership or target identity.
Expression analysis assumes nonaliasing input/stack and excludes address wrap;
both conditional edges are explored without feasibility/exception modelling.
The no-call path reaches a return; this is not behavioral verification.

Next bounded decision: authorize locating the producer of H+78 and the nested
service's+34 target (read-only, explicit body/search limits), then separately
approve any target outside the caller closure before lift/reference/native work.
Do not substitute the opener's different H+34 callback or fabricate a response.
M1–M4 remain incomplete; no new native body or original behavior is executable.

## Five-cache caller contract/scope preflight (run5-057)

`inspect_cache_contract.py` checks already-selected `1ABD40` against the existing
persistent read-only index and an independent bounded decode of the pinned image.
No re-import, new query, callee decoding, lift, reference execution or runtime
binding is performed. It inventories the pinned historical group/wrapper catalogs
rather than inventing missing reference states.

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/inspect_cache_contract.py \
  --index work/recomp-bench/run5-046-logs/index.json.env.json \
  --output work/recomp-bench/NEW-cache-contract.json
# Expected exit 2: inspection complete, native comparison BLOCKED (not a pass).
python3 -m unittest discover -s tests -p test_recomp_cache_contract.py -v
```

Use a NEW private output path and bounded detached jobs/private logs. Missing or
changed image/index/catalogs, malformed operands and output clobbering reject.
Five public tests use authored operand metadata, not original bytes or a generated
replacement function. They mutate every operation/operand, stack cleanup, store
ordering, memory addressing, catalog provenance and selection/output controls.

Observed static contract: five pushes of handle `[receiver+34]`, interleaved with
previous cache-result stores; all five argument words remain until one caller
cleanup of20 bytes. The caches80/84/88/8C/90 receive1240/1290/12D0/1250/1270.
The final test sets **only AL** from cache80 nonzero; upper EAX retains the fifth
callee result. These are static caller operands, not tested callee effects or a
composed CPU-state comparison. Invalid/null handles, FP/flags/stack preservation,
callbacks, ownership and service behavior remain unvalidated.

**Concrete scope gate:** pinned catalogs cover1240/1250/1270, not1290/12D0;
those two are absent from the fixed25 selection. Reference-only x86 dependencies
cannot supply their native implementations. Adding both would make the selection
union27, requiring separate explicit scoped owner approval; no swap-out or26th
body is authorized. `closed_native_body_count` means this immediate five-callee
union only, not transitive whole-game closure. Even complete standalone catalogs
would not prove this caller's composed ABI. Native comparison is not attempted;
unique counts remain25 attempted/23 lifted+ARMcompiled/14 bounded-matched+QEMU.
Phase1 and all existing P0/P1 gates remain open.

## Consolidated 25-candidate result (run5-056 reflection)

[MEASURED_SELECTION.md](MEASURED_SELECTION.md) joins the existing base21 + four
supplements with unique per-candidate selection rules, dependencies, boundary
limits, stage outcomes, costs, fixture scopes and reproducing commands. Read-only
audit checks the table against private records; no new selection or execution.
Totals:25 attempted /23 lifted and ARM compiled /14 bounded-matched and QEMU /
9 object-only /2 analysis rejections. Not25 behavioral passes or a whole-game
estimate. This docs-only synthesis immediately follows tested artifact `c456a2b`;
all Android/gameplay and prior ABI/service/ownership gates remain open.

## Fresh selected callback-setter measurement (run5-055)

`measure_setter.py` measures the already-selected 19-byte `1070`, using the
unchanged pinned private pcrecomp copy and the existing upstream difftest case,
C-shell and state protocols. The historical device bundle lacks its generator:
these are **64 NEW deterministic cases**, not recreated old device inputs.
The single original body comes from `Lifter(precise_carry=True).lift_function`;
no hand-written implementation is counted. All derived files remain private.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1070 --instructions 40 --out work/recomp-bench/NEW-1070.json
python3 scripts/recomp/measure_setter.py \
  --index-1070 work/recomp-bench/NEW-1070.json.env.json \
  --output work/recomp-bench/NEW-setter
python3 -m unittest discover -s tests -p test_recomp_setter.py -v
```

Use exclusive NEW output paths and bounded detached **bash** jobs/private logs.
The existing stack-only public execution gate is unchanged; the setter uses a
separate exact-image/range-pinned fixture with object/stack checks. Ghidra is
advisory, not the owner of a generic execution authorization. Native memory words
are checked for alignment and membership in the two seeded spans. Reference
execution follows `reference_startup.py`'s hook-free, checked single-step pattern:
prevalidate every explicit read/store and implicit RET read, require exact store
journal and end PC, and bound instructions/time. This avoids the existing Unicorn
memory-hook SIGBUS without dropping read-range checks or claiming that bug fixed.

Both host and AArch64 Linux/QEMU must match the independent setter oracle and
fresh x86 states for all GPRs, full flags at fixed initial0x202, full-window memory
deltas and empty FP-stack transport. X86 pre-step stores are journaled even for
same-value writes; native transient stores/PC are NOT compared. No callbacks are
invoked, no ownership/services/startup or production runtime binding is validated.
Compile/link/run costs are separate; this is an isolated warm-O0 fixture cost,
not full-game throughput or Android/hardware evidence. Seven public control tests
exercise deterministic cases, independent state expectations, every observed
component's corruption, both-ISA completion, checked accesses, exact body insertion
and private exclusive output/failure records. Findings: task-local reports.

## Fresh standalone read-only group measurement (run5-054)

`measure_group.py` freshly lifts the already-selected `1240/1250/1270` with the
unchanged pinned `group_probe.py`, regenerates deterministic cases without running
x86, and requires exact historical full-fixture source identity before the existing
read-only dispatch preparation. All 96 saved x86 states are rechecked against the
rig's independent oracle. Native host and AArch64 Linux/QEMU must both match all
96 states with identical stdout. Standalone coverage is explicitly 16/32/48 cases,
unlike the preceding wrapper-only coverage of1270. This is not fresh x86 execution,
Android/hardware, production integration or executable-wide throughput evidence.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1240 --instructions 100 --out work/recomp-bench/NEW-index.json
python3 scripts/recomp/measure_group.py \
  --index-1240 work/recomp-bench/NEW-index.json.env.json \
  --output work/recomp-bench/NEW-group
python3 -m unittest discover -s tests -p test_recomp_group.py -v
python3 -m unittest discover -s tests -p test_private_readonly_dispatch.py -v
```

Use exclusive NEW paths and bounded detached jobs with private logs. Index1240 is
function-at, three instructions, no caps; standing ERROR1 retained. The exact pinned
rig and independent CFG own all three extents, not an advisory index sweep. This
does not change the startup harness's stricter own-index gates. The historical rig
decodes each leaf at synthetic base A0000000; actual selected RVAs and this decode
base are both recorded. Per-body analysis/lift costs are separate from shared-fixture
compile/link/run costs; never divide the latter into fictitious per-body timings.
Five public tests cover entry distribution, complete claims, index provenance,
private-path safety and missing-input/no-clobber failure records. Results and all
remaining P0/P1 gates are in task-local PHASE1_REPORT.md and OPEN_QUESTIONS.md.

## Fresh composed cache-wrapper measurement (run5-053)

`measure_wrappers.py` reuses the pinned private wrapper rig unchanged, freshly
lifts four selected bodies (`1250`, `1270`, `1AB770`, `1AB78C`), and requires the
resulting fixture source to match its historical SHA exactly before using the
existing scoped dispatch preparer. No handwritten replacement bodies are used.
The two wrapper entries compare 64 saved x86/oracle states per ISA; leaf behavior
is exercised through those entries, not a standalone leaf test. Linux/QEMU is
not Android or hardware. Full-game throughput cannot be inferred from this group.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1AB770 --instructions 100 --out work/recomp-bench/NEW-770.json
scripts/ghidra-query.sh --rva 1AB78C --instructions 100 --out work/recomp-bench/NEW-78c.json
scripts/ghidra-query.sh --rva 1270 --instructions 100 --out work/recomp-bench/NEW-1270.json
python3 scripts/recomp/measure_wrappers.py \
  --index-1270 work/recomp-bench/NEW-1270.json.env.json \
  --index-1ab770 work/recomp-bench/NEW-770.json.env.json \
  --index-1ab78c work/recomp-bench/NEW-78c.json.env.json \
  --output work/recomp-bench/NEW-wrappers
python3 -m unittest discover -s tests -p test_recomp_wrappers.py -v
python3 -m unittest discover -s tests -p test_private_scoped_dispatch.py -v
```

Use exclusive NEW paths and bounded detached jobs/private logs. Ghidra reports
address-only/capped linear walks for both wrappers; these are retained, NOT used
as function extents. The independent bounded CFG agrees with the pinned rig's
28/28-byte wrapper and 27/30-byte leaf ranges. The indexed `1270` query has 11
instructions without caps. All three queries retain ERROR1. No index mutation,
recovery, selection expansion or PE launch occurs. This is not a relaxation of
`measure_startup.py`'s indexed-boundary gate: a separate already-pinned rig owns
these exact ranges and the entire regenerated fixture must match its source pin.

Private `result.json` records pins, exact invocation, per-body decode/lift costs,
group compile/link/execute costs and both comparisons. `metrics.jsonl` emits one
row per body, with explicitly composed verification scope. Do not divide group
costs by four to invent per-function compiler times. Missing inputs, changed pins,
partial output, one-ISA-only execution and comparison differences fail closed.
Four public tests cover provenance/claim gates and private-output containment;
existing strict comparison tests mutate registers, flags, memory and FP transport.
Measured results and remaining Phase 1 gates: task-local `PHASE1_REPORT.md`.

## Selected cache/mapping caller whole-object cost (run5-052)

HYPOTHESIS tested: already-selected `1AB7E0` can lift whole and compile as
host/AArch64 objects without following or inventing its jump-table dependency.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1AB7E0 --instructions 400 \
  --out work/recomp-bench/NEW-mapping-index.json
python3 scripts/recomp/measure_startup.py --rva 1AB7E0 \
  --index work/recomp-bench/NEW-mapping-index.json.env.json \
  --output work/recomp-bench/NEW-mapping
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use exclusive NEW output paths, bounded detached jobs and private logs. The
persistent Ghidra12.2 query resolves39B/16 instructions; no caps, standing ERROR1
retained. Zero indexed callers is not proof of unreachability. Independent
Capstone agrees on39 reachable bytes/3 blocks/16 normal edges. Calls are assumed
returning, not behaviorally validated. Only this selected caller is lifted.

| RVA | Bytes | Analysis | Index check | Lift | Host object | ARM64 object | Linked / matched / QEMU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1AB7E0 | 39 | .001920s | .000287s | .000125s | .518905s | .167818s | no / no / no |

Preflight1.627758s separate; query startup not timed. Whole unmodified pinned
pcrecomp body retained verbatim; ELF64 little-endian ET_REL machines62/183.
Objects16,536/18,264B at-O0 are not linked sizes or cold/full-game forecasts.
Direct dependencies `1240` and `1AB8A9`; no indirect calls, absolute or segmented
memory operands locally. This does NOT resolve the callee's indirect jump table,
cache/mapping semantics, ownership or ABI. Measurement exit2 INCOMPLETE; no x86
reference, native CPU comparison, linking, QEMU execution or runtime binding.
Two authored tests retain own-index/selection/bound/cap/trap/indirect-JMP guards.
Private artifacts:work/recomp-bench/run5-052-mapping/ and run5-052-logs/.
Unique totals:selected25/rejected2/attempted20/lifted18/ARMcompiled18 (nine
object-only)/native-matched9/QEMU9. Full25 remains incomplete; the purposive
shortlist cannot estimate44,151 functions. Linux/QEMU is not Android/hardware.
Focused39/39 passed; host CTest22/22 plus Python574 OK/no skips and existing
ARM64/QEMU CTest22/22 passed. Android build blocked SDK unset (exit1);
Phase1 acceptance blocked validator unset (exit78). See task-local report for
reproducible commands and the retained P0/P1 audit.

## Selected callback producer object cost (Ralph15 reflection checkpoint)

Reflection: nine native-reference-matched/QEMU-executed functions remain the
correctness evidence. Recent object-only measurements establish mechanical lift
cost, NOT runtime correctness or a route to gameplay. HYPOTHESIS tested here:
already-selected `1460` admits a whole lift and host/AArch64 object compilation
without inventing service or failure-cleanup callbacks.

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1460 --instructions 400 \
  --out work/recomp-bench/NEW-callback-index.json
python3 scripts/recomp/measure_startup.py --rva 1460 \
  --index work/recomp-bench/NEW-callback-index.json.env.json \
  --output work/recomp-bench/NEW-callback
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use exclusive NEW output paths and bounded detached jobs/private logs. One
persistent read-only Ghidra12.2 query:279B/82 instructions, two callers/four
callees, no caps; standing ERROR1 retained. Independent Capstone agrees on all
279 reachable bytes,13 blocks/86 normal edges. Calls assumed returning; this
is not a service/ownership/ABI or exception-flow contract.

| RVA | Bytes | Analysis | Index check | Lift | Host object | ARM64 object | Linked / matched / QEMU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1460 | 279 | .004116s | .000467s | .000421s | .567808s | .216943s | no / no / no |

Preflight1.718314s separate; query startup not timed. Whole pinned unmodified
pcrecomp body retained verbatim; ELF64 little-endian ET_REL machines62/183.
Objects39,832/46,416B at-O0 are not linked/cold/full-game cost forecasts.
Two direct dependencies `102D0`/`831A6F`, four unresolved indirect calls and
one ES-segment memory operand; no absolute memory operands locally. Dependency
inventory is not an implemented callback/allocator service. Measurement exit2
INCOMPLETE; no original reference run, native CPU comparison, linking, execution,
GuestMemory/image binding, callback ownership or startup validation. Public tests
use authored bytes, require own index/selection and retain cap/bound/trap failures.
Focused37/37 passed. Private artifacts:run5-051-callback/ and run5-051-logs/ under
work/recomp-bench/. Inline audit11/11 true. Unique totals:selected25/rejected2/
attempted19/lifted17/ARMcompiled17(eight object-only)/native-matched9/QEMU9.
The base manifest contains21; existing deterministic measurement extensions bring
the union to25, not four newly selected functions here. Full25 remains incomplete;
nonrandom shortlist cannot estimate44,151 functions. Linux/QEMU is not Android
or hardware. Next bounded measurement:already-selected1AB7E0, one persistent
query first; no jump-table helper lift or invented target/service.

## Selected sibling factory object cost (iteration50 / Ralph14)

HYPOTHESIS tested: already-selected `1DA310` admits whole-body lift and object
compilation without supplying its dependencies. Reuse the required-index runner:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1DA310 --instructions 256 \
  --out work/recomp-bench/NEW-sibling-index.json
python3 scripts/recomp/measure_startup.py --rva 1DA310 \
  --index work/recomp-bench/NEW-sibling-index.json.env.json \
  --output work/recomp-bench/NEW-sibling
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use bounded detached jobs/private logs and exclusive new output paths. `--out`
is raw JSON; `.env.json` is the required provenance envelope. One persistent
query resolves35B/12 instructions, no caps, zero callers/two callees; standing
log ERROR1 retained. Zero callers is not proof of unreachability. Independent
Capstone agrees on35 reachable bytes,3 blocks/12 normal edges. Calls are assumed
returning, not behaviorally validated.

| RVA | Bytes | Analysis | Index check | Lift | Host object | ARM64 object | Linked / matched / QEMU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1DA310 | 35 | .001647s | .000298s | .000120s | .517533s | .167671s | no / no / no |

Preflight1.781124s separate; headless startup not timed. Unmodified pinned
pcrecomp body is verbatim in object.c; ELF64 little-endian ET_REL machines62/183
checked. Objects16,360/18,040B at-O0 are not linked/cold/full-game cost estimates.
Two direct dependencies `1D9CB0`/`824624`; no indirect calls, absolute or segmented
operands in this body. That absence says nothing about dependencies' services,
SEH or callback behavior. No callees lifted or stubbed. Measurement exits2
INCOMPLETE: no reference, native comparison, linking, QEMU or runtime binding.
Two new authored tests retain own-index, selection, cap/bound/trap rejection and
FS/indirect metadata behavior. Full25 pipeline and executable-wide forecast remain
incomplete. Selected25/rejected2/attempted18/lifted16/ARMcompiled16 (seven
object-only)/native-matched9/QEMU9. Linux/AArch64 is not Android/hardware.

## Selected resource factory object cost (iteration49 / Ralph13)

HYPOTHESIS tested: already-selected `1D3E20` can lift whole and compile without
invented allocation, construction, registration, vtable or FS/SEH services.
Existing required-index harness only; no extra selection or callee lift:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1D3E20 --instructions 400 --quiet
# Use emitted private envelope path as INDEX; exclusive NEW output.
python3 scripts/recomp/measure_startup.py --rva 1d3e20 \
  --index "$INDEX" --output work/recomp-bench/NEW-factory
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use bounded detached jobs/private logs. Exact entry/provenance, uncapped index,
0x400 decode bound, independent boundaries and trap/nonreturn rejection remain.
Two authored tests cover selection/own index, FS versus absolute addressing,
conditional call bypass, unresolved dependency retention, shortened/capped extent,
unselected neighbor and reachable trap rejection. Focused33/33 passed.

| RVA | Bytes / instructions / blocks | Analysis | Index check | Lift | Host object | ARM64 object | Linked / matched / QEMU |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1D3E20 | 185 / 64 / 11 | .003622s | .000466s | .000289s | .518606s | .217806s | no / no / no |

All185 bytes reachable,67 normal-flow edges; calls assumed returning. Ghidra12.2
extent agrees; zero indexed callers/three callees, no caps, standing ERROR1
retained. Zero callers is not proof of unreachability. Preflight1.615466s
separate; query startup not timed. Pinned unmodified pcrecomp body verbatim in
object.c; ELF64 ET_REL machines62/183 checked. Objects47,080/55,040B at-O0
are not linked code sizes, cold throughput or a full-game cost estimate.
Measurement exits2 INCOMPLETE.

Four direct sites/three unique dependencies `824632`, `1D8B90`, `14323F`
(twice); six unresolved indirect calls and three FS:[0] memory operands. No x86
reference/native state comparison, link, QEMU, ABI/SEH/ownership/lifecycle or
startup/attachment-order validation. No GuestMemory/image/runtime binding.
Compilation cannot validate the emitted FS/SEH or callback semantics.

Unique totals: selected25/rejected2/attempted17/lifted15/ARMcompiled15(six
object-only)/native-matched9/QEMU9. Full25 incomplete; nonrandom shortlist cannot
forecast44,151 functions. Inline artifact audit12/12 true, no audit script created;
private outputs/logs at work/recomp-bench/run5-049-factory/ and run5-049-logs/.
Linux/AArch64/QEMU is not Android or hardware evidence.

## Selected candidate-rebuild object cost (iteration48 / Ralph12)

HYPOTHESIS tested: selected `1E95C0` can be lifted whole and compiled without
inventing its enumeration, sorting, container, callback or SEH dependencies.
The existing required-index harness now accepts this already-selected entry:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1E95C0 --instructions 400 --quiet
# Use the emitted private envelope path as INDEX; exclusive NEW output.
python3 scripts/recomp/measure_startup.py --rva 1e95c0 \
  --index "$INDEX" --output work/recomp-bench/NEW-rebuild
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Run bounded detached jobs with private logs. Required provenance, exact entry,
uncapped extent, independent boundary agreement, 0x400 decode limit and trap/
nonreturn rejection are unchanged. Two authored tests require selection/own
index, preserve loop edges and direct/indirect external dependencies, and reject
caps, an excluded return, a reachable trap and an unselected adjacent entry.
Focused31/31 passed. No callee, stub, additional selection or upstream change.

| RVA | Bytes / instructions / blocks | Analysis | Index check | Lift | Host object | ARM64 object | Linked / matched / QEMU |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1E95C0 | 323 / 105 / 15 | .021008s | .000452s | .000418s | .468114s | .167075s | no / no / no |

All323 bytes reachable;112 normal-flow edges. Ghidra12.2 extent agrees with
Capstone; nine indexed callers/six callees, no truncation, standing ERROR1
retained. Preflight1.626646s separate; query startup not timed. Whole pinned
unmodified pcrecomp body appears verbatim in object.c. Both ELF64 ET_REL objects
compile, machines62/183 checked; sizes60,752/69,560B at-O0 are NOT linked sizes,
cold-build throughput or porting cost. Measurement exits2 INCOMPLETE.

Seven direct call sites/six distinct dependencies: `825300`, `1D77A0`, `1D6B00`,
`825414`, `82540F` (twice), `1D72E0`; one unresolved indirect call. Three FS:[0]
memory operands are recorded as segmented, not absolute/IAT addresses. Compilation
is not proof that FS/SEH, callbacks, stack/flags/memory, lifetime or sorting
semantics are correct. No original reference run, link, QEMU, guest-runtime
integration, package ordering or Android evidence for this caller.

Unique totals: selected25/rejected2/attempted16/lifted14/ARMcompiled14(five
object-only)/native-matched9/QEMU9. Full25 remains incomplete; the nonrandom
shortlist cannot estimate44,151 functions. Ten private audit checks true;
`work/recomp-bench/run5-048-rebuild/` and `run5-048-logs/` contain derived source,
objects, metrics, index pointer and logs. Linux/QEMU is not Android/hardware.

## Selected attachment funnel object cost (iteration47 / Ralph11)

HYPOTHESIS tested: already-selected `9B52C0` can be lifted whole and compiled
without resolving its callback/lock/container dependencies. Reuse the harness:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 9B52C0 --instructions 300 \
  --out work/recomp-bench/NEW-attachment-index.json
python3 scripts/recomp/measure_startup.py --rva 9b52c0 \
  --index work/recomp-bench/NEW-attachment-index.json.env.json \
  --output work/recomp-bench/NEW-attachment
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use exclusive NEW outputs and bounded detached jobs/private logs. Required-index,
exact-entry/extent/provenance and independent boundary checks remain unchanged.
Three authored tests cover selection membership, missing/wrong index, branching
with direct/indirect dependencies, cap rejection and exclusion of an unowned RET.
One fixture initially miscounted four instructions as five; only that count was
corrected. No original body or gate was changed to pass a test.

| RVA | Bytes / instructions / blocks | Analysis | Index check | Lift | Host object | ARM64 object | Linked / matched / QEMU |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 9B52C0 | 190 / 72 / 6 | .003171s | .000402s | .000321s | .518490s | .167190s | no / no / no |

Preflight1.698893s separate; query startup not timed. Ghidra12.2 full extent
agrees; standing log ERROR1 retained. All190 bytes reachable,74 normal-flow
edges. Whole unmodified pinned pcrecomp output is verbatim in object.c. Both
ELF64 ET_REL compile exits0, machine62/183 checked. Objects41,744/47,928B at-O0
are not linked code sizes or cold-build throughput. Measurement exits2 INCOMPLETE.
Two exact direct dependencies `1D4740`/`824632` and four unresolved indirect
calls remain; no callee lift, guessed callback, lock/allocator service or stub.
No x86 reference, ABI/flags/stack/memory comparison, link, QEMU, GuestMemory/
image/runtime integration, attachment ordering or Android evidence is claimed.

Unique totals: selected25/rejected2/attempted15/lifted13/ARMcompiled13(four
object-only)/native-matched9/QEMU9. Nonrandom25 and incomplete pipeline cannot
support an estimate for44,151 functions. Private evidence:
`work/recomp-bench/run5-047-attachment/` and `run5-047-logs/`.

## Selected five-query caller object cost (iteration46 / Ralph10)

Reuse the existing measurement harness; no new selection or callee lifts:

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1ABD40 --instructions 100 \
  --out work/recomp-bench/NEW-cache-index.json
python3 scripts/recomp/measure_startup.py --rva 1abd40 \
  --index work/recomp-bench/NEW-cache-index.json.env.json \
  --output work/recomp-bench/NEW-cache-refresh
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use bounded detached jobs/private logs. The measurement intentionally exits2
for an incomplete pipeline even when both objects compile. The pinned index
must own the exact entry/extent, with uncapped instructions and independent
Capstone boundary agreement; an adjacent return cannot extend the body.

Measured whole selected `1ABD40`: 88 bytes,22 instructions,one block,five direct
calls, no absolute/segmented memory operands or indirect call instructions.
Ghidra12.2 boundaries agree; its standing log ERROR1 remains. Unmodified pinned
pcrecomp emits the entire body verbatim into the object source, retaining five
exact-VA `RECOMP_ICALL` dependencies at1240/1290/12D0/1250/1270. No callee is
newly translated, replaced or stubbed. In particular1290/12D0 behavior remains
unverified. Caller CPU/memory/flags/ABI/ownership behavior is NOT validated.

| RVA | Size | Analysis | Index crosscheck | Lift | Host object | AArch64 object | Linked / x86 matched / QEMU executed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1ABD40 | 88 | .002924s | .000308s | .000135s | .518158s | .167579s | no / no / no |

Preflight1.598823s is separate; analysis times cover decoding/index comparison,
not headless query startup (not timed here). Compiler timings include process
startup and warm caches, not clean-build throughput or a whole-image forecast. Host object
26,368B, AArch64 relocatable object30,016B at `-O0` (not linked code size).
Unique campaign totals now selected25/rejected2/attempted14/lifted12/
AArch64-object-compiled12(three object-only)/native-matched9/QEMU9. The full25
pipeline and an estimate for44,151 functions remain incomplete. Linux AArch64
is not Android/hardware. Private evidence: `work/recomp-bench/run5-046-cache-refresh/`
and `run5-046-logs/`.

## Same-memory selector hot reentry (iteration45 / Ralph9)

Use the `execute_storage_cold.py` command immediately below with a new exclusive
output directory; schema3 retains the cold module/cache publication into a second
selector invocation. Only CPU/stack are reset. Hot name/range/API-slot access,
non-cache module access, module/encoder/API calls and unsupported tails reject.
Guard/FLS/TLS remain authored endpoints; no Windows services are provided.

The2528-case sweep retains all1504 earlier cold scenarios and adds1024 cases:
all32 cookie counts × FLS/TLS × results0/1/80000000/FFFFFFFF × indices0/FFFFFFFF
× preserving/clobbering hot storage endpoints. Clobbers set ECX/EDX to authored
sentinels only after FLS/TLS entry is observed, never at the guard or cold APIs.
Input is28 little-endian words plus4096 stack bytes; appended word27 is the
strict boolean hot-clobber mode. Malformed mode2 is a seventh rejection control.
The cold scenario generator/reference is unchanged.

The existing independent `storage_hot_composed_probe.oracle` checks all eight
caller GPRs, the full4096 stack and complete endpoint GPR/argument/return-RVA/SP
frames. Hot flags are checked in the separately run original x86 reference,
**not** compared natively. Native non-stack pages must be unchanged after hot
reentry. Cold observations retain the preceding partial-state limits. Fresh x86
cold and hot frames are checked separately: only native execution here tests the
longer same-memory selector sequence. Do not call this a same-memory x86 trace.

Input word24 is now a test-only reentry control (normal0); the storage index stays
in the caller stack. Control1 erases cache publication immediately before hot
entry and must reject forbidden cold work. The five prior rejection/recovery
controls remain alongside malformed-clobber rejection. Public tests additionally
inject forbidden hot reads/calls and immutable writes; malformed or changed hot observations reject. Missing inputs,
compiler, QEMU or reference failures remain errors, never skips. Original bodies,
states, generated code and timings stay under ignored `work/recomp-bench/`.

This repeats three existing whole lifts; no unique translation/count increase,
GuestMemory/image/runtime binding, full cold ABI, native hot flags, native PC/RET,
transient writes, FP/SEH, ownership/races, Android/hardware/startup or gameplay
claim is implied.

## Three whole lifts in a cold selector frame (iteration43 / Ralph7)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_storage_cold.py \
  --selector-index work/recomp-bench/run5-033/selector-index.json.env.json \
  --resolver-index work/ghidra/query-out/847E6C.20261023T082112Z.json.env.json \
  --module-index work/phase1-run4-009/module-index.json.env.json \
  --output work/recomp-bench/NEW-storage-cold
python3 -m unittest discover -s tests -p test_recomp_storage_cold.py -v
```

Run bounded/detached with private logs and a new exclusive output directory.
This reuses the three measurement scripts, pinned unmodified pcrecomp, and
validated persistent Ghidra envelopes; no re-import or new candidate. Each whole
lift is inserted verbatim exactly once. Native encoder82F3EC, API, guard and
storage replies remain AUTHORED, not translated bodies or Windows services.
The existing independent x86 composition runs freshly before native comparison.

The1504-case sweep compares EAX/ESP/nonvolatiles, ordered resolver/API/guard/
storage args/returnRVA/SP, module/cache page, immutable pages and stack outside
92-byte scratch. Guard/FLS require target ECX. Original selector name/range and
slot33 are retained; API traps are distinct from storage traps. Only the declared
TLS external tail is accepted; FLS uses a nested call and stdcall4 cleanup.
Five native wrong-stack/load/export/target/cleanup controls must reject, and all
other cases must still match after each rejected record. Input/outputs, lifted
bodies, exact commands/versions/hashes/timings and source audit stay private.

No full cold volatile/flag/scratch/transient-write/native-PC/RET/FP/SEH contract,
Windows storage, lifecycle/ownership/races, GuestMemory/image/runtime binding,
Android/hardware/startup/menu/gameplay is claimed. No additional unique lift or
native-matched function is counted: this composes three previously tested bodies.

## Cold selector composition reference (iteration42 / Ralph6)

```sh
. scripts/campaign/worker-env.sh
python3 tools/storage_cold_composed_probe.py \
  --selector-index work/recomp-bench/run5-033/selector-index.json.env.json \
  --resolver-index work/ghidra/query-out/847E6C.20261023T082112Z.json.env.json \
  --module-index work/phase1-run4-009/module-index.json.env.json
python3 -m unittest discover -s tests -p test_storage_cold_composed_probe.py -v
```

Use bounded detached execution and private logs. This is the independent x86
reference prerequisite, NOT native recompilation: selected whole8480BF selector
executes over whole847E6C/847DA1 in one frame, with original82F3EC reference-only
where called. No new candidate/lift. Resolve entry is observed, never stubbed.
The actual selector supplies its name/range pointers and slot33; load/error/
comparison/export/guard/storage responses remain authored, NOT Windows services.

1504 cases cover cached/cold/failed modules, error87 and both prefix vetoes,
retry, export failure, FLS call vs original-frame TLS tail, edge storage indices
and results, and all32 cookie rotations. Compare final EAX/ESP/nonvolatiles,
ordered endpoint args/returnRVA/SP, whole module/cache page, immutable pages and
stack outside92-byte nested scratch. Guard/FLS require target ECX. Four private
wrong-cache/provider-cleanup controls must reject. Public independently authored
fixtures additionally reject opaque bodies, forbidden writes/targets, bad code,
budget exhaustion and observed-state mutations. No original bytes/states committed.

Cold volatile registers/flags/scratch, transient writes, FP/SEH, ownership/races,
real services, native host/AArch64 composition and runtime binding remain OPEN.
Next: execute the three unchanged whole lifts against this partial-state
reference on host and Linux/AArch64/QEMU. Native encoder remains explicitly
AUTHORED, not a counted translation; Android/startup/gameplay is not established.

## Two whole lifts: cold frame and same-memory hot reentry (iteration41 / Ralph5)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_cold_composed.py \
  --module-index work/phase1-run4-009/module-index.json.env.json \
  --resolver-index work/ghidra/query-out/847E6C.20261023T082112Z.json.env.json \
  --output work/recomp-bench/NEW-cold-composed
python3 -m unittest discover -s tests -p test_recomp_execute_cold.py -v
```

Use bounded detached execution with private logs and an exclusive output. Reuses
both measurement scripts and persistent index envelopes. Two unchanged WHOLE
pcrecomp bodies (847DA1/847E6C) execute on one native stack. Export, encoding,
load/error and comparisons are explicitly authored endpoints, not Windows
services or additional original translations. Encoder82F3EC is NOT selected
or lifted: the existing x86 reference executes it only as before. No26th candidate.

The1336-case bounded sweep covers lengths0/1/2, cached module states, both prefix
vetoes, retries, export failure, all32 cookie counts, edge indices and salts.
Original x86 composition is checked freshly against the existing independent
oracle; the native comparison observes EAX/ESP/nonvolatiles, ordered endpoint
args/return RVA/SP, whole module/cache page, immutable pages and stack outside
64-byte scratch. Return metadata is authored, not native-PC evidence.

Schema2 additionally resets only CPU/stack, retaining the published native memory.
The second invocation compares all eight GPRs and all4096 stack bytes against
`encoded_cache_probe.oracle`, with the original range-end caller argument retained.
Cookie and module/cache pages must remain unchanged; candidate/name/IAT and all
nonselected module/cache addresses now reject reads. Every CALL endpoint rejects,
including the authored encoder. No cache reseeding occurs on successful reentry.
Seven SP/range/load-target/export-target/reserved-export/index/unpublished-hot
controls per ISA must reject the affected case and recover for all others.
The last explicitly erases publication immediately before reentry (input word26=1,
normal=0), forcing forbidden cold work; it is fault injection, not an original input.
Index11 aliases a module slot and rejects. Unsupported CALL/TAIL fails closed.

Cold ECX/EDX/flags/scratch/transient writes, hot native flags, native PC/RET target,
FP/SEH, concurrency/ownership/Windows services remain unverified. This is isolated development execution, not GuestMemory/image/runtime
binding, Android/hardware/startup/render/menu/gameplay or whole-image throughput.
Public tests compile authored fixtures only. No original body/state is committed.

## Whole cold module-acquisition execution (iteration39 / Ralph3)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_module_acquisition.py \
  --index work/phase1-run4-009/module-index.json.env.json \
  --output work/recomp-bench/NEW-module-native
python3 -m unittest discover -s tests -p test_recomp_execute_module.py -v
```

Use bounded detached execution with private logs. This runner re-lifts the same
whole203-byte847DA1 body with pinned unchanged pcrecomp, inserts it verbatim once,
and compares host plus static Linux/AArch64/QEMU execution against the existing
1944-case independent oracle, freshly checked against original x86. No additional
candidate is selected. All branches/calls remain; only load/error/two comparisons
have explicit authored endpoint responses. Unknown targets and the FreeLibrary
race branch reject; injected race rejection is NOT concurrency correctness.

Observations are EAX/ESP, nonvolatiles, ordered endpoint args/return RVA/SP, final
module page, immutable data and stack outside36-byte scratch. The transport supplies
call return addresses explicitly; it does not observe native PC/RET targets.
No ECX/EDX/flags/scratch-stack/transient-write/FP/SEH/ownership/Windows service
contract is established. Four invalid-stack/range/target/race controls per ISA
must reject the affected case and recover for all subsequent cases. Public tests
compile independently authored code against the transport, never game bodies.
This is isolated development evidence, not GuestMemory/image/dispatch integration,
Android/hardware/startup/menu/gameplay or an executable-wide estimate.

## Whole cold module-acquisition measurement (iteration38 / Ralph2)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/measure_module_acquisition.py \
  --index work/phase1-run4-009/module-index.json.env.json \
  --output work/recomp-bench/NEW-module-lift
# Expected exit2: objects compiled, NOT native behavior verified.
python3 -m unittest discover -s tests -p test_recomp_module_acquisition.py -v
```

Use bounded detached jobs/private logs and an exclusive ignored output. Reuses
persistent Ghidra evidence and module_acquisition_probe.py without querying,
re-importing or implementing services. Deterministic supplement selects actual
847DA1 as candidate25/25, retaining every earlier selection/rejection/failure.
Whole203-byte normal-flow body agrees with74 indexed boundaries:17 blocks,
82 edges, all bytes reachable. Six call sites (two direct comparator calls,
four indirect import calls) remain in unchanged pinned pcrecomp output. Known
index ERROR1 retained. Import names establish metadata, not service bindings.

| RVA / bytes | Lift | AArch64 compile | Native match / QEMU |
| --- | --- | --- | --- |
|847DA1 /203|whole unchanged pinned body|ELF relocatable object|NOT compared / NOT executed|

Fresh original-x86 vs existing independent oracle:1944 cases, four wrong-policy
models rejected. Covers module states, both prefix vetoes, error87 retry/failure,
publication, range lengths0/1/2 and two register salts. Observes EAX/ESP, ordered
external args/return RVAs/SP, nonvolatiles, module page and stack outside36-byte
scratch. Does NOT establish volatile ECX/EDX, flags, full scratch-stack, transient
writes, actual comparator/Windows APIs, FreeLibrary/races/ownership, FP/SEH or
native lift correctness. The unexercised race branch remains in the translation.

Six NEW public tests cover selection/cap/duplicates/history, whole-CFG retention,
unsupported/truncated/gap/escape rejection, verbatim body assembly, private outputs,
exclusive/failure metrics and sanitized incomplete CLI semantics. No prior test
or gate changed. Unique totals: selected25, rejected2, attempted13, lifted11,
AArch64-compiled11 (THREE object-only), native-matched8, QEMU8. Selection is full;
measurement of all25 and a representative44151-function estimate are NOT complete.
NEXT: execute this same whole body using checked isolated memory and explicitly
authored endpoints, comparing ONLY the existing oracle's observable components
on host and AArch64; reject unsupported race/unknown targets. Do not infer full
ABI guarantees from this partial-state oracle or bind it to the game runtime.

## Two whole lifts in one hot frame (iteration37 / Ralph1)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_storage_composed.py \
  --selector-index work/recomp-bench/run5-033/selector-index.json.env.json \
  --resolver-index work/ghidra/query-out/847E6C.20261023T082112Z.json.env.json \
  --output work/recomp-bench/NEW-storage-composed
python3 -m unittest discover -s tests -p test_recomp_execute_composed.py -v
```

Use bounded detached execution/private logs and an exclusive output. Reuses the
existing measure scripts and persistent index envelopes, not a new discovery walk.
Both whole pinned pcrecomp bodies are inserted verbatim once. The actual compiled
resolver runs beneath the selector on the same stack; it is NOT an authored
GuestEncodedHotAbi or value-policy substitution. Every resolver external CALL/TAIL
rejects. Guard/storage endpoints remain authored; no Windows service is supplied.

The unchanged storage_hot_composed_probe.py independently checks both original
x86 bodies in one frame against its oracle. The native comparison projects only
eight caller GPRs, the entire4096 stack and ordered endpoint args/return RVA/SP/ECX
from that oracle. Cookie/cache/slot pages must stay unchanged. Native flags, final
PC/RET target, full endpoint CPU, FP/SIMD/SEH and transient writes are NOT compared.
3456 hot cases cover both storage paths, all32 rotate counts, result/index edges,
two salts and endpoint volatile clobbers. Invalid stack/clobber/cold/unknown-target
controls require rejection followed by independent recovery of all later cases.
Public tests compile only authored adapter controls, never proprietary bodies.

This is a two-function composition measurement, not two new selected functions,
a cold resolver implementation, an image/runtime binding, Android or startup.
The 25-function sample and executable-wide throughput estimate remain incomplete.

## Whole resolver hot execution (iteration36 / Ralph11)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_encoded_resolver.py \
  --index work/ghidra/query-out/847E6C.20261023T082112Z.json.env.json \
  --output work/recomp-bench/NEW-resolver-native
python3 -m unittest discover -s tests -p test_recomp_execute_resolver.py -v
```

Use bounded detached jobs/private logs and exclusive outputs. The measurement
rechecks the existing persistent index/image/upstream pins, then includes the
WHOLE133-byte pinned pcrecomp body verbatim once in resolver_transport.c.in.
No cold instructions are pruned. The transport admits only aligned stack words,
one exact cookie word and the selected exact cache word; every external CALL or
TAIL rejects, never returns invented EAX0. The native transport compares all eight
final GPRs, the entire4096 stack and internally requires both cookie/cache pages
unchanged. No native flags/PC/RET-target/FP/SIMD/SEH/transient writes are compared.

The unchanged existing encoded_cache_probe.py oracle/reference checks1332 fresh
original-x86 cases:37 cookies (preserving the earlier eight, adding every missing
rotate count), six decoded values including all-ones sentinel, three indices,
two salts. Four encoded-null cases must reject in x86 and native execution.
Three invalid SP/index/frame controls per ISA must reject while every later case
recovers and matches. Public authored native fixtures additionally check unknown
CALL/TAIL, exact-word/padding/bounds/immutability rejection and truncated inputs;
these fixtures test transport, NOT original code or a replacement resolver.

| RVA / bytes | Lift | ARM build | Native reference match / QEMU |
| --- | --- | --- | --- |
|847E6C /133|whole unchanged pinned body|linked static Linux executable|1332 hot cases +4 cold rejections per ISA|

Synthetic isolated data only: NOT selector composition, cold dependency behavior,
Windows storage, GuestMemory/image integration, Android/hardware or game startup.
Unchanged generated C's native return does NOT prove guest-PC transfer. Next use
storage_hot_composed_probe.py to compose this actual body with the unchanged
selector; keep real storage/guard endpoints explicitly authored and fail closed
on unsupported paths. No new candidate/function is counted for repeat lifts.

## Whole encoded-resolver lift, no cold pruning (iteration35 / Ralph10)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/measure_encoded_resolver.py \
  --index work/ghidra/query-out/847E6C.20261023T082112Z.json.env.json \
  --output work/recomp-bench/NEW-resolver-lift
# Expected exit2: object-only, not native verified.
python3 -m unittest discover -s tests -p test_recomp_encoded_resolver.py -v
```

Use bounded detached jobs, private logs and exclusive ignored output paths.
Reuses the existing persistent index and encoded_cache_probe.py reference;
no query/re-import or new prefix walker. Deterministic supplement selects actual
847E6C as candidate24/25, preserving prior selections, rejections and failures.
Independent normal-flow decoding and all56 indexed boundaries agree:133 bytes,
59 edges, ten blocks, every byte reachable. Cold calls to847DA1/82F3EC and the
indirect slot remain in the unchanged pinned pcrecomp output. GetProcAddress is
PE import metadata, NOT a service binding. Known index ERROR1 retained.

| RVA / bytes | Lift | ARM compile | Native reference match / QEMU |
| --- | --- | --- | --- |
|847E6C /133|whole unchanged pinned body|ELF relocatable object|NOT compared / NOT executed|

Existing bounded original-x86 hot reference matches its independent oracle in
288 cases (eight cookies, six decoded values, three indices, two register salts),
with four wrong-decode controls and four cold-path rejections. This is NOT a
native lift comparison. Host and AArch64 objects compile; CLI deliberately exits2.
Six new public tests check deterministic selection/cap/duplicates, whole-CFG
retention, unreachable-gap/suffix/trap rejection, verbatim body assembly,
private/exclusive outputs and sanitized incomplete CLI behavior. No prior test
or decoder was weakened. No cold behavior, flags/ABI correctness of native output,
Windows storage, game integration, Android or executable-wide estimate follows.
NEXT: execute this unchanged whole body on both ISAs with checked hot-only memory,
fail closed on every external call, and compare against the existing hot oracle
before nesting it with the selector using storage_hot_composed_probe.py. Do not
substitute GuestEncodedHotAbi or silently remove cold instructions.

## Original selector executes with explicit endpoint ABI (iteration34 / Ralph9)

```sh
. scripts/campaign/worker-env.sh
# Reuse the existing private persistent-index envelope; no re-import/query needed.
python3 scripts/recomp/execute_storage_selector.py \
  --index work/recomp-bench/run5-033/selector-index.json.env.json \
  --output work/recomp-bench/NEW-selector-native
python3 -m unittest discover -s tests -p test_recomp_execute_selector.py -v
```

Use bounded detached jobs and exclusive ignored outputs. This reuses
`measure_storage_selector.py` to verify the input/upstream/index, lift the actual
63-byte `8480BF` selector with unchanged pinned pcrecomp, and include its emitted
body verbatim in `selector_transport.c.in`. No new candidate is selected; prior
rejected/failed candidates are retained. A fresh existing x86 rig checks all256
states against the existing independent oracle; the native transport compares
eight final GPRs, the entire4096 stack, and ordered endpoint arguments/return
RVAs/SP/ECX on host and Linux AArch64/QEMU. Eight new public tests cover packing,
full observed-state mutations, strict parsing, body insertion and output gates.

The authored macro adapter replaces only header CALL/TAIL plumbing, not generated
instructions or upstream files. Three explicit call-site return VAs come from
the existing x86/oracle contract, validated by full-stack/frame comparisons.
Unknown targets or wrong call order reject; TLS tail dispatch adds no return word.
Resolver/guard/storage responses are **authored endpoints**, NOT actual resolver
execution, Windows APIs or real thread storage. Invalid entry SP, resolver target
and clobber mode each reject natively on both ISAs; the remaining255 cases must
still match, checking per-case reset. The synthetic slot page must stay unchanged.

| RVA / bytes | Lift | ARM compilation | Native x86 comparison | QEMU |
| --- | --- | --- | --- | --- |
|8480BF /63|unchanged pinned body|linked executable|256/256 GPR/full-stack/ordered-frame cases|256/256; 3 rejection/recovery controls|

No native flags, final PC/RET target, full endpoint CPU snapshots, FP/SIMD/SEH,
transient-write, cold storage, lifecycle/ownership/races/reentry, image/GuestMemory
integration, Android or game startup is established. O0 warm local measurements
are bounded feasibility samples, not whole-executable throughput. Actual resolver
composition is separate; use the already-existing `storage_hot_composed_probe.py`
reference before nesting a generated resolver; measure its whole bounded body
without silently pruning cold paths, and keep cold behavior unverified. `8460CF`
full return and the separate `8480FE` all-ones branch remain open. The prior iteration33 object-only
record below is historical; its native comparison gap is narrowed by this run.

## Real storage-selector lift, explicit indirect tail (iteration33)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 8480BF --instructions 100 \
  --refs 32 --callers 32 --callees 16 \
  --out work/recomp-bench/NEW-selector-index.json --quiet
python3 scripts/recomp/measure_storage_selector.py \
  --index work/recomp-bench/NEW-selector-index.json.env.json \
  --output work/recomp-bench/NEW-selector-lift
# Expected exit 2: object-only, NOT native verified.
python3 -m unittest discover -s tests -p test_recomp_storage_selector.py -v
```

Run bounded detached jobs with private logs and exclusive new output directories.
This supplements the prior22 manifest with8480BF (23/25), preserving rejections.
The63-byte/23-instruction selector was already characterized in
`tools/ptd_query_probe.py`; do not rediscover its ABI with another prefix walker.
The measurement reuses that independent oracle and original-x86 rig:256 cases,
three wrong-cleanup rejections. Resolver/guard/FLS/TLS are **authored endpoints**,
not actual Windows services or the resolver body. Indexed names are HYPOTHESES;
PE import/string metadata does not install a binding.

A separate bounded CFG decoder admits exactly ONE declared absolute indirect
external JMP and retains it as a terminal tail, never RET. All linear instructions
must be reachable; traps, undeclared/register/segmented jumps, escapes, interior
targets and unreachable suffixes reject. Existing normal-return decoder remains
unchanged and rejects the authored indirect-tail fixture. Index boundary evidence
is not a behavioral return guarantee. Seven NEW authored tests cover these gates,
deterministic selection, verbatim generation, private outputs and CLI exit2.

Pinned unchanged pcrecomp emits the original body verbatim with three
`RECOMP_ICALL` sites and one `RECOMP_ITAIL`. Host/AArch64 ELF relocatable objects
compile; no link/native execution/native comparison/QEMU/Android claim.

| RVA / bytes | Category | Dependencies | Boundary agreement | Lift | ARM compile | Native x86 match / QEMU |
| --- | --- | --- | --- | --- | --- | --- |
|8480BF /63|resource, direct/indirect call, stack|847E6C; guard slot; register call; external slot tail|23/23 indexed instructions|yes|object only|no / no|

Existing
`GuestStorageAbi` is an authored model, not a lift adapter: replacing the generated
body with that model would NOT verify recompilation. NEXT: a bounded development
transport for this unchanged generated body, using the existing endpoint/oracle
contract and comparing host/AArch64 integer state, stack and ordered call frames.
Use the existing exact-return seam: pinned upstream header's default ICALL pushes
synthetic RECOMP_RETADDR and unresolved calls set EAX0/print; unresolved ITAIL only
prints. These are not acceptable fail-closed/exact-frame behavior. Keep the body
unchanged, reject unknown targets and add no return word on the tail. No upstream
modification is authorized or needed for the separate development transport.
Actual resolver composition, thread-storage lifecycle and8460CF slow path remain
separate obligations. No executable-wide estimate is supported by this sample.

## Resource storage dependency: first-call frames, not returns (iteration32)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 8460CF --instructions 100 \
  --refs 32 --callers 16 --callees 16 \
  --out work/recomp-bench/NEW-storage-index.json --quiet
python3 scripts/recomp/reference_resource_storage.py \
  --index work/recomp-bench/NEW-storage-index.json.env.json \
  --output work/recomp-bench/NEW-storage-reference
python3 -m unittest discover -s tests -p test_recomp_resource_storage.py -v
```

Use bounded detached jobs and new private outputs. The persistent index and
independent normal-flow decoder characterize 163 bytes/61 instructions/66 edges/
14 blocks. Nine direct call sites target five distinct dependencies; no indirect
call or segmented memory operand in this body. Index names are HYPOTHESES, not
validated CRT/storage service identities or ABI contracts. All query sections
uncapped; known CA-bundle ERROR1 retained.

`frame_plan` independently decodes a deliberately small raw-encoding subset,
including full CMP flags and a single explicit read-only global word. Hook-free
Unicorn single steps compare every GPR, PC, defined integer/DF flag and full
stack/immutable pages after every instruction. CALL pushes the actual return
word, then stops at the target entry: NO callee instruction, invented return,
service stub, native translation or runtime binding. Synthetic global values
zero/one/signed boundaries/all-ones test both first-call paths, not live thread
initialization. Detailed states stay ignored. Translation counts do not change.

The absence of a call-free entry path in these fixtures rejects using this
helper as an immediately executable return dependency. Resolve actual first
callee return/effects before composing 8460CF -> 82A528 -> 82A70A; do not infer
contracts from imported names, prune slow paths or count prefix matches as
successful native translations. Full caller/nonreturn/SEH obligations remain.

## Resource return dependency: measured lift, object-only (iteration31)

```sh
. scripts/campaign/worker-env.sh
# Bounded detached jobs/private logs as in AGENTS.md; reuse the persistent index.
scripts/ghidra-query.sh --rva 82A528 --instructions 100 \
  --out work/recomp-bench/NEW-return-index.json --quiet
python3 scripts/recomp/measure_resource_return.py \
  --index work/recomp-bench/NEW-return-index.json.env.json \
  --output work/recomp-bench/NEW-return-lift
# Expected exit 2: incomplete pipeline even when both objects compile.
python3 -m unittest discover -s tests -p test_recomp_resource_return.py -v
```

The new measurement supplements the historical fixed21 shortlist with82A528
(selected22/25), retaining all earlier candidates/rejections. Its deterministic
`selection()` and private metrics contain the combined manifest; the historical
`select_candidates.py` baseline remains unchanged. This is a dependency-directed
sample, NOT an executable-wide estimate or a replacement for a failed candidate.

Persistent Ghidra and independent normal-flow/linear decoding agree on70 bytes/
31 instructions/31 edges/four blocks. All query sections uncapped; known ERROR1
retained. Calls are assumed returning, NOT executed. Two absolute call slots have
PE import metadata for GetLastError/SetLastError; the direct dependency is8460CF.
Names are metadata, not verified bindings or permission to inject success stubs.

The unchanged pinned pcrecomp emits the original body, included verbatim in an
object-only translation unit. ELF64 relocatable types/machines checked for host
and AArch64. Private recorded warm costs: preflight2.796451s, analysis+index.005322s,
lift.000220s, host object.771213s, ARM object.268752s. No link, reference return/
effects comparison, native execution, QEMU, Android or startup claim. Genuine
translation counts increase by ONE, but matched/executed counts do not.

Seven new authored tests cover selection preservation/cap, dependency separation,
index provenance/boundaries/caps, retained trap/escape rejection, verbatim body/
unsupported-marker checks, exclusive private output/pins and CLI incompleteness.
Actual return/frame effects remain OPEN: calls cannot be traversed hook-free
without resolving dependencies. NEXT ONE: bounded persistent query8460CF and
independent reference evidence for its frame/return contract before composing
82A528. Keep82A4FF, callbacks,82A7B4 nonreturn/SEH/full caller obligations open.
No original-input/upstream/decoder/validator/runtime-binding changes.

## Resource dependency: branch-to-first-call reference (iteration30)

```sh
. scripts/campaign/worker-env.sh
# Reuse the previous persistent private index; no new import/query required.
python3 scripts/recomp/reference_resource_branch.py \
  --index work/recomp-bench/run5-029-logs/dependency-index.json.env.json \
  --output work/recomp-bench/NEW-branch-reference
python3 -m unittest discover -s tests -p test_recomp_resource_branch.py -v
```

Run with the bounded detached/private-log contract. The development-only raw
encoding oracle independently predicts MOV/TEST/PUSH/JZ/JNZ states and stops
BEFORE the first direct or indirect CALL. Hook-free original x86 single stepping
compares every executed instruction's eight GPRs, PC, defined integer/DF flags
(TEST AF excluded), full4096 stack and immutable code/global/payload pages.
The original124-byte/44-boundary index is rechecked, retaining ERROR1 and capped
references/callers. No call target is resolved, read, executed, stubbed or returned.

The1024 HYPOTHESIS inputs use two stacks, zero/nonzero first five argument words,
an explicit readable sixth-argument pointer, a null/mapped pointee and zero/nonzero
field at pointee+35C. Only TWO exact payload words are readable, not arbitrary
page slack; null/unmapped/adjacent reads reject. Two initial fixture hypotheses
failed these checks; no rejected case is skipped. Full-frame raw-oracle tests use
independently authored encodings, including three call cutpoints and corruption.

Measured first-call cuts:82A71C512 cases,82A751256,82A740256; executed instruction
union20/44, not full path/edge/ABI coverage. The indirect cut stops BEFORE reading
the target slot or pushing the call return. No dependency behavior, actual global
ownership, callback identity, return/nonreturn, FP/SIMD/SEH or transient-write
proof. No lift/native/QEMU/Android execution: unique translation totals unchanged.
Next ONE: query direct first dependency82A528 and test its actual bounded return/
frame effects before extending the null-pointee path. Keep82A4FF, indirect handler,
82A7B4 and full caller effects open; no failure-path pruning or service binding.

## Next resource dependency: bounded rejection evidence (iteration29)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 82A70A --instructions 100 --refs 20 \
  --callers 20 --callees 20 --out work/recomp-bench/NEW-dependency-index.json --quiet
python3 scripts/recomp/inspect_resource_dependency.py \
  --index work/recomp-bench/NEW-dependency-index.json.env.json \
  --output work/recomp-bench/NEW-dependency-inspection.json
python3 -m unittest discover -s tests -p test_recomp_resource_dependency.py -v
```

Use bounded detached jobs/private logs. This is inspection, NOT a new translation
or native execution. The persistent index and independent linear decode agree on
124 bytes/44 boundaries. The unchanged normal-return decoder rejects an escape
at82A786, immediately after call82A781→82A7B4. A separately inspected adjacent
instruction is an interrupt; including ONLY that instruction changes the failure
to the existing interrupt-policy rejection. It is not assigned to the indexed
function. Neither indexed noReturn=false nor a nearby trap proves any return ABI.
The branch-before-first-call rejection also prevents reuse of a straight-prefix
oracle. No failed path is pruned, no callback/termination service is stubbed.

Linear dependencies: direct82A528/82A4FF/82A7B4, two indirect calls, two absolute
data addresses, no explicit segmented operand. These counts are NOT a complete
CFG or runtime dependency inventory. Calls82A740 (absolute slotD9A71C) and82A746
(register target) remain unvalidated. Index instruction/callee sections uncapped;
refs/callers capped at20; known ERROR1 retained. HYPOTHESIS: a nonreturning failure
branch explains the adjacent trap, not demonstrated behavior. Next experiment:
bounded original x86 reference for82A70A's branch/first-dependency frames and an
independent oracle, before any caller composition or inferred guard binding.
Six authored tests distinguish indexed extent, adjacent trap, returning branch,
indirect targets, partial windows, private output, pins and exclusivity. Unique
pipeline counts unchanged; Phase1 and representative25 remain incomplete.

## Explicit resource-leaf global hypotheses (iteration28)

Reuse the existing private persistent-index envelopes; no re-import is needed.
Use a new ignored output directory for every invocation, and the bounded detached
execution contract for long commands:

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_resource_leaf.py \
  --index work/recomp-bench/run5-026-logs/dependency-index.json.env.json \
  --caller-index work/recomp-bench/run5-027-caller-index.json.env.json \
  --global-states --output work/recomp-bench/NEW-global
# Optional second explicit suite: add --global-aliases; use another new output.
python3 -m unittest discover -s tests -p 'test_recomp_resource*.py' -v
```

`--global-states` initializes the three statically observed word slots with
zero/mapped payload-pointer combinations, four pointed-byte patterns and two
entry stacks (64 cases). These are **HYPOTHESIS** inputs, not recovered global
initialization or Windows service state. `--global-aliases` requires this option;
it tests explicit pointee profiles at the declared ECX/EDX/argument payload
addresses instead of only distinct pointees. No rejected case is skipped.
Default zero-global inputs and exact two-stack native gates remain unchanged.

Both suites retain continuous original x86 prefix+leaf execution, independent
raw prefix-frame prediction, unchanged pinned pcrecomp leaf output and strict
host/AArch64 Linux/QEMU comparisons (eight final GPRs, four full data pages).
Native execution still starts AT THE LEAF, not at its caller. Neither native
PC/flags/FP/SIMD, real global ownership, exceptions nor full caller return is
verified. Coverage is explicitly reported with uncovered RVAs, not promoted
from matching cases. Optional reference access collection counts prevalidated
explicit operands of executed instructions only; it is not a hook-based memory
trace, implicit-stack journal or transient-write proof.

Each caller-global suite matches64/64 on both ISAs but remains23/26 instructions,
missing82A499/82A49B/82A49E. Thus these global/pointer variations alone do NOT
close that suite's gap. However, fresh default-mode64/64 matches cover22/26 with
a DISJOINT missing set:82A4A0/82A4A6/82A4A8/82A4AD. Verified cross-suite UNION is
therefore26/26 for the same unchanged lifted artifact. This corrects the earlier
caller-only coverage interpretation, not a full edge/path/input/ABI contract.
No additional unique function is counted. Actual Android gameplay,
representative25 selection and whole-executable cost remain unverified.
See task-local PHASE1_REPORT.md for final measurements.

## First resource failure leaf: original differential execution (iteration26)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 82a47b --instructions 128 --refs 8 \
  --callers 8 --callees 12 --out work/recomp-bench/NEW-leaf-index.json
python3 scripts/recomp/select_candidates.py
python3 scripts/recomp/execute_resource_leaf.py \
  --index work/recomp-bench/NEW-leaf-index.json.env.json \
  --output work/recomp-bench/NEW-leaf-native
python3 -m unittest discover -s tests -p test_recomp_resource_leaf.py -v
```

Run long commands detached with real timeouts and private logs. New selection
82A47B (21/25, no replacement) is the first direct dependency of82A6D3, not an
arbitrary easy leaf. Persistent index and independent recursive/linear decoding
agree on72 bytes/26 instructions/27 normal edges, no calls or segmented accesses,
three absolute data dependencies. Known ERROR1 and capped refs/callers retained;
instructions/callees uncapped. Unknown ABI/noReturn=false are metadata only.

`execute_resource_leaf.py` generates64 synthetic entry frames with a mapped
pointer argument and zero-initialized global/payload pages, two stack positions,
four pointer positions and seeded random other registers/stack bytes. Original
code executes hook-free in bounded Unicorn x86 steps, validating byte/word data
accesses before execution, checking code/return pages immutable, and requiring
return to a sentinel and observed SP+8. It covers22/26 instructions, NOT every
branch or real caller/global state. Null/small integer arguments initially
rejected on low-address access; no permission/window was widened to admit them.
HYPOTHESIS: pointer argument obligation; no service identity or live ABI proved.

The existing index-gated measurement emits this original body using unchanged
pinned pcrecomp `Lifter(precise_carry=True, lifted={0xA082A47B})`
`.lift_function(function)`. That body is inserted verbatim into the authored
transport, compiled and executed on host and AArch64 Linux/QEMU. Both match64/64
original x86 final states: eight GPRs and four entire4096-byte data pages. No
native guest PC/flags/FP/SIMD/transient-write comparison, original caller
continuation, callbacks, exceptions, Windows binding, Android or game startup.
Native C return is not guest-PC verification. The guard shares Capstone decoding;
synthetic page slack is admitted. These limits must accompany the match count.

Private metrics.json and its one-row metrics.jsonl retain exact invocation/
upstream/source/reference/template/binary hashes, stage booleans and timings.
Object compilation, linkage, QEMU execution and differential match remain
separate fields; a later comparison rejection cannot turn execution into a match. Public tests use authored fixtures only: byte/word width and
page bounds, branch paths, return cleanup/target, calls/segments/misalignment,
budget, malformed/partial/mutated records, private/exclusive output and compiled
native transport rejection. An early 32-bit-only guard rejected byte MOVs; width
support now applies consistently to the x86 guard and native MEM8/MEM32 adapter.

Cumulative unique selected21/rejected2/attempted9/lifted7/ARMcompiled7 (one other
body object-only)/native-matched6/QEMU6. Selection status is not pipeline status;
no25-function representative sample or executable-wide throughput estimate.
Next: construct independently checked caller82A6D3→82A47B frames and exercise the
four uncovered instructions before promoting the return contract; then remaining
82A70A/82A4C3 effects and82A7B4 nonreturn proof. Resource rejection unchanged.

## Resource failure-path dependency: lift/object cost, not execution (iteration25)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 82a6d3 --instructions 128 --refs 8 \
  --callers 8 --callees 12 --out work/recomp-bench/NEW-handler-index.json
python3 scripts/recomp/select_candidates.py
python3 scripts/recomp/measure_startup.py --rva 82a6d3 \
  --index work/recomp-bench/NEW-handler-index.json.env.json \
  --output work/recomp-bench/NEW-handler
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use timeout-bounded detached workers/private logs. Measurement intentionally
exits2 even after successful object compilation: this is an INCOMPLETE pipeline.
New selected dependency82A6D3 is the first callee observed in iteration24, not
an easier replacement for rejected resource entry1E36F0. Persistent Ghidra and
independent recursive/linear decoding agree on55 bytes/20 instructions/19 edges,
one encoded RET with zero immediate cleanup. All query sections uncapped; known
CA-bundle ERROR1 retained. This does NOT establish actual return/argument ABI.
Three direct dependencies are82A47B,82A70A,82A4C3; no indirect call, absolute data
operand or segmented operand occurs in this body. Their effects remain unknown.
HYPOTHESIS: failure-reporting path, not a validated handler or termination service.

Pinned unmodified pcrecomp c0cbd3e3653010782b17e8a87b58953608ea411c emits this
one original body using `Lifter(precise_carry=True, lifted={0xA082A6D3})`
`.lift_function(function)`. No unsupported marker; all external calls retain
exact-VA dispatch. Host and AArch64 ELF relocatable objects compile; no linking,
original reference execution, native comparison, QEMU, Android or integration.

| RVA | Bytes | Selected | Attempted | Lifted | ARM object | x86 matched | QEMU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0x82A6D3 | 55 | 1 | 1 | 1 | 1 | 0 | 0 |

Private `run5-025-handler/metrics.jsonl`: preflight2.840309s, analysis0.002150s,
index crosscheck0.000413s, translation0.000164s, host object0.569590s,
ARM object0.218055s. Timings are one warm-toolchain sample, NOT verified-function
throughput or a44,151-function estimate. Cumulative unique selected20/rejected2/
attempted8/lifted6/ARMcompiled6 (one object-only)/native-matched5/QEMU5; manifest
status remains selection-only, not a runtime result. Hard failures retained.

Existing index checks now accept this explicitly allowlisted dependency as well
as resource entry, with mandatory pinned envelope, uncapped bounded extent and
exact instruction boundary crosscheck. Three new authored tests enforce required
input, exclusion of unowned trailing RET/trap, cap/end/provenance mismatch and
no expansion to neighboring or unrelated entries. Existing resource trap and
returning-call policy is unchanged. Before any execution beyond the first nested
CALL, query82A47B and establish its actual return/ABI obligations independently.
82A7B4 nonreturn proof remains separate; no success stubs or failure-path pruning.


## Resource boundary: first dependency frame, not nonreturn proof (iteration24)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 82a797 --instructions 96 --refs 12 \
  --callers 12 --callees 12 --out work/recomp-bench/NEW-boundary-index.json
python3 scripts/recomp/reference_resource_boundary.py \
  --index work/recomp-bench/NEW-boundary-index.json.env.json \
  --output work/recomp-bench/NEW-boundary-reference.json
python3 -m unittest discover -s tests -p test_recomp_resource_boundary.py -v
```

Use timeout-bounded detached workers/private logs. Persistent Ghidra resolves
82A797 at entry:28 bytes/16 linear instructions, uncapped instructions/callees,
capped references/callers, known ERROR1 retained. Independent Capstone boundaries
agree; operand semantics are NOT compared with Ghidra. Its `noReturn=true` is
metadata, not a behavioral contract. The terminal indexed CALL82A7AE targets
82A7B4 (indexed name `__invoke_watson`); following traps are not used as proof.

New development-only harness executes the original15-byte prefix through
CALL82A7A1 to82A6D3 and stops BEFORE the callee executes. An independent raw-byte
oracle (no Capstone execution semantics) checks each instruction's eight GPRs,
PC, defined integer/DF flags and complete4096-byte stack. XOR AF is excluded;
code/target pages remain immutable.16/16 synthetic entry frames match:five zero
argument words, saved entry ESI and stack delta-28. This is not a service stub,
a lift, AArch64/native comparison, actual resource reachability or nonreturn proof.
Seven authored tests include corrupt-oracle, bounds, budget, unsupported encoding,
PUSH ESP old-value, memory/control-flow and private/exclusive-output rejection.

Neither nested dependency executes or is replaced. No callee return, final CALL
reachability, unwinding/SEH, FP/SIMD or transient-write behavior established.
HYPOTHESIS: failure-reporting boundary from index metadata only. Resource rejection
and normal-flow policy unchanged; no candidate added. Translation totals remain
selected19/rejected2/attempted7/lifted5/ARMcompiled5/native-matched5/QEMU5.
Next bounded query82A6D3 should establish the first dependency's actual return/
indirect-handler obligations before executing beyond it;82A7B4 nonreturn proof
is still needed before changing the resource flow policy. No executable-wide
throughput estimate or Android/gameplay evidence follows from this reference.

## Resource entry: indexed-boundary/nonreturn rejection (iteration23)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1e36f0 --instructions 224 --refs 12 \
  --callers 8 --callees 16 --out work/recomp-bench/NEW-resource-index.json
python3 scripts/recomp/measure_startup.py --rva 1e36f0 \
  --index work/recomp-bench/NEW-resource-index.json.env.json \
  --output work/recomp-bench/NEW-resource-attempt
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use detached timeout-bounded jobs/private logs. This extends the existing
measurement harness to already-selected1E36F0, not another candidate. Required
index provenance is checked; errors/caps are preserved. The first160-instruction
query was capped. A224-cap query of the SAME persistent function returns185
instructions/607-byte linear extent ending1E394E, untruncated; known CA-bundle
ERROR retained. No re-import/pseudocode. This is indexed extent, not a complete
normal/exception-flow or ABI proof.

Initial1024-byte-window analysis rejected an interrupt at1E394F. The follow-up
shows that byte is OUTSIDE the indexed extent: the final indexed instruction
is a CALL at1E394A to82A797. The corrected resource path now limits decoding to
the uncapped indexed extent; returning-call flow rejects at that boundary
(`escaping-normal-flow`, exit1), BEFORE lifting. Neither failure was hidden.
HYPOTHESIS: a nonreturn/exception dependency; the callee has not been validated.
No new pcrecomp invocation, compile, original reference or native execution.
Pinned upstream files are checked in preflight, not edited. A failure here is
NOT evidence that pcrecomp cannot translate indirect calls.

Structured partial evidence retains180 visited instructions,8 pending addresses,
12 distinct direct targets (including9B52C0),10 encountered indirect call sites,
and the adjacent CALL target. These are traversal-prefix observations, NOT a
complete dependency inventory or observed runtime path. Six new authored tests
cover index provenance/cap retention, required input, bounded indirect calls,
partial rejection evidence, and exclusion of post-extent trap/padding bytes.
Existing trap/overlap/escape/unknown-target and private-output controls remain.

| RVA | Indexed extent | Selected | Attempted | Lifted | ARM compiled | x86 matched | QEMU |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0x1E36F0 | 607 bytes,185 linear instructions; full CFG unknown | 1 (existing) | 1 | 0 | 0 | 0 | 0 |

Cumulative selected19/rejected2/attempted7/lifted5/ARMcompiled5/native-matched5/
QEMU5; repeats add no functions. Final preflight2.782324s/analysis0.008228s are
failure-stage costs, NOT translation throughput. Next diagnose82A797's actual
return/nonreturn/ABI contract before changing either resource or startup-tail
flow policy. No throw/SEH/service stub, runtime binding, precedence change or
Android/gameplay claim. Whole-executable cost estimation remains unjustified.

## First tail helper: unchanged pcrecomp lift and native frame comparison (iteration22)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/select_candidates.py
python3 scripts/recomp/execute_frame.py \
  --index work/recomp-bench/run5-019-logs/dependency-index.json.env.json \
  --output work/recomp-bench/NEW-native-frame
python3 -m unittest discover -s tests -p test_recomp_frame_native.py -v
```

Use bounded detached `setsid timeout` jobs and private logs. This explicitly adds
825BB0 to the fixed selection (19 selected/2 rejected, budget25); no candidate
is replaced. The existing persistent Ghidra envelope is reused without another
query/import, retaining its ERROR and capped references/callers. The image is
pinned before/after reference and native runs. `measure_startup.py --rva 825BB0`
uses the unchanged pinned pcrecomp `Lifter(precise_carry=True,
lifted={0xA0825BB0}).lift_function(function)`. Recursive/linear boundaries agree:
69 bytes/21 instructions/20 edges/one return/no calls. Neither a nonstandard
frame nor FS operands produce unsupported markers: the lifter explicitly emits
FS_BASE accesses. Actual runtime code is NOT silently given a zero FS base.
Dependency metadata records segmented operands separately: FS:[0] is a relative
segment offset, never absolute VA0 or a resolved IAT slot. An authored FS read/
write/call regression enforces this distinction.

`execute_frame.py` builds64 fresh composed original prefix/helper reference
cases using the earlier per-instruction x86/model comparison and independent
raw-encoding PUSH/CALL oracle. Native input is the checked post-CALL helper-entry
frame, NOT a native translation of the caller prefix. The generated helper body
is inserted verbatim once into `frame_transport.c.in`, linked separately on host
and AArch64 Linux/musl, ELF machine checked, and executed on both ISAs (AArch64
through `scripts/campaign/arm64-run.sh`). Compare all eight final GPRs and entire
4096-byte stack/FS/cookie pages; strict64-record transport rejects malformed,
duplicate, extra, incomplete or memory-rejected outputs. Both streams must match
reference and each other before success. Exact invocation/version/source/body/
binary hashes, states and timings stay private. Seven authored public tests
cover these checks, actual transport memory/FS handling and exclusive/private
output. Their tiny public C header fixture tests transport only, not pcrecomp ABI.

Initial native comparison failed64/64 on BOTH ISAs: GPRs/stack agreed, but the
transport initialized FS/cookie page padding with A5 instead of the reference's
6D/B6. Exactly4092 bytes per page differed. A focused regression was made red,
then transport initialization was corrected; reference/full-page comparisons
were NOT changed. Initial failure logs remain private. Final result64/64 per ISA.

This verifies the bounded helper's final frame/data effects, NOT native PC/RET
target transfer, flags/FP/SIMD, full tail ABI, exception dispatch/unwind, actual
startup reachability or Windows services. The native RET is a C return; only its
SP effect is tested. The helper reference shares Capstone between guard/model.
Surrounding frames/page slack are synthetic. Native checked lvalue access does
not isolate read/write permissions; complete final cookie-page comparison detects
persistent writes, not transient writes. No GuestMemory integration, Android
binding, continuation execution or lifted-body rewriting. Tail interrupt rejection
and previous hook SIGBUS remain unchanged. HYPOTHESIS: exception-frame setup.

| RVA | Bytes | Selected | Attempted | Lifted | ARM compiled | x86 reference matched | QEMU executed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0x825BB0 | 69 | 1 | 1 | 1 | 1 | 1 (64 final-state cases) | 1 (Linux, not Android) |

One additional genuine translation, no count for repeated lifts/compiles/cases.
Cumulative campaign counters increase by ONE: selected19/rejected2/attempted6/
lifted5/ARMcompiled5/native-reference-matched5/QEMU5. Existing historical group
results are not newly translated functions. Timings in task report include
fixture/header/process/transport overhead; never extrapolate to44,151 functions.

## Original tail prefix through first helper (iteration21)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/reference_startup_prefix.py \
  --index work/recomp-bench/run5-019-logs/dependency-index.json.env.json \
  --output work/recomp-bench/NEW-prefix-reference.json
python3 -m unittest discover -s tests -p 'test_recomp_*reference.py' -v
```

Use detached timeout-bounded jobs and ignored logs. Reuses the persistent index
(no query/re-import), pinned image and helper reference. Executes only the original
12-byte prefix at824727, its direct call82472E to825BB0, and the69-byte helper;
stops at824733 BEFORE executing the continuation. A separate raw-encoding caller
oracle (no Capstone semantics) checks immediate PUSH sign extension, rel32 target,
CALL return word and full caller stack/GPR/PC after each prefix instruction.
Helper steps retain the prior integer model and actual nonzero-FS GDT transport.
All steps compare full stack/FS/cookie pages and immutable code/GDT/return pages.

Private `run5-021-logs/reference.json`:64/64 pass, two stack entry positions/two
FS bases; stack delta-56bytes and FS stack-head publication64/64. Original caller
return word survives, but this is NOT a normal tail return or full-tail ABI proof.
Entry frames/page slack are synthetic; flags/FP/SIMD/SEH dispatch/unwind and real
startup reachability are unverified. Helper semantics still share Capstone
decoding with the guard. HYPOTHESIS: exception-frame setup, not an SEH service.
Reference/preflight1.994957s is NOT translation throughput. No new lift/selection/
AArch64/native/runtime binding; selected18/rejected2/attempted5/lifted4/ARMcompiled4/
native-matched4/QEMU4 unchanged. NEXT ONE: explicitly select/attempt this dependency
with pinned unmodified pcrecomp against the now-composed reference, retaining any
FS/frame translation rejection; never replace it with authored C or zero-base FS.
Full tail interrupt rejection remains unchanged.

## First tail helper x86 reference (iteration20)

```sh
. scripts/campaign/worker-env.sh
# Reuse iteration19's existing private persistent-index envelope; no new query.
python3 scripts/recomp/reference_startup_dependency.py \
  --index work/recomp-bench/run5-019-logs/dependency-index.json.env.json \
  --output work/recomp-bench/NEW-dependency-reference.json
python3 -m unittest discover -s tests -p test_recomp_dependency_reference.py -v
```

Run long checks detached with a real timeout and ignored private logs. Pins the
read-only image, rechecks the helper's69-byte/21-instruction index boundaries,
and executes the original helper in64 hook-free single-step x86 cases. Two
nonzero FS bases use real32-bit GDT descriptors; flat address zero is unmapped.
Each instruction is compared with a separate Python integer/memory model: eight
GPRs, PC, complete4096-byte stack/FS/cookie pages and immutable mapped code/GDT/
return pages. Stack and cookie-page slack are authored canaries, NOT copied PE
pages; this is not whole-image execution or comparison. Explicit/implicit word
accesses are checked from actual x86 state before each step. Only FS:[0], one
read-only cookie word and the declared stack may be accessed. No hooks, calls,
branches, unknown instructions, external services or exception dispatch admitted.

Actual `run5-020-logs/reference-final.json`:64/64 match;64 FS heads become stack
addresses. Eight observed net stack deltas range from-136 to-24 bytes for the
synthetic helper-entry inputs. This independently disproves an unchanged/cdecl
caller-frame assumption for THESE inputs, not a complete actual caller ABI.
Frames are deliberately synthetic; the original tail prefix is NOT executed.
The integer model shares Capstone decoding with the access guard; decoder bugs
are a common-mode risk. Flags/FP/SIMD and SEH dispatch/unwind are not compared.
HYPOTHESIS: exception-frame setup, still not a validated exception service.

Authored tests use known FS/frame/arithmetic results, actual nonzero segment
transport, descriptor encoding, register/memory/PC corruption, unsupported-flow/
range rejection and private exclusive output. The script is development-only,
not an x86 interpreter shipped in Android, a replacement helper, or a lift.
Selected18/rejected2/attempted5/lifted4/ARMcompiled4/native-matched4/QEMU4 stay
unchanged. Reference/preflight2.784892s is NOT translation throughput. Next test
the original bounded caller prefix through the helper with an independent caller
frame oracle, before selecting/lifting it; preserve the tail interrupt rejection.

## First tail dependency inspection (iteration19)

```sh
. scripts/campaign/worker-env.sh
# ONE bounded query of the existing project; no re-import, no pseudocode.
scripts/ghidra-query.sh --rva 825bb0 --instructions 32 --refs 12 \
  --callers 8 --callees 12 --out work/recomp-bench/NEW-dependency-index.json
python3 scripts/recomp/inspect_startup_dependency.py \
  --index work/recomp-bench/NEW-dependency-index.json.env.json \
  --output work/recomp-bench/NEW-dependency-inspection.json
python3 -m unittest discover -s tests -p test_recomp_startup_dependency.py -v
```

Use timeout-bounded detached worker jobs for long checks. The harness pins the
existing image, requires the first contiguous direct tail call to target825BB0,
and independently decodes at most128 bytes at that dependency. It compares
instruction boundaries/extent to the read-only Ghidra envelope, retaining log
errors and caller/reference truncation. It does NOT compare operand semantics or
trust the indexed signature. `extentEndVa` from Sims2Query is an INCLUSIVE byte;
an exclusive-end fixture must reject. No original text/bytes are emitted.

Measured: call82472E targets825BB0; indexed function-at and independent decoding
agree on21 instructions/69 bytes, one return, no calls. FS read/write and explicit
ESP/EBP writes are observed. HYPOTHESIS: exception-frame setup; neither an ordinary
cdecl ABI nor complete SEH behavior is established. Encoded RET cleanup0 is NOT a
net-stack-delta proof. No segment state or helper service is synthesized.

Authored tests cover first-call ordering/indirect/branch/trap rejection, segment
and explicit-frame-write metadata, normal-flow failures, boundary/provenance
mutations and exclusive private output. This is inspection of one dependency,
NOT a new selected/attempted/lifted/compiled/reference-matched/QEMU candidate.
Selected18/attempted5/lifted4/ARMcompiled4/native-matched4/QEMU4 remain inherited.
The tail interrupt rejection stays intact. Next establish the helper's frame and
FS effects with a bounded original x86 reference and independent stack oracle
before selecting/lifting it. No executable-wide throughput estimate is justified.

## Entry-tail translation rejection (iteration18)

```sh
. scripts/campaign/worker-env.sh
# Query the existing persistent project once; keep output private.
scripts/ghidra-query.sh --rva 824727 --instructions 32 --refs 12 \
  --callers 8 --callees 12 --out work/recomp-bench/NEW-tail-index.json
python3 scripts/recomp/measure_startup.py --rva 824727 \
  --output work/recomp-bench/NEW-tail-attempt
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
python3 -m unittest discover -s tests -p test_recomp_selection.py -v
```

Run long commands through the bounded worker execution path. Candidate18 is
824727, the unresolved original-entry tail, not a replacement for a hard case.
The selection stays below25; existing rejection records remain. The query is
address-only with zero indexed instructions; nearest-function metadata does NOT
supply a boundary. Historical normal-flow analysis is a HYPOTHESIS, not execution.

The measured attempt rejects in analysis (exit1), before any pcrecomp lift or
object compilation: a reachable terminal interrupt requires an explicit nonreturn
policy. The initial attempt instead reported escaping normal flow at the excluded
entry; independent decoding isolated the interrupt immediately before that entry.
The decoder now explicitly rejects interrupt-group instructions rather than
silently treating them as normal fallthrough, RET or an authored success stub.
`analysis_rejection=interrupt-without-nonreturn-policy` is retained in private
metrics. Authored tests reject traps even when a later RET or alternate return
path exists, reject crossing into the known entry, and retain prior CFG controls.

This adds ONE attempted candidate, ZERO successful lifts/compiles/reference
matches/QEMU executions. Unique current totals: selected18, rejected2,
attempted5, lifted4, AArch64-compiled4, independently native-matched4 (inherited
successes, not rerun by this attempt). This is not an executable-wide estimate.
No trap, unknown helper, tail body or service is executed or bound. Next inspect
the earliest direct tail dependency before proposing a scoped nonreturn/SEH
contract; do not cut out the failing branch to count a translation.

## Persistent image entry observation (iteration17)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/verify_startup_image.py --entry-boundary \
  --output work/recomp-bench/NEW-entry-image
```

Optional entry mode reuses all THREE existing pinned lifts/provenance from
`run5-012-entry`; no new translation. Entry8248A3 -> initializer8258A9 ->
helper82585C each cross the production exact-VA dispatcher on the same image.
Only that nesting is admitted. The external tail824727 is deliberately **not
bound** in GuestDispatch: the authored observation endpoint captures register
state and throws a private typed stop through generated/native frames. Only
the outer observer catches it and returns the boundary PC. No generated tail
continuation, target instruction, guest return or stack cleanup occurs. A
returning entry, wrong stop target or stop from another scope fails closed.
This is C++ diagnostic unwinding, NOT guest SEH/unwind implementation.

The entry frame permits one additional aligned stack word (48 bytes below
original SP, versus44 in pair-only mode); all other image/overlay restrictions
below remain. Entry comparison additionally requires the exact stop EIP and
original caller SP, a complete fresh x86/oracle stack, and same-memory native
replay invariants. Replays remain oracle-only, without another x86 run. The
existing pair command and authored dual-ISA tests below remain regression gates.
No Windows services, PE execution, Android binding or game boot is provided.

## Persistent image startup pair (iteration16)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/verify_startup_image.py \
  --output work/recomp-bench/NEW-startup-image
python3 -m unittest discover -s tests -p test_recomp_startup_image.py -v
TS2_IMAGE_TEST_TARGET='-target aarch64-linux-musl -static' \
TS2_IMAGE_TEST_RUNNER="$PWD/scripts/campaign/arm64-run.sh" \
  python3 -m unittest discover -s tests -p test_recomp_startup_image.py -v
```

Use bounded detached execution and ignored private logs. Requires existing
`run5-012-pair` pinned bodies/provenance plus the authorized pinned image and
unmodified pcrecomp runtime; missing inputs fail, never create a new lift.
The two existing bodies are inserted verbatim and compiled as C++ with a checked
word proxy: conversion uses production GuestMemory::read32, assignment uses
write32. No raw host-memory pointer is exposed and no generated instruction is
edited. The new **separate development** adapter uses persistent GuestImage and
GuestDispatch; the previous read-only adapter and overlap rejection are unchanged.
Outer initializer and nested helper each cross the exact-VA dispatcher. Only
outer-to-helper nesting is allowed. Exceptions unwind invocation scopes; writes
are not transactional and callbacks are trusted, not sandboxed.

Setup writes one non-image 4096-byte stack and exactly the cookie/complement
words, never the synthetic data page. Execution permits only aligned stack reads,
44 bytes below original SP for stack writes, two exact global words and four
read-only IAT endpoint overlays. Physical IAT bytes are preserved; endpoint APIs
are authored deterministic diagnostics, NOT Windows entropy/security services.
The bounded fresh x86/oracle320 reference is retained. Native comparison checks
EAX, nonvolatile GPRs, return SP, endpoint order, the complete actual stack and
the two global words. The unrelated synthetic A5 data page is explicitly NOT
compared as though it were real memory. Instead the complete mapped image,
including physical IAT, BSS, gaps and headers, is compared before/after execution,
excluding ONLY the two declared global words. Same-memory native replays verify
the normalized-cookie bypass oracle and unchanged stack/globals without setup;
these replays have no second x86 execution. No flags/volatile/FP/SIMD/SEH or
concurrency claim. Linux/AArch64 QEMU is not Android or hardware. This is a
production-memory boundary experiment, not APK integration or game boot, and
adds zero unique translations.


## Startup pair: measured writable-memory requirements (iteration15)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/assess_startup_memory.py \
  --output work/recomp-bench/NEW-startup-memory
python3 -m unittest discover -s tests -p test_recomp_startup_memory.py -v
# Production rejection controls, host and Linux/AArch64:
python3 -m unittest discover -s tests -p test_recomp_image_dispatch.py -v
TS2_IMAGE_TEST_TARGET='-target aarch64-linux-musl -static' \
TS2_IMAGE_TEST_RUNNER="$PWD/scripts/campaign/arm64-run.sh" \
  python3 -m unittest discover -s tests -p test_recomp_image_dispatch.py -v
```

Use bounded detached jobs and private logs. No new lift or native startup
integration is claimed. The existing pinned image/index/import/reference checks
run first, unchanged. Optional hook-free access journaling in `exercise` then
records decoded explicit reads/stores (including same-value stores), selected
implicit PUSH/CALL/POP/RET/LEAVE stack accesses and authored endpoint writes.
This is a narrow diagnostic journal, not a general instruction tracer/sandbox;
setup writes are excluded. Existing reference behavior without journaling remains
unchanged. Full final stack/data pages and existing register/frame/event oracle
checks remain mandatory. Independent writable-scope controls reject IAT/code/
page-slack writes, bad endpoint output pairs and absent global publication.

Private `run5-015-assessment/result.json`: 320 x86/oracle cases,160 helper calls
and160 bypasses; up to44 distinct stack bytes written below original SP. Both
paths store the complement at RVA104F580; initialization also stores cookie at
104F540 (4 versus8 global bytes). Four exact IAT slots are read. Stacks remain
outside the mapped image. Existing reference6.351523s; journal+x86/oracle5.571204s,
including process/fixture overhead, NOT recompilation throughput. No new function
or AArch64 translation is counted.

The actual production read-only adapter rejects both exact startup VAs even
with supplied callbacks/non-image storage; public authored controls prove zero
callback invocation and unchanged registers on both ISAs. Current image-overlap
rejection and whole-image immutability must NOT be removed to force a pass.
Next: a separately scoped writable adapter for these two globals plus stack,
with explicit read-only IAT/endpoint binding, nested decoded call returns and
whole-image comparison excluding ONLY declared mutations. Existing copied data
page initialization cannot overwrite a real mapped page. This remains future
work; no real Windows services, flags/FP/SEH/concurrency or Android startup claim.

## Fresh non-image input reference for existing leaf1250 (iteration14)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/verify_image_leaf.py \
  --output work/recomp-bench/NEW-image-leaf
python3 -m unittest discover -s tests -p test_recomp_image_leaf.py -v
```

Run bounded/detached with private logs. This explicitly allocates a NEW32-case
fixture at object `B0001000` and stack `B0003000`, after checking both spans are
outside the pinned PE's mapped extent. It never edits/relocates the historical
saved96 states or removes the image-overlap guard. Only existing leaf1250's
pinned generated body is inserted verbatim from the historical source; no new
translation/function is counted. The authored callback copies integer state and
resets the existing lazy flags; it does not implement the original function.

Fresh bounded Unicorn x86 execution at the original VA is compared against an
independent modular arithmetic/register/flag/no-write oracle before compiling.
The reference uses at most64 hook-free single steps per case: a narrow development
instruction allowlist and decoded effective addresses reject stores, segments,
out-of-span reads, page gaps, unsupported instructions and escaping control flow.
All three mapped4096-byte reference pages are compared before/after. The first
hook-based attempt crashed process135; no reference/native pass came from it.
Hook-free stepping avoids those hooks, not their validation obligations. Only
undefined AF on the logical branch is normalized; FP instructions are not tested.

The same generated fixture links the actual `image_dispatch.cpp` and production
`libts2_core.a`, NOT either copying bridge. Each ISA process retains one loaded
GuestImage/GuestMemory/exact-VA dispatcher over all32 cases and checks the full
mapped image before/after successful execution. Both native32-case streams must
match every x86 state (eight GPRs, transported flags, return SP, no-write memory
result and zero FP transport) and each other. The callback snapshots/compares all
68 words of the actual persistent object/stack spans around the unchanged body;
native same-page gaps are not included in that input snapshot. Exact commands/timings, binary/body/
input hashes and fresh states stay private in `result.json` and child logs.
Production initialization/snapshot/process overhead is included; this is not
per-function translation throughput. Input memory copies/callback globals are
not transactional; only the tested read-only, single-owner boundary is covered.
No invalid game-pointer semantics, callback ownership, imports, Windows services,
startup, renderer, Android binding or gameplay is established. QEMU is Linux
AArch64 instruction execution, not Android/hardware.

## Persistent image-backed dispatch assessment (iteration13)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/verify_existing_group.py --image-memory \
  --output work/recomp-bench/NEW-image-dispatch
# Current pinned fixture: expected exit1, NOT a verified integration.
python3 -m unittest discover -s tests -p test_recomp_image_dispatch.py -v
TS2_IMAGE_TEST_TARGET='-target aarch64-linux-musl -static' \
TS2_IMAGE_TEST_RUNNER="$PWD/scripts/campaign/arm64-run.sh" \
  python3 -m unittest discover -s tests -p test_recomp_image_dispatch.py -v
```

Use bounded detached execution and private logs. The opt-in mode reuses the
unchanged pinned three-leaf artifact and saved96 states; no new lift or reference
is claimed. The existing preparer retains generated bodies and input cases.
Only its read/dispatch symbols and header change; C `main` is renamed at compile
time. The old copying bridge is **not linked** in this mode. Public
`image_dispatch.cpp` loads the authorized PE as data using production
`load_guest_image`, retains ONE `GuestMemory` and exact-VA `GuestDispatch` across
cases, and supplies the narrow C callback seam. No runtime x86 decoding occurs.

Input spans may not overlap the mapped image. This is intentional: the existing
synthetic high-bit fixture places an input span inside that image range. Both
ISAs reject BEFORE copying/dispatching the first case (process105); no original
leaf executes and no state comparison passes. The runner records both failures
and rehashes the unchanged image before failing its completeness gate (CLI1).
Do not relocate saved states silently, drop the overlap guard, or overwrite code
pages to obtain96 matches. Next: explicitly allocate non-image inputs for ONE
existing verified leaf and obtain a new independent bounded original-x86
reference for those relocated addresses before attempting native comparison.

Public authored controls execute the actual adapter with a synthetic PE and
non-image spans: repeated persistent reads, same-page gaps, crossing/wrapping
reads, reentry, exceptions, unresolved/duplicate entries, image-overlap rejection
and recovery. They do not execute original game code. Every successful fixture
run compares the ENTIRE mapped image (headers, sections, gaps, BSS) before/after.
A failed fixture returns no successful immutable-image claim; original disk input
is separately rehashed by the Python runner. Input copies and memory commits are
not transactional; callback globals/external effects are not rolled back. This
trusted single-owner diagnostic is not a sandbox or general runtime adapter,
and is excluded from Android. Default read-only mode remains unchanged.


## Selected entry native comparison at external-tail stop (iteration12)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_startup.py --call-returns --entry-boundary \
  --output work/recomp-bench/NEW-entry-native
python3 -m unittest discover -s tests -p test_recomp_startup_native.py -v
python3 -m unittest discover -s tests -p test_recomp_call_returns.py -v
```

Run long commands detached with a real timeout and private logs. Entry mode
requires the explicit call-return adapter; default pair/dummy-return behavior is
retained. Three unchanged pinned pcrecomp bodies (selected entry8248A3 plus the
existing pair8258A9/82585C) are inserted verbatim. `derive(entry=True)` rechecks
the image pin and exact ten-byte entry flow, then derives the unique entry CALL
return VA; the inventory becomes six calls, not a guessed execution order.
Repeated targets and runtime aliases still reject. No upstream source is edited.

The lifted ITAIL remains unchanged. Exact target824727 resolves ONLY in entry
mode to a **non-returning observation stop**, which verifies the entry caller,
records the boundary VA and longjmps out before any target instruction executes.
It never pops the caller frame, returns to lifted code or supplies target behavior.
Any unexpected normal return rejects. Endpoint frames shift by the additional
outer CALL word; no endpoint/stack/oracle check is relaxed. Unknown dispatch still
rejects. This is a diagnostic fixture, not a general tail ABI or runtime binding.

Actual private `work/recomp-bench/run5-012-entry/result.json`: host320/320 and
AArch64 Linux/QEMU320/320 match a fresh bounded original x86 entry reference AND
the unchanged independent composed oracle; complete native streams agree.
Compared: EAX, nonvolatile GPRs, original caller SP/return word, entry CALL return,
full4096 stack/data pages, ordered strict endpoint frames/pointers/cleanup and
external-tail boundary VA. No final flags/ECX/EDX/FP/SIMD/SEH/transient-write/
concurrency/Windows-service/game-startup claim. The target body is NOT executed.

Measured seconds (single observation, not steady-state throughput): x86 reference
with preflight/process10.382932; per-body lift entry.000047, initializer.000173,
helper.000163; joint host compile/link.568650, execution/transport.115256,
comparison.016520; joint ARM compile/link.317468, QEMU execution/transport1.116599,
comparison.014193. Metadata preflight1.702602. Costs include tool/cache/header and
transport overhead and are not separable per-function engineering effort. No
44,151-function estimate follows. Unique selected17/rejected2/attempted4/lifted4/
ARMcompiled4/native-reference-matched4; no extra functions counted for cases,
objects, repeated lifts or the authored observer. Android remains false.

Next: assess one existing verified translation through the real native guest
boundary on both ISAs, without publishing its body or substituting authored code.
Do not broaden into824727 or claim game startup from this boundary comparison.

## Opt-in decoded startup call-return ABI (run5 iteration9)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_startup.py --call-returns \
  --output work/recomp-bench/NEW-call-returns
python3 -m unittest discover -s tests -p test_recomp_call_returns.py -v
```

Use bounded detached worker execution as below. Default mode retains iteration8's
upstream ABI failure. `--call-returns` uses authored `call_returns.py` to decode
only the two existing selected bodies from the pinned read-only image, with the
existing bounded recursive/linear decoder. It derives caller, target (direct VA
or absolute IAT slot), and instruction-end return VA. Repeated same-target calls
within one caller and register/based operands reject: target-only generated calls
cannot identify their sites. Runtime IAT aliases, unknown caller/target and
unresolved dispatch reject before pushing. No execution-order guesses.

An explicit diagnostic ICALL macro supplies these return VAs and preserves the
upstream register/flag transfer seams and caller restoration. Both freshly lifted
bodies remain byte-identical and occur exactly once; upstream is not modified.
This is an adapted call ABI, NOT unmodified upstream runtime behavior or a general
solution for repeated targets, callbacks or changing IAT bindings. No hand-written
original-function replacement, runtime x86 decoding or shipped binding exists.
Metadata decoding is development-time only; generated binaries contain a table.

Actual `work/recomp-bench/run5-009-native/result.json`: fresh original x86/oracle
320/320; four negative controls rejected. Host and AArch64 Linux/QEMU each match
320/320 with byte-identical outputs, no rejected/mismatched cases. This verifies
the bounded startup pair under deterministic authored API responses, not game
startup or Android. Comparisons retain EAX/nonvolatile GPRs/return ESP, full4096
stack/data and strict ordered API frames/return addresses/zeroing/cleanup. Final
flags/ECX/EDX/FP/SIMD/SEH/transient writes/concurrency/real Windows services are not
validated. Checked lvalue memory and fixture lookup are not GuestMemory/Dispatch
integration or a sandbox; native processes have timeouts, not instruction budgets.

Joint host compile/link .568421s; ARM .317528s; host execute/output .115258s;
QEMU 1.116185s; compares .015565/.013803s; metadata pin/parse/decode 1.691752s.
Per-function analysis/lift and exact commands/hashes remain private in the child
metrics. Single cached observation with fixture/process/output overhead, NOT
whole-executable throughput or per-function joint compilation costs. Unique run5
selected17/rejected2/attempted3/lifted3/ARMcompiled3/native-reference-matched3;
prior iteration8 pair failures remain historical evidence. No new candidates.


Run 5 starts by executing the **existing** three-function pcrecomp artifact,
not by writing another equivalent C implementation or relifting more functions.

```sh
. scripts/campaign/worker-env.sh
# Use a new private output directory each time, with the documented worker
# setsid + timeout execution path for the whole command.
python3 scripts/recomp/verify_existing_group.py \
  --output work/recomp-bench/NEW-group
python3 -m unittest discover -s tests -p test_recomp_existing_group.py -v
```

Requires both configured `build/host` and `build/arm64` trees (README Linux/AArch64
instructions), pinned private `group.c`, analysis image and saved reference JSON.
Missing inputs fail; no downloads, image recovery, fixture synthesis or new lift.
The runner refreshes both native libraries before compiling, uses the same adapted
source for both ISAs, validates ELF machine IDs, executes AArch64 through the
existing `scripts/campaign/arm64-run.sh`, and invokes the unchanged pinned 96-state
comparator for **each** output. Both successful executions/comparisons plus identical
stdout are required before `success` and `arm64_executed` become true.

`result.json` retains exact command arguments, per-command wall seconds, hashes,
exit codes and matched counts. Raw stdout, derived source, binaries and logs stay
in a new mode-0700 directory under ignored `work/recomp-bench/`. It does not mutate
the historic `group-result.json`, original fixtures or installation. Each subprocess
has a 180-second limit; bound the whole worker command as well. A failed stage
leaves `success=false` (except failures before output-directory creation, which
create no report). No failed process is retried or counted as verified. The
upstream reviewed-file hashes are verified without fetching or patching.

## What the comparison establishes

| RVA | Size | Category | Saved cases | Translation origin |
| --- | ---: | --- | ---: | --- |
| `0x1240` | 11 | pointer read / simple leaf | 16 | existing pinned pcrecomp artifact |
| `0x1250` | 27 | branching arithmetic / pointer reads | 32 | existing pinned pcrecomp artifact |
| `0x1270` | 30 | guarded arithmetic / pointer reads | 48 | existing pinned pcrecomp artifact |

All three are historical reviewed leaf ranges with no game imports, direct or
indirect calls, or game-global dependencies; their data dependencies are the
caller-supplied object and stack spans. Boundary evidence and original range
pins are recorded in `docs/LOCAL_VALIDATION.md`; this run performs no new Ghidra
boundary analysis and does not treat automatic pseudocode as a correctness oracle.

All eight GPRs, transported defined flags, return-stack effects, FP transport and
tracked byte-level memory deltas are checked against the pinned saved x86 states
by `tools/check_private_readonly_dispatch.py`. Undefined AF normalization and legacy
lazy flags remain fixture-specific. These functions contain no FP operations;
FP transport agreement does not validate FP instructions. Invalid-pointer behavior,
OS services, callbacks and concurrency are not covered. The prep tool preserves
lifted bodies and case data, adapting only the checked-memory/dispatch seam into
`GuestMemory`/exact-VA `GuestDispatch`.

The original generation is documented in `docs/LOCAL_VALIDATION.md`, performed by
private `group_probe.py` using pinned pcrecomp `Lifter(precise_carry=True)`; its
artifact SHA is checked by the existing preparer. **This runner does not measure
fresh analysis or translation time and must not be reported as doing so.** Build,
compile, link, execution and comparison times are joint three-function fixture
costs, including test scaffolding; dividing by three is not a per-function lift
estimate. New selection/attempt/lift counts for this checkpoint are zero. Three
historically lifted functions are compiled and compared on both ISAs when the
runner succeeds. Saved x86 comparison is not fresh original x86 execution.

## Deterministic candidate selection

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/select_candidates.py > work/recomp-bench/selection.json
cmp scripts/recomp/candidates.json work/recomp-bench/selection.json
python3 -m unittest discover -s tests -p test_recomp_selection.py -v
```

Create the ignored parent directory first. The CLI hashes the read-only analysis
image before emitting anything; a missing/wrong pin fails with no manifest or
private path in the error. `--image` may name another owner-controlled copy but
cannot change the accepted hash. Output is metadata only and deterministic:
no paths to private files, code, states, timestamps or ambient environment values.
The checked-in `candidates.json` is that exact output, not a fabricated run report.

The current **17-function** shortlist is deliberately below the authorized 25-function
ceiling (eight places remain for evidence-driven dependencies, not padding).
Iteration5 explicitly added startup helper82585C, with matching manifest/test
changes, after bounded dependency evidence; the original16 remain selected.
All six requested resource/caller/constructor seeds are retained, as are the
original-entry/first-dependency pair and callback/jump-table paths. Historical
references are preferred for the first fresh attempts, regardless of manifest
rank. Rank is selection priority, NOT execution order; it keeps hard functions
visible before easy leaves. All seven stress categories occur. Categories and
roles are **HYPOTHESES** from cited static evidence, not behavioral validation.
This is purposive dependency sampling, not a statistically representative sample.

Rejected suggestions `0x1AB79C` (a call instruction) and `0xC261A1` (an immediate
site with an address-only index result) are retained with reasons rather than
promoted to functions. They are not lift failures or extra attempted functions.
There is no CLI to silently lower the cap or replace hard cases after a failure.
Changing the shortlist requires a reviewed source/manifest/test change; the code
rejects a duplicate or a catalog exceeding 25 rather than truncating it.

Manifest sizes are present only for four historically reviewed ranges; all other sizes,
dependencies and Ghidra boundary reliability remain **null / unmeasured**, not
zero, absent or passed. Historical range evidence is distinct from Ghidra boundary
proof. Current selection counts are selected17/rejected2; attempted/lifted/AArch64-compiled/reference-
matched/QEMU-executed are all zero **for this selection operation**. The previous
three-function execution checkpoint remains separate and is not erased or recounted.

## Fresh single-leaf cost measurement

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/measure_leaf.py --output work/recomp-bench/NEW-leaf
python3 -m unittest discover -s tests -p test_recomp_leaf.py -v
```

Use the documented detached worker execution path, with a real overall timeout
(e.g.360s). Each child compile/execution is bounded to120s. The output must be new
and below ignored `work/recomp-bench/`; resolved symlink escapes and clobbering
reject. Its `metrics.jsonl` records one candidate even on a post-creation failure,
with stage/type, partial flags, exact CLI/interpreter, lifter invocation/version,
input/tool hashes, subprocess argv/exit/times and separate pipeline timings.
Raw derived source, logs and states remain inside the mode0700 output directory.
Missing inputs fail, with no downloads, recovery, protection work or PE launch.

Only selected RVA1250 is freshly lifted and compiled in this runner. The pinned
private `group_probe.py` supplies the existing deterministic cases and fixture
assembly, NOT replacement C logic; its main is never invoked. The private
pcrecomp lifter is loaded first and its actual module origin is checked. Reviewed
lifter/runtime files match pristine pins; block-wrapper/disassembler files are
also compared to the existing pristine archive tree, with their digests retained.
The separate DRM parser is not imported. Upstream is never patched.

Analysis checks the historical27-byte range/hash and exact3-block partition,
rejecting misaligned/incomplete blocks, escaping branches and calls. Translation
is exactly `Lifter(precise_carry=True).lift_function(function)`; it generates the
body anew. The fixture's historical rebased decode address is0xA0000000, while
input bytes come from real RVA1250; this leaf has no PC-relative data or calls.
Only registry entries/count are filtered during fixture assembly; the generated
body is not rewritten. This is the existing checked read-span fixture, **not** a
new GuestMemory/GuestDispatch runtime integration. Its32 cases are compared to
exact saved reference slice[16:48] after hashing the entire unchanged96-state
reference. All integer registers, transported flags, stack effects, byte memory
deltas and zero FP depth/empty FP transport must match. No fresh x86 run occurs.

Iteration3 final measurement (`work/recomp-bench/run5-003-final/metrics.jsonl`):

| RVA | Size | Attempted | Lifted | ARM64 compiled | Host saved-x86 match | QEMU executed / saved-x86 match |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 0x1250 | 27 | 1 | 1 | 1 | 32/32 | yes / 32/32 |

Seconds (single observation, no cold-cache guarantee): preflight/cases1.781685,
analysis0.001402, translation0.000104, fixture assembly0.006680,
host compile+link0.667608, host execution0.034331, host comparison0.001060,
AArch64 compile+link0.317715, QEMU execution0.265449, comparison0.000849.
Compilation includes fixture/flag/memory scaffolding and linking; execution
includes32 cases and output, and QEMU includes wrapper/startup. These are NOT
isolated instruction costs, steady-state throughput or fresh Ghidra-analysis
costs. Historical boundary analysis effort and engineering time are unmeasured.
Cached Ghidra1250 envelope resolves function-at with one known log ERROR, not
proof of full reliable boundaries (JSONL reliability remains null).

The manifest still selects16/rejects2; this measurement attempts/lifts/compiles/
reference-matches/QEMU-executes **one** function, not32 or96. All other15 selected
candidates remain unattempted by this runner; failures are not silently replaced.
Five public tests cover block boundaries, observable/count corruption, incomplete
stage claims, missing inputs, no-clobber and symlink escapes. They are policy
regressions, not original-game comparisons; the private CLI supplies that evidence.
Batch orchestration/failure isolation between functions is still NOT established.

## Selected startup dependency: mechanical lift, unverified object compilation

```sh
. scripts/campaign/worker-env.sh
PY=$(command -v python3)
"$PY" scripts/recomp/measure_startup.py --output work/recomp-bench/NEW-startup
# Expected exit2: incomplete pipeline, even when both objects compile.
"$PY" -m unittest discover -s tests -p test_recomp_startup.py -v
```

Run through bounded `setsid` + `timeout` with logs under ignored `work/`.
The runner exclusively creates a mode0700 output directory. It hashes the same
read-only image, verifies pinned pristine sources and unchanged private lifter
files, checks the actual imported lifter origin, and uses exact VA A08258A9.
No historical fixture rebase, recovery, service stub, PE launch or nearest-function
substitution occurs. The selection manifest remains unchanged.

Reuses the iteration2 persistent Ghidra query (address-only/zero instructions,
correct pin, known log ERROR); no re-import or adjacent query sweep. Independent
recursive normal-flow decoding is bounded to1024 bytes. Escapes, overlapping
instructions, indirect JMPs, undecodable paths, no bounded RET and disagreement
with a separate linear boundary sweep reject. Calls are recorded but **assumed to
return normally**, not followed. Block leaders include conditional fallthroughs
and branch targets. Entry identity, complete Ghidra ownership, SEH/nonreturn edges,
helper effects and actual startup reachability remain unproven.

Iteration4 (`work/recomp-bench/run5-004-startup/metrics.jsonl`):

| RVA | Locally inferred bytes | Attempted | Lifted | ARM object compiled | Linked | Saved-x86 matched | QEMU executed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0x8258A9 | 75 | 1 | 1 | 1 | 0 | 0 | 0 |

26 reachable instructions/8 blocks/29 normal edges, all75 bytes reachable;
linear boundaries agree. Dependencies: direct call RVA82585C and absolute memory
operands at RVAs104F540/104F580, with no indirect calls in this bounded graph.
These are static dependencies, NOT identified Windows services or validated
global semantics. Full reliable boundary status remains null. The unchanged
pcrecomp invocation is `Lifter(precise_carry=True, lifted={0xA08258A9})` followed by
`lift_function(function)`; unresolved external direct calls retain exact-VA
runtime dispatch. No generated instructions are rewritten. A header include and
`RECOMP_GENERATED_CODE` supply upstream declarations for **object-only** compilation.
ELF64 ET_REL and machine IDs62/183 are checked; no link/execution is attempted.
Missing helper/reference/runtime contracts block correctness verification; no
unsupported-instruction marker occurred in this lift. Compilation is NOT a pass
for the function's behavior and the CLI intentionally exits2.

Seconds, one cached-environment observation: preflight1.656629,
analysis0.003106, pure lift0.000179, host object compile0.518457,
ARM object compile0.167524. Compilation includes upstream runtime header overhead,
NOT linking. No reference/run time measured. Historical analysis/engineering
cost and cold-start Ghidra work are unmeasured; no throughput extrapolation.
Five public tests exercise authored CFGs/call dependencies, malformed/escaping/
overlapping/indirect-jump flows, unsupported-marker policy, absent input reports,
no-clobber and symlink escape. They are not original behavior tests.

## Startup helper: four IAT dependencies, mechanically lifted but unverified

```sh
. scripts/campaign/worker-env.sh
PY=$(command -v python3)
"$PY" scripts/recomp/measure_startup.py --rva 82585C \
  --output work/recomp-bench/NEW-helper
# Expected exit2: object-only, incomplete pipeline.
"$PY" -m unittest discover -s tests -p test_recomp_startup.py -v
"$PY" -m unittest discover -s tests -p test_recomp_selection.py -v
```

Iteration5 explicitly selects82585C as candidate17, no replacement of hard cases.
The runner allowlists only8258A9/default and82585C; arbitrary RVAs reject before
output creation. It records absolute IAT call-slot/import metadata separately from
unresolved register calls; names do NOT establish an API binding or runtime ABI.
Ordinal-only imports retain their ordinal, unknown slots/targets remain null.

One bounded persistent query at82585C (40 instructions/12 refs/callers/callees,
no pseudocode) resolves function-at with25 instructions/four callees, no capped
sections; source pin/readOnly/noanalysis verified, known log ERROR retained.
Independent recursive/linear decode agrees on77 reachable bytes/25 instructions,
one block/24 normal edges. Calls assumed returning; exception flow, helper/API
side effects and actual startup reachability remain unverified. Boundary
reliability remains null rather than claiming full indexed ownership.

| RVA | Bytes, local extent | Attempted | Lifted | ARM object compiled | Linked | x86 matched | QEMU executed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0x82585C | 77 | 1 | 1 | 1 | 0 | 0 | 0 |

Private `work/recomp-bench/run5-005-helper/metrics.jsonl` records exact unchanged
pcrecomp invocation `Lifter(precise_carry=True, lifted={0xA082585C})` then
`lift_function(function)`, same revision/pins/origin checks as8258A9. Generated
instructions untouched. Both ELF64 ET_REL objects/machine IDs checked. No
unsupported marker, link, service stub, original x86 reference or execution;
no CPU/flags/memory/FP components compared. Import dependency metadata:

| IAT slot RVA | KERNEL32.dll import |
| --- | --- |
| D9A2A4 | GetSystemTimeAsFileTime |
| D9A194 | GetCurrentThreadId |
| D9A1BC | GetCurrentProcessId |
| D9A24C | QueryPerformanceCounter |

One cached observation in seconds: preflight1.590063, analysis0.002615,
lift0.000169, host object compile0.470039, ARM object compile0.167367.
No link/reference/execution or historical research cost measured; compiler/header
overhead included. Not batch throughput or an executable-wide estimate.
Eight startup public tests now cover authored control flow, IAT/register/unknown/
ordinal metadata resolution, allowlist, unsupported policy and private-output
failure guards; selection has five tests. These are NOT original-code behavior
comparisons. Prior1250 remains the only freshly verified/executed candidate;
fresh measured total3, selected17/rejected2, other14 unattempted. Batch missing.

Next ONE experiment: define bounded original8258A9+82585C x86 reference with
explicit deterministic **authored API endpoints**, then compare unchanged lifted
code on both ISAs. Endpoint stack cleanup, pointer output ranges, register/flag
clobbers, order and fail-closed unknown calls need independent controls before
any behavior-match claim. Such a test would validate only those endpoint
contracts, not actual Windows APIs, timing/entropy, startup or runtime integration.
HYPOTHESIS: those four endpoint contracts suffice for a bounded reference;
untested. Do not substitute a hand-written helper for the original body.

## Isolated sequential batch (iteration6)

```sh
. scripts/campaign/worker-env.sh
PY=$(command -v python3)
"$PY" -m unittest discover -s tests -p test_recomp_batch.py -v
"$PY" scripts/recomp/batch.py --rva 8258A9 --rva 1250 --rva 82585C \
  --seconds 120 --output work/recomp-bench/NEW-batch
# Expected exit2: two unverified startup objects, one verified leaf.
```

Use detached `setsid timeout450` with private logs. No new candidate, lifter,
service stub or PE execution is added. Only the existing1250/8258A9/82585C
measurement CLIs are allowlisted. Explicit selection is nonempty, unique and
bounded; order is retained, no failed candidate is replaced/retried. Each child
has a fresh Python process/session and exclusively created private output. Timeout
or child failure kills the same process group (including ordinary compiler
children), preserves logs and continues with the next candidate. This is not a
sandbox: a malicious child can escape its session; inputs/toolchain and filesystem
caches are shared. No concurrent scheduling or general arbitrary-function
measurement is supplied, and there is no dynamic expansion toward25.

One aggregate JSONL row per requested candidate is flushed immediately, including
failures without child metrics. `summary.json` includes stage counts and wall
seconds. Child JSONL retains original pins, exact lifter command/version, raw
stage times and private results. Strict schema/RVA/boolean/exit-code consistency
checks reject malformed, multiple or contradictory records. Timeout partial
states are not counted. Leaf execution is distinct from reference match (a
post-execution mismatch remains failed, not verified). Exit0 requires every
child verified; any failure exits1; otherwise incomplete exits2. Startup object
compilation cannot become a behavior pass or QEMU execution. The child harnesses,
not the batch summary, remain the source of behavior evidence.

Authored subprocess tests exercise crash-before-next, timeout-before-next,
same-process-group descendant cleanup, independent process-global state/PIDs,
malformed rows, partial pipeline claims, selection/no-clobber/symlink guards.
These test fixtures are not external-tool substitutes or game translations.
The actual batch remeasures the same three candidates to check composition,
order and costs; it adds zero unique attempted/verified functions to the earlier
run5 totals. Runtime guest-state isolation between functions executing in one
process is NOT tested by process isolation of these development harnesses.

Actual final batch `work/recomp-bench/run5-006-final/summary.json`, exit2:
selected3/attempted3/lifted3/ARM-compiled3/reference-matched1/QEMU-executed1.
Order8258A9→1250→82585C retained; incomplete startup children exit2 did not
prevent the leaf or later helper from being measured. Three distinct child PIDs,
no child timeout/failure. All unchanged lifter and image pins verified per child.

| RVA | Analysis s | Lift s | Host compile s | ARM compile s | Reference match / execution |
| --- | ---: | ---: | ---: | ---: | --- |
| 8258A9 | .002813 | .000173 | .516595 object | .167029 object | none / none |
| 1250 | .001259 | .000102 | .668247 link included | .317275 link included | host32/32, QEMU32/32 |
| 82585C | .004574 | .000160 | .469622 object | .167061 object | none / none |

Total sequential wall8.723188s; child walls2.671384/3.426949/2.624329s.
Leaf host execution.032723s/QEMU.264673s; preflight and comparison costs remain
separate in child JSONL. Compiler/cache/header/fixture/startup overhead included;
this single cached observation (after a preliminary batch) is not steady-state
translation throughput, cold-cache cost or an estimate for44151 functions.
The preliminary five-test run and8.673241s batch are retained separately under
`run5-006-batch`; final code additionally preserves executed-but-unmatched status
and tests descendant cleanup. No failed behavior was retried or removed.

## Reproducible startup-pair x86 reference (iteration7)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/reference_startup.py --output work/recomp-bench/NEW-reference
python3 -m unittest discover -s tests -p test_recomp_startup_reference.py -v
```

Use a bounded detached worker job. This commits the previously private run3
pair/frame hypothesis as a reusable reference stage; it is NOT a new discovery
of the pair, a new lift, or another native correctness pass. The image must match
the existing pin; the persistent helper envelope from iteration5 is reused with
its known CA-bundle ERROR, not re-imported. Both bounded normal-flow decodes and
all four PE IAT call-slot/name contracts must agree before execution. Missing
inputs fail; exclusive output stays under ignored `work/recomp-bench/`.

Single-step Unicorn runs the actual initializer/helper, never a substituted
helper, with deterministic FILETIME/thread-ID/process-ID/QPC responses. API calls
check order, original return addresses, exact frame/output pointers, FILETIME
zeroing and stdcall cleanup. QPC wrong cleanup rejects immediately, even if a
later frame teardown would mask it. Explicit memory operands have range checks;
code/IAT/sentinel/API pages must remain unchanged. Unknown instruction targets,
segment operands, bad stacks and the140-step budget reject. This trusted-input
reference is not a general x86 sandbox. No hooks are used; the historical code-
hook SIGBUS remains unresolved.

Final private `run5-007-reviewed/result.json`:320/320 fresh x86 cases matched
independent EAX/nonvolatile GPR/return-ESP/full4096 stack/full4096 data-page and
ordered endpoint/frame oracles. Helper runs160/bypasses160 across four stack
bases. Four actual negative controls reject (QPC cleanup0/8, instruction budget1,
swapped IAT endpoints). Seven public tests additionally use separately authored
x86 transport/read-bound fixtures and endpoint/oracle/mutation/output guards;
no original bytes/states appear in tests. Final flags/ECX/EDX, FP/SIMD, transient
writes, SEH, real Windows time/entropy/security/lifecycle are NOT compared.

The first run rejected an incorrect new EAX-complement oracle; other compared
components agreed. Targeted checks identified path-dependent EAX scratch state:
bypass preserves initial EAX, collision keeps raw reduction, low normalization
leaves its shifted term. The corrected independent formula then passes320 cases;
initial failure retained in `run5-007-reference`. This is a harness correction,
not an upstream/body/input change or a retried translation failure.

Reviewed observation: preflight1.584425s, reference+oracle2.304199s for the pair,
including single stepping and page comparisons, NOT per-function translation
costs. Raw states and source/envelope/range hashes remain private. No compiler or
pcrecomp runs here: fresh unique attempt/lift/ARM-compile counts remain3; native
reference-matched/QEMU functions remain1, selection17/rejections2. Neither startup
object has been verified as a translation. Next: compile the unchanged generated
pair for host and AArch64 against these states using explicit checked-memory and
exact-VA call seams; do not reuse historical rewritten instructions as a fresh
unchanged lift. No whole-executable throughput estimate follows.

## Unchanged startup pair: native call-ABI rejection (iteration8)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/execute_startup.py --output work/recomp-bench/NEW-native
# Expected exit2 with the pinned upstream ABI: incomplete, NOT verified.
python3 -m unittest discover -s tests -p test_recomp_startup_native.py -v
```

Run with detached `setsid timeout480`, private logs/output. The runner reuses the
existing reference CLI (actual original pair320/oracle320, four negative controls)
and unchanged startup measurement CLI for both fresh pcrecomp bodies. Image,
upstream/module-origin/ELF pins are checked by those stages. All original code,
states and logs remain ignored. No new candidates, Ghidra query, re-import,
protection/recovery, PE launch or runtime bindings. Six public tests exercise
immutable assembly, strict transport/claim counts, observed-state mutation,
rejections, reference/oracle disagreement, case protocol and output guards.

`scripts/recomp/startup_transport.c.in` supplies only authored fixture transport,
checked aligned MEM32 lvalue spans and exact-VA lookup for the pair/four authored
APIs. Both generated bodies occur byte-for-byte exactly once; no generated
instruction, upstream CALL/ICALL macro, return marker, oracle or acceptance gate
is rewritten. Unknown calls fail; API order, frame, original return address,
output pointer, zeroing and cleanup gates remain. Endpoint rejection abandons
that case without publishing a CPU/memory state. Every case resets registers,
flags, pages and trace counters. This is single-owner diagnostic infrastructure,
NOT GuestMemory/GuestDispatch integration, write-mode isolation or a sandbox.
The subprocess/outer deadlines bound compiled execution, not an instruction budget.

Actual `work/recomp-bench/run5-008-native/result.json`, exit2:

| Pair invocation | ELF compile/link | Process/transport execution | Full state matches | Endpoint rejections | Verified pair |
| --- | --- | --- | --- | --- | --- |
| Host | yes | exit0 |160/320 (all helper bypasses)|160 return-address|no|
| AArch64 Linux/QEMU | yes | exit0 |160/320 (all helper bypasses)|160 return-address|no|

The generated initializer makes one upstream ICALL and the helper four. Upstream
`RECOMP_ICALL` pushes the same dummy marker rather than the original call-site
return VA. All160 helper-taking cases therefore reject at the first authored
API's **return-address check**, on both ISAs. The native helper was entered but
never completed an API; its arithmetic/publication is NOT verified. The160
bypass results compare EAX, nonvolatile GPRs, return ESP and entire4096-byte
stack/data pages. Host/QEMU stdout is byte-identical including failures, NOT a
behavior pass. No gate was relaxed or failed translation retried/replaced.

Cached single observation, seconds: initializer analysis.002499/lift.000166;
helper analysis.002774/lift.000174. Joint fixture compile/link host.619559,
ARM.318026; execution/output host.065217/QEMU.616593; comparison.009694/.010523.
Reference preflight1.602480/single-step+oracle5.509977 (child wall7.479028).
Fresh object-only timings remain in each private child JSONL; they are distinct
from joint executable compile/link and not summed into a per-function estimate.
These include cache/header/fixture/process/output overhead; no44151 extrapolation.

Unique selected17/rejected2/attempted3/lifted3/ARM-compiled3/reference-verified1.
The pair is now linked and invoked on both ISAs (three unique generated bodies
including the prior leaf have been invoked under QEMU); only1250 has a complete
successful reference comparison. Do NOT count a zero-exit rejection transport as
successful execution of both startup functions. Final flags/ECX/EDX/FP/SIMD,
transient writes, SEH/concurrency, real Windows/time/entropy/security, startup
and Android remain unverified. No actual menu/render/input/gameplay exists.

Next ONE experiment: transport call-site return VAs without rewriting generated
instructions or upstream. HYPOTHESIS: a bounded decoded `(caller,target)` table
can supply unambiguous original return VAs for this pair through an explicit call
macro seam; repeated-target ambiguity must reject, and generic scalability must
not be inferred. Keep API/full-stack oracles unchanged. Such a seam has not yet
been implemented or tested; historical rewritten adapters remain separate.

## Selected original-entry tail-boundary reference (iteration10)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/reference_startup.py --entry-boundary \
  --output work/recomp-bench/NEW-entry-reference
python3 -m unittest discover -s tests -p test_recomp_startup_reference.py -v
```

The opt-in mode includes only selected entry8248A3's bounded10-byte flow and the
existing initializer/helper. Pinned-image decoding must find exactly a direct
CALL to8258A9 followed by a direct JMP to824727. The external target is a stop
BEFORE execution, never a returning stub or an implemented service. No target
body is decoded or executed; normal-return `decode_flow` still rejects escaping
tails. Existing persistent private Ghidra envelopes are provenance only, not a
behavior oracle. The default pair-only interface is unchanged.

An independent frame composition applies the pair oracle with SP reduced by4,
then requires the entry CALL return word, intact original caller return, original
SP and nonvolatile registers at the tail boundary. Full4096-byte stack/data pages,
EAX, API order/frames/output pointers/zeroing/cleanup remain strict. Tail EIP is
additionally compared. Final flags/ECX/EDX/FP/SIMD/SEH/transient writes and actual
Windows services remain unverified. The same deterministic320 cases include160
helper paths and160 bypasses across four stacks. No translation/compile/QEMU/
Android/startup claim follows from this development-time x86 reference.

Three additional public tests cover assembled authored call/tail transport,
wrong/truncated/extra/indirect flow, every observed tail-state component, budget
and explicit-mode rejection, and preflight orchestration with mocked public
metadata. The latter guards against overwriting the boolean mode while walking
body addresses. Initial private entry measurement rejected that harness bug;
its failed result is retained separately, not relabeled as a behavioral failure
or silently erased. No original bytes, generated bodies or raw states are public.

Next: ONE fresh pinned lift attempt of this selected entry with an explicit
external-tail boundary, retaining any unsupported flow rather than widening into
the target. Keep native verification distinct from this reference-only result.

## Selected original-entry mechanical lift (iteration11)

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/measure_startup.py --rva 8248A3 \
  --output work/recomp-bench/NEW-entry-lift
# Expected exit2: object-only, not verified execution.
python3 -m unittest discover -s tests -p test_recomp_startup.py -v
```

Use bounded detached execution and private logs. Only the already-selected entry
is added to this measurement CLI; batch and native-pair CLIs remain unchanged.
The separate strict decoder accepts exactly one direct CALL to8258A9 followed by
one direct JMP to824727 in10 bytes. It supplies a single block to the unchanged
pinned lifter; the external tail is an edge, never a local block or a RET. No
bytes from824727 are decoded, merged or translated. Normal-return `decode_flow`
still rejects this escaping flow. Existing persistent entry provenance was
established by the preceding reference experiment; no new query or re-import.

Actual `work/recomp-bench/run5-011-entry-reviewed/metrics.jsonl`, exit2: entry attempted,
mechanically lifted and compiled to both host and AArch64 ELF64 ET_REL objects.
No unsupported marker; unchanged upstream emits its existing ICALL/ITAIL seams.
No generated instruction or upstream source is rewritten. The exact invocation
is `Lifter(precise_carry=True, lifted={0xA08248A3}).lift_function(function)`.
Pinned revision remains `c0cbd3e3653010782b17e8a87b58953608ea411c`.

| RVA | Bytes | Attempted | Lifted | ARM object | Linked | Native x86 match | QEMU executed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8248A3 | 10 | 1 | 1 | 1 | 0 | 0 | 0 |

Seconds, final cached observation: preflight1.646555, analysis.002720,
translation.000046, host object compile.518427, ARM object compile.166718.
Preliminary `run5-011-entry` is retained, also exit2 with identical generated body.
Header/compiler/cache overhead is included; no joint link/run cost, engineering
cost or steady-state throughput is measured. The previous independent entry x86
reference320/320 is NOT a native translation comparison. No registers, flags,
memory or FP are compared by this object-only command. Boundary reliability stays
null; returning CALL/normal-flow assumptions exclude SEH/nonreturn behavior.

Unique totals now selected17/rejected2/attempted4/lifted4/ARMcompiled4,
fully native reference-matched3. No sample-wide or44151-function estimate follows.
Authored public tests cover the explicit edge/block contract and wrong targets,
indirect/truncated/extra/internal/RET flows; no original bytes/states are public.
NEXT ONE: compare this unchanged lifted entry with the existing verified pair on
host and AArch64 at the independently checked external-tail stop. Derive entry
call-return metadata explicitly and reject unknown tail dispatch; do not implement
824727 or infer full startup from a boundary comparison. General call identity,
GuestMemory/Dispatch integration, real services and Android/gameplay remain open.

## Next measurement (historical iteration6 plan; reference stage above supersedes it)

Measure fresh pinned pcrecomp invocations per selected candidate, without altering
upstream. Record analysis/translation/compilation/testing costs independently and
retain failures at their original RVAs. Reuse saved x86 states for the first leaf
attempt, then tackle a hard dependency; do not infer timing from historical lifts.
A bounded persistent query of `0x8258A9` in iteration2 returned address-only, zero
indexed instructions, and one known query-log ERROR, despite the correct image
pin. This is an index coverage gap, NOT an empty function or permission to omit
it. The iteration4 runner uses bounded independent decoding to establish its local
extent before lifting; it never substitutes a nearest preceding function. No re-import is needed.
Iteration4 above now supplies the bounded local extent and mechanical lift, but
not a behavioral contract. Iteration5 above now supplies82585C index/decode,
import dependencies and mechanical lift; a bounded x86 reference for the pair
remains next. Further selection changes need explicit manifest/test review within
the remaining eight slots; do not silently add a counted function.
The bounded batch checkpoint below now covers process isolation/containment for
these three existing runners only. These leaves and a purposive at-most-25
sample still cannot estimate 44,151 functions.

AArch64 here means **Linux user-mode QEMU**, not Android, hardware, startup,
rendering, menu or gameplay. The trusted Phase 1 gate remains independent.

## Resource failure caller → first leaf boundary (iteration27)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 82a6d3 --instructions 64 --refs 8 \
  --callers 8 --callees 8 --out work/recomp-bench/NEW-caller-index.json
# LEAF_INDEX is the existing private pinned 82A47B envelope from iteration26.
python3 scripts/recomp/reference_resource_call.py \
  --index work/recomp-bench/NEW-caller-index.json.env.json \
  --leaf-index "$LEAF_INDEX" --output work/recomp-bench/NEW-call-reference
python3 scripts/recomp/execute_resource_leaf.py \
  --index "$LEAF_INDEX" --caller-index work/recomp-bench/NEW-caller-index.json.env.json \
  --output work/recomp-bench/NEW-call-leaf-native
python3 -m unittest discover -s tests -p 'test_recomp_resource*.py' -v
```

Use bounded detached jobs with private logs. `reference_resource_call.py` validates
both indexed boundaries, builds an independent raw-encoding prefix oracle, then
executes original x86 continuously through the first leaf RET. Each prefix step
compares eight GPRs, PC, defined flags and full stack; other data/code pages must
stay unchanged. Only the straight-line 18-byte prefix through the first CALL is
executed from the caller. No following caller instruction or later dependency
executes. Calls/branches/segments/arbitrary memory outside the tiny prefix subset
reject. The existing checked leaf reference validates accesses and return PC;
it is NOT a second independent semantic oracle for the leaf.

The optional `--caller-index` mode reuses the unchanged pinned leaf lift. Native
execution starts **at the leaf**, with the independent prefix oracle's registers
and stack. It compares all eight final GPRs and four full data pages against
continuous original x86 prefix+leaf execution. This is a caller-produced entry
frame comparison, NOT a translated native caller or full caller composition.
Two exact oracle-derived entry stack positions are compiled into the transport;
other SP values still reject. Default leaf-only fixtures retain their previous
stack gate. Native PC/flags/FP/SIMD/transient writes remain excluded. Synthetic
globals and caller entries do not establish real ownership, service identity,
exception handling, startup reachability, Android or gameplay. No new candidate
or unique translation is counted. Three leaf instructions remain uncovered in
this caller-produced-frame mode; full caller return remains unverified.

## Authorized five-cache caller composition (Campaign C iteration4)

```sh
. scripts/campaign/worker-env.sh
scripts/ghidra-query.sh --rva 1abd40 --instructions 32 \
  --out work/recomp-bench/NEW-cache-caller-index.json
"$PY" scripts/recomp/execute_cache_caller.py \
  --caller-index work/recomp-bench/NEW-cache-caller-index.json.env.json \
  --output work/recomp-bench/NEW-cache-caller
"$PY" -m unittest discover -s tests -p test_recomp_cache_caller.py -v
```

Use bounded detached jobs and exclusive ignored outputs. This freshly lifts the
exact owner-authorized eight-function closure, executes original caller1ABD40
with all five live callees plus FCF0→9550 in a bounded x86 context, and compares
host and static Linux/AArch64/QEMU executions. Eight GPRs and six whole pages
include receiver, handle, stack, text and both image tables; flags/FP/nativePC/
transient writes are excluded. Exact-VA adapters route compiled bodies through
actual GuestMemory/GuestDispatch; no behavior responses or runtime x86 decoding.
All private bodies are inserted verbatim. The C++ proxy bridges checked guest
lvalue reads/writes; table writes, unknown edges and out-of-range accesses fail.
Independent post-state checks cover five-slot ordering, count/index agreement,
H108 update, caller/return cleanup and AL/upper-EAX result. Public tests exercise
authored bridge controls and reject slot/cleanup/count/index/update mutations;
they do not contain or independently reproduce originals.

The whole-sample synthetic range domain is explicit, not arbitrary text support.
The preceding raw-truncated-range budget failure remains unresolved. Actual
writers/lifetime, ownership, handle copying,95C2 coverage and production Android
binding remain open. Real guest memory in a private diagnostic executable is NOT
game startup, Android execution or gameplay. See the iteration4 task report for
reference/source pins, exact measurements, failed attempts and remaining gates.
