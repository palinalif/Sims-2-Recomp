# Read-only object-query caller map — 2026-10-21

## Actual `1AB665` opener-result edge executed natively — 2026-10-30, run6 iteration2

`execute_initialization_opener_result.py` freshly lifts the 202-byte opener-result
segment at RVA `0x1AB6A6` (60 flow nodes, `02fd4cdbf888…`) — a strict sub-range of the
settled 267-byte/83-node `1AB665` pin `6c35c084…` — with the unchanged pinned pcrecomp
(`Lifter(precise_carry=True).lift_function` at VA `0xA01AB6A6`) and executes its
**zero-opener-result completion** natively for the first time: `pop ecx` (`0x1AB6A6`),
`mov [esi+0x34], eax` (`0x1AB6A7`), `pop ecx` (`0x1AB6AA`), `test eax, eax`
(`0x1AB6AB`), `je 0x1AB763` (`0x1AB6AD`, taken because the result is zero), then the
shared `cmp [esi+0x34], edi` (`0x1AB763`) / `setne al` (`0x1AB766`) comparison and the
`pop edi`/`pop esi`/`ret` epilogue (`0x1AB769`–`0x1AB76B`, `ESP + 0x14`). This is the first native execution of the
store into `+0x34` and of the `CMP`/`SETNE` polarity, and its executed six sites
(`1ab6a6`,`1ab6a7`,`1ab6aa`,`1ab6ab`,`1ab6ad`,`1ab763`) are disjoint from both settled
early-return arms (guard `+0x34`-populated AL=1; zero-`+0x1C` no-open AL=0), which is
asserted by test. Opener result is forced to zero, so `AL` is derived, not constant:
AL=0 for callee-saved `EDI==0` (32 cases) and AL=1 for `EDI!=0` (32 cases), which is what
makes the `CMP`/`SETNE` operand semantics observable.

Private `work/recomp-bench/opener-result-{first,reviewed,controlled}/result.json` (the
first two byte-identical artifacts, the third after the control strengthening below):
64/64 final states predicted by an independent pure-python oracle match the original-x86
single-step reference (eight GPRs + six complete 4096-byte pages, the stored `+0x34` word
observable because every case starts with a non-zero slot); **64/64 host** and **64/64**
`-target aarch64-linux-musl -static` under `arm64-run.sh`/qemu-aarch64 through production
`GuestMemory`/exact-VA `GuestDispatch`; `arm64_executed:true`, `host_executed:true`,
`android_executed:false`, `stub:false`, `whole_function_verified:false`, coverage 10/83
instructions, `callee_calls:0`. The `wrong-result` control was strengthened from forcing
`AL=1` (which can differ only on the 32 `EDI==0` cases; the retained pre-strengthening
receipts differ 32/64) to **flipping `AL`** — a `SETE`-for-`SETNE` polarity bug — so both
controls now differ **64/64 per ISA**. Nine registered authored skip-free tests.

Not established: a non-zero opener result, which diverts at `0x1AB6B3` to
`push ESI; push EAX; call 0x1030` — that argument shape is bound by the x86 boundary
observation only, never executed or responded to; the association/`0x1030`+setter
sequence, failure/`0x27D0` cleanup/callback arms, composed whole-function `1AB665`,
E3/E4 production integration, flags/FP/PC comparison, Android, gameplay. Nine registered
authored tests; the authored stack words are a bounded return-edge frame, not producer,
input, lifetime or callback ownership proof.

## Actual `1AB665` opener selection and argument binding — 2026-10-30, iteration2

`execute_enclosing_opener_selection.py` derives the enclosing initializer's opener
selection contract from decoded nodes of the pinned image and confirms it by
bounded original-x86 single-step traces. Four authored receiver families (16
cases each, inline and heap `std::string` forms): populated `+0x34` returns AL=1;
zero `+0x1C` returns AL=0 without opening; `+0x7C==0` reaches `call 0x3C50` with
arguments (string data, `0x40`); `+0x7C!=0` reaches `call 0x3A50` with (string
data). String data = capacity(`+0x74`)>0xF ? `[+0x60]` : `+0x60` inline. The
unexecuted CALL boundary is recorded by stop `pc`; the visited sequence never
includes it. Opener result stores to `[+0x34]` (`0x1AB6A7`); zero selects the
`0x1AB763` failure arm.

Private `work/recomp-bench/enclosing-opener-selection-1/result.json`: 64/64
cases match an independent pure-python input→path/state prediction on outcome,
stop site, visited instruction sequence, eight final GPRs and all six full
4096-byte pages. 32 selector-flip differentials: changing only the `+0x7C` byte
(one-byte page delta verified) swaps the observed target between `0x3A50` and
`0x3C50` and the ESP argument shape. 64 adversarial predictions (swapped target,
dropped `0x40` word) differ from every observation; unaligned ESP and a receiver
reading past its page end trace as `unsafe-access`. Coverage 26/83 visited sites
(16 beyond the settled guard path); 57 sites unvisited. No lift, no native
execution here (`host/arm64/android_executed: false`), no callee body or
response: opener bodies are the separately verified `3A50`/`3C50` compositions,
not executed or linked by this artifact. Six registered authored tests.
This resolves the receiver/mode/input-binding gap for selection only; the
composed enclosing success edge (store, association/setters, failure/cleanup
arms), production integration and Android remain OPEN.

## Live1330 value/list publication native differential — 2026-10-29, iteration7

`execute_value_assignment.py` freshly lifts1330 with831A6F/8461F2 through pinned,
unchanged pcrecomp and executes the live3700 pending-argument fixture. Independent
Capstone graph agrees with the reused untruncated Ghidra index:299B/116 sites,
75 visited. Retain query advisory ERROR1/scriptCompileError=false. Eight live
pages and five caller arguments stay exact; only CALL's return sentinel is
synthesized. Null free-list/callback success only: two portable dirty allocations
for value record/payload after the explicitly occupied4136-byte prefix. Marker0
excludes NUL; nonzero marker replaces NUL. An independent x86 occupancy and full
nonstack publication oracle checks list links, metadata, payload and retained
owned key/source/table/slack. Production GuestHeap is NOT Windows HeapAlloc.

Private `value-reviewed/result.json`:64/64 original-x86 contracts,64/64 host and
64/64 Linux/AArch64 QEMU matches of eight final GPRs/eight full pages (including
scratch stack). Two controls each reject64/64 per ISA;9 authored public tests
PASS/no skips. Repeated allocator calls require a fail-closed ordered return-PC
adapter; forward REP copies route through checked guest-byte accesses, keeping
lifted bodies verbatim. An eight-page strict comparator retains malformed-mutant
rejection and leaves old six-page comparators unchanged. Earlier failed receipts
record these two integration issues, not hidden mismatches or dropped cases.

ONE new bounded success path, ZERO whole dependencies resolved. No whole1330,
3700/3C50/1AB665/E3/E4, flags/FP/PC/transient-store/general ownership/Windows or
Android verification. Reuse/realloc/failure/release/indirect-callback contracts
remain OPEN. NEXT compose the actual remaining3700 caller with this callee and
retained heap state; HYPOTHESIS: fixed single-key=value path can return, untested.
Task PHASE1_REPORT.md has sanitized cost metrics, exact commands and all gates.


## Live key ownership before value assignment — 2026-10-29, iteration6

`probe_key_publication.py` advances the existing live caller state from37B2 to
BEFORE3861→1330, with no service/callee response or allocation in this segment.
The node's temporary key pointer is replaced by the separately allocated key
copy; the original temporary key region is then overwritten by the fixed mode's
value including NUL. This is a bounded `key=value` input grammar, not general
parser or lifetime proof. Descriptor1DC advances to the end of that replacement;
the owned key, table, source descriptor capacity and every other non-stack byte
remain exact. Pending four arguments, ESP−20, ESI and caller frame are checked.

Private `key-publish-reviewed/result.json`:64 original-x86 subsets,832 rejected
mutations,40 visited sites,0.553s. Eight discoverable authored tests require no
private inputs. ZERO newly resolved whole dependencies or fresh lifts/native
host/AArch64/Android verifications. Upstream portable heap MODEL is NOT Windows;
GPR/pages cross segments but EFLAGS resets0x202. Scratch/full flags/FP/PC/transient
stores, general lifetimes/errors and whole3700/3C50/1AB665/E3/E4 remain OPEN.
The persistent1330 query succeeded readOnly/noanalysis with advisory ERROR1 but
hit its100-instruction cap. Follow-up256-site bounded query is untruncated with
116 sites/299B linear extent and the same advisory warning; this is NOT an
independent code pin or closure proof. NEXT pin/decode the1330 boundary, then
fresh lift and independent host+AArch64 verification of its live dependency contract. Do not repeat this prefix alone.
Task PHASE1_REPORT.md records reproduction, failures and regression evidence.

## Caller-owned bucket allocation prefix — 2026-10-29

`probe_table_allocation.py` now executes actual183D→83A371→849A00 from
3C50→3700→1820 caller-produced GPR/pages. The independent portable service
retains all four previous allocations, then zeroes the new64×4 extent. Stops
BEFORE1861→1800; no invented hash/lookup/insertion response. Private
`create-live-reviewed/result.json`:64 subset matches, four controls rejecting64
cases each, reference+contracts2.862s. The independent contract checks256 zero
bytes, publication into the table descriptor, preservation of prior objects/text
and subsequent slack, immutable pages and EDI/stack subset. Five authored tests
pass without private inputs. Persistent read-only1820 query exit0; no re-import.

This advances the earlier actual-creation frontier, not whole1820 verification:
no fresh lift or native host/AArch64/Android execution this increment, ZERO
all-path dependencies resolved. Exact GPR/pages cross three bounded segments;
EFLAGS resets0x202. Portable occupancy/zeroing MODEL is NOT Windows execution.
No full flags/FP/PC/transient-store, errors/retry, general ownership/lifetime,
whole3700/3C50/1AB665/E3/E4 or gameplay claim. NEXT execute1861→1800 and follow
insertion. HYPOTHESIS: the verified1800/17D0 bodies fit this live newly created
table; the current prefix does not execute them. Earlier dated claims below are
historical, not silently rewritten. Task report records exact reproduction.

## Calloc success branch native differential — 2026-10-28

`scripts/recomp/execute_calloc_success.py` freshly lifts849A00 (93B/39 sites)
with unchanged pinned pcrecomp. Reused persistent Ghidra exact-boundary evidence:
no truncation, advisory ERROR1/scriptCompileError=false. Original reference needed
a separate default-OFF bounded DIV reg32 / IMUL reg32,mem32 allowance; authored
math/operand/bounds/trap tests retain fail-closed defaults and normal memory checks.

Private `calloc-arithmetic/result.json`: independent success/zeroing contract64/64;
same generated body + production GuestHeap through checked GuestMemory/exact-VA
GuestDispatch matches eight final GPRs/six pages64/64 host and64/64 Linux/AArch64
QEMU. Wrong-result and cleanup controls reject64/64 on both ISAs. Coverage28/39,
no overflow/retry/error proof. Explicit independent zeroing MODEL at HeapAlloc,
NOT Windows heap execution. Synthetic IAT/global/token ownership. Eight authored
tests pass; no proprietary bytes/bodies/state in Git. AndroidFALSE.

ONE newly executable bounded success branch, ZERO fully resolved dependencies.
83A371 tail and actual caller-owned1820 creation are still unverified. NEXT fresh
thunk composition then resume creation; do not remeasure isolated settled paths.
Whole1820/3700/3C50/1AB665/E3/E4/startup/menu/gameplay remain OPEN.

## Actual alternate-opener lookup creation frontier — 2026-10-28

`probe_alternate_binding.py` (recovered from preserved uncommitted WIP) and
`probe_table_create.py` now measure actual3C50→3A50/10B60/10AF0→3700 setup.
The first lookup is378A→1820, NOT the earlier synthetic3903 edge. Incoming3C50
arg1 is a byte option; its fixed mode input is image-backed atE16FB0. Four
successful allocations are explicit portable occupancy MODEL behavior, not
Windows heap execution. At lookup: allocatedH, ESI=H, EDI=H+160, zero four-word
table, args(owned key,8); cursor/text derive from real allocation/copy execution.

The next prefix reaches183D→83A371 with a **64×4-byte** request, no response.
Private `create-segmented/result.json`:64 subset checks and five rejecting
controls64/64 each;1820 coverage12/154. All non-stack pages and caller words
remain intact. Ten discoverable authored tests cover stop/read-only policy,
binding/control oracles and exact GPR/page handoff. No lift/native dependency
resolved, host-native/AArch64/AndroidFALSE. Longest255-byte source exhausted
4096 steps when treated as one extended invocation; final evidence is explicitly
segmented startup<=4096 and originalCALL/create<=128 with exact live GPR/pages.
EFLAGS resets0x202 at segment entry; no uninterrupted/flag equivalence claimed.

Persistent bounded queries, no reimport:83A371 is11B/5 sites, tail edge849A00;
849A00 is93B/39 sites with direct842A91/8437C6/831B17 and external import.
No query truncation; advisory ERROR1/scriptCompileError=false retained. This
identifies the next calloc dependency, NOT verified allocation semantics.
HYPOTHESIS: success-path flags8 guest allocation/zeroing can close that import;
next fresh lift + original reference + independent service model/native heap
host+AArch64 before resuming1820. Full create/growth/node/free,3700/3C50/
1AB665/E3/E4, failures/callback/lifetime/gameplay remain OPEN. Detailed receipt
and reproducing commands are in task PHASE1_REPORT.md. Original bytes, states,
index output and any future generated bodies stay private under ignored work/.

## Alternate-opener dependency3700 empty input — 2026-10-27

`execute_mode_empty.py` freshly lifts the complete582B/163-site function and
verifies ONLY the empty EAX byte-string branch. Persistent read-only Ghidra query
and independent pinned decode agree on extent, two callers and four unique direct
callees1330/1820/1AF0/26B0. No callee is registered for this experiment; unknown
edges fail closed, not authored responses. Advisory query ERROR1 with no script
compile error is retained; all truncation flags false.

Original x86 matches an independent complete final-state oracle64/64; host and
Linux/AArch64 QEMU each match64/64, both result/cleanup controls reject64/64 per
ISA. Coverage15/163. EAX returns1, ECX=input pointer, ESP+=4; other GPRs preserved.
Stack scratch retains four saved words; every other tracked byte, including the
poisoned valid ESI handle, remains unchanged. Source positions include the final
readable byte; receiver positions include the exact page end. Eight final GPRs
and six pages compared, not flags/FP/PC/native transient stores. Five discoverable
authored tests; private final receipt mode-empty-verified/result.json.

This is ONE newly executable bounded branch/body, ZERO fully resolved all-path
dependencies. It is NOT composed3C50/1AB665/E3/E4, Android or game startup.
Five exploratory nonempty fixtures faulted in incomplete caller context; absent
fault addresses, neither callee reachability nor failure semantics is established.
Next derive actual3C50→3700 register/stack/pointer inputs and locate the first
failed access. Nonempty paths/all four callee behaviors remain OPEN. Reproducer
and regression receipts are in task PHASE1_REPORT.md; do not repeat this empty
branch as progress.

## Actual `3A50` null-input success composition — 2026-10-27, iteration3

`execute_opener_success.py` now freshly lifts the complete508B/137-site opener
and nine real dependencies, without changing pcrecomp or substituting responses.
The tested domain is NULL input/zero options with three successful allocations
(528,256,1024 bytes). Original x86 executes the allocation wrapper/allocator and
member, aggregate, descriptor and inline producer/classifier bodies. Its imported
allocation boundary uses the independent persistent occupancy model; native
execution uses production GuestHeap through GuestMemory/exact-VA GuestDispatch.
This is NOT original Windows HeapAlloc execution or process-global initialization.

64/64 original-x86 subset publication/ABI contracts,64/64 host and64/64
Linux/AArch64 QEMU full-state matches; wrong-result and outer-cleanup controls
each differ64/64 per ISA. Eight final GPRs/six pages;201/251 closure sites
(119/137 opener sites). Repeated root allocation/initializer calls and2570's
five buffer initializers retain distinct decoded return PCs via bounded per-edge
counters reset every case. Unknown callees remain unregistered and fail closed.

The original opener now establishes the528-byte handle and its inline producer
storage rather than receiving a fabricated preinitialized handle. Member122F0
is bound at H+E8; H+EC remains dirty/preserved, H+F0=0 and H+F4=1. Inline service
publication H+78/H+C8 and class6 are independently checked. H+0/H+4, H+74 and
H+E4 are zero in this domain. HYPOTHESIS: these successful allocations supply
the bounded ownership needed for a later text-input composition, NOT general
lifetime/callback or shutdown safety.

Private receipt: `work/recomp-bench/opener-compose-verified/result.json`, all
current harness/scenario/artifact/helper/native/upstream/image audit groups MATCH.
One newly lifted caller body/path; zero completely resolved all-path dependencies.
Whole opener coverage,26B0 text input, allocation failure/retry/errno,27D0 cleanup,
3C50/1AB665/E3/E4, original-code Android and gameplay remain OPEN. No flags/FP/PC/
native transient-store comparison. Eight discoverable authored tests; reproducer
and regression receipts are in task-local PHASE1_REPORT.md iteration3.

## Opener dependency `0x122F0` verified — 2026-10-27, iteration2

The unresolved call at `3A7E` in `3A50` reaches `122F0`. A bounded persistent
Ghidra query and independent pinned decode agree on 25 bytes/five sites, no
calls. The existing initialization runner now freshly lifts and executes this
complete dependency: private `opener-member-verified/result.json`, success=true.
64 original-x86 cases match an independent full final-state oracle; host and
Linux/AArch64 each match64/64. Wrong-result and wrong-cleanup controls differ
64/64 on each ISA. Coverage5/5; eight GPRs/six complete pages compared, NOT
flags/FP/PC/native transient writes. The Ghidra advisory ERROR1 is retained;
scriptCompileError=false and exact independently decoded boundaries agree.

Measured contract: first stack argument addresses16 writable aligned bytes;
receiver+0 receives VA `A0012220`, +8 becomes0, +12 becomes1, and +4 is
preserved. EAX returns the receiver, ESP advances4; other GPRs, stack arguments,
neighbors and all other tracked bytes remain unchanged. Four receiver positions
include the exact page end. Six registered authored tests check this distinction,
bounds, transport and rejecting controls. HYPOTHESIS: a member constructor;
no recovered symbol, target invocation, upstream allocation or lifetime proof.
The stored address's type is unproven; table terminology is HYPOTHESIS.

New dependency body1 and newly executable original behavior122F0; the other
opener edges are not counted as resolved. This is diagnostic GuestMemory/exact-VA
execution, NOT composed3A50/1AB665/E3/E4, production registration or Android.
Next compose actual3A50 allocation/member initialization with the already-verified
1A40/2570/26B0/109D0 paths, retaining122F0's untouched+4 rather than assuming a
zeroed object. Full opener failure/cleanup/global contracts remain OPEN.

## Owned-empty capacity growth through realloc — 2026-10-26

`execute_capacity_reallocate.py` composes original2790/26B0/1AF0 with the
already-verified8413B0/85217F pair, freshly lifting all five from the pinned
image. The synthetic fixture owns an empty64-byte active chunk plus a blocking
64-byte allocation. Initial start/cursors equal active+8, end=active+64,
spare-chain pointer null; disjoint input lengths64–95 exceed usable capacity.
Original x86 reaches a120-byte flags0 realloc request. Import behavior is an
explicit independent portable occupancy/copy model, NOT Windows execution;
native behavior uses production GuestHeap and exact-VA dispatch.

Important correction to the initial contract: the writer fills the old56-byte
payload BEFORE realloc, preserves that prefix across the move, then resumes
copying including NUL and rebases source/cursors. New usable capacity112;
the blocking block and old written prefix remain intact in the final snapshot.
Eight discoverable authored tests reject byte/publication/ABI/request corruption.
Frozen-source `capacity-compose-reviewed/result.json`: original-x86 contract
64/64, host and Linux/AArch64 matches64/64 each; result/cleanup controls reject
64/64 each ISA. Coverage111/243 (1AF0=42/148); eight final GPRs/six pages, not
flags/FP/PC/transient writes. Current source/artifact pins MATCH. Reproduction
is in task PHASE1_REPORT.md; failed source-pin-audit attempts are retained
privately, not counted as final receipts.

This narrows the earlier realloc-composition hypothesis only for synthetic
owned-empty chunks. Original upstream creation/reset/lifetime, arbitrary filled
chunks, full1AF0/26B0/openers/1AB665/E3/E4 and error/retry/global/callback contracts
remain OPEN. Android and Windows heap execution are not claimed.


This note maps the immediate caller and lifetime evidence for the three
ARM64-validated original queries. It uses the owner's pinned Steam Legacy
analysis image (SHA-256
`63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985`).
The private image, decoded instructions and scan script remain under ignored
`work/interop-legacy-002/`. These RVAs are observations, not recovered symbols.

## Descriptor spare-chain consumption — 2026-10-26, iteration5

**Correction to earlier terminology:** descriptor+4 (H+1D4) is not established
as an allocator selector. Original1AF0 reads it as a linked chunk pointer and
writes it while manipulating chunk chains. `execute_capacity_reuse.py` now
executes a bounded nonnull case; no integer selector or fake callee response.
Initial state explicitly owns two64-byte spare chunks with8-byte headers
(link, usable56), no active chunk. This is synthetic declared ownership, NOT
proof of the upstream producer/reset/lifetime protocol.

Original2790→26B0→1AF0 promotes the spare head to active, advances descriptor+4
to the second chunk, clears the promoted header's link, publishes active+8 at
H+D0 and copies the source INCLUDING NUL. The second chunk, unused bytes and
immutable pages remain unchanged. Both x86 and native transports **reject any
allocator call**. Seven discoverable authored tests check publication, chain,
headers, untouched pages, ABI, and rejecting controls.

`work/recomp-bench/capacity-reuse-final/result.json`: original x86 independent
contract64/64, host64/64, Linux/AArch64 QEMU64/64, result and outer-cleanup
controls reject64/64 per ISA. Eight final GPRs/six complete pages compared;
flags/FP/PC/native transient writes not compared. Coverage63/231:
2790=13/16,26B0=26/30,1AF0=24/148, allocator bodies0 sites. Five fresh lifts
are retained as the existing composition, NOT five standalone verifications.
One new composed path, zero new bodies/fully resolved allocator dependencies;
AndroidFALSE, no whole1AF0/openers/1AB665/E3/E4 or startup/gameplay claim.

Persistent bounded1AF0/8413B0 queries reused the existing project, retaining
advisory ERROR1. Independent bounded operand analysis also identifies a distinct
realloc eligibility predicate: active chunk nonnull AND descriptor+16 equals
active+8. **HYPOTHESIS:** an empty owned active chunk at this start, with a
source longer than its usable capacity, reaches verified8413B0/85217F.
Next test that contract, rather than changing descriptor+4 into an invented
policy value. Original upstream spare-chain production/reset remains OPEN.
Reproduction commands and checks are in task-local PHASE1_REPORT.md.

## Nonempty null-field capacity extension: chunk linking — 2026-10-26, iteration4

`execute_capacity_growth.py` freshly lifts the existing2790/26B0/1AF0/
831A6F/8461F2 closure and verifies a previously unexecuted nonempty path.
Persistent1AF0 query reused the private index; no import/sweep. Receipt:
`work/recomp-bench/capacity-growth-linked/result.json`, current source pins MATCH.
Independent x86 service model vs production GuestHeap through GuestMemory/exact-VA
GuestDispatch; NOT Windows execution. Two explicit64-byte live allocations occupy
arena offsets0/64. The descriptor's old raw pointer is offset0, its two cursors
and bound are offset64, and descriptor+4 is0. Authored ownership is NOT evidence
of the original producer or startup lifetime.

This corrects the preceding next-step HYPOTHESIS: **nonempty does not imply
realloc**. This corpus calls831A6F for1032 bytes, not8413B0. The new raw block
is arena+128; its first header word links the old raw block, second word is1024.
The old block and obstructing allocation remain byte-identical. The new string,
including NUL, starts at new_raw+8; H+D0 and descriptor cursors publish that new
chunk's storage. No old-payload copy/rebase or free is executed. Interpreting this
as general chunk ownership/cleanup semantics remains HYPOTHESIS. Descriptor+4's
nonnull contract is still unknown; a nonzero integer is not a valid pointer fixture.

64/64 independent x86 publication checks;64/64 host and64/64 Linux/AArch64 QEMU
matches; both result/cleanup controls reject64/64 per ISA. Eight final GPRs and
six final pages, excluding flags/FP/PC/transient stores. Coverage111/231:
2790=13/16,26B0=26/30,1AF0=48/148,831A6F=5/5,8461F2=19/32. Seven public authored
registered tests. New bodies0; newly executable composed path1; fully resolved
dependencies0; AndroidFALSE. Full capacity/openers/1AB665/E3/E4 remain OPEN.
Next: recover descriptor+4's actual producer/representation before selecting a
nonnull realloc corpus; do not repeat either empty or this nonempty null-field path.
Reproduction and regression evidence: task-local PHASE1_REPORT.md, iteration4.

## Capacity growth boundary / portable reallocation — 2026-10-26

Next-step static evidence corrects the earlier shorthand “old-descriptor release”:
`8413B0` is an11-byte/five-instruction tail thunk to `85217F`; the latter is
105 bytes/44 instructions and imports HeapReAlloc. Its other indexed dependencies
are8437C6,842A91,8461B8,831B17 and8461F2. Both bounded read-only persistent queries
succeeded with one advisory ERROR log line each (no script compile error).
Private envelopes are located by `capacity-next-logs/{query,realloc-query}.stdout`.
No re-import, original-function lift or execution is claimed for these two units.

`GuestHeap::reallocate` and its stdcall16 endpoint now provide an explicit portable
service candidate: flags0, exact live base, shrink/adjacent growth or first-fit
move, preserve min(old requested,new size), failed growth retains ownership/data.
Zero-size remains an owned minimum block; unsupported flags/handles reject.
This is authored runtime policy, NOT Windows allocator reconstruction, IAT wiring,
startup ownership proof or a new original-function match. Registered C++ heap tests
include an independent cell/byte oracle plus move/failure/ABI/boundary cases.
HYPOTHESIS: this service can support85217F's successful nonempty growth path;
next verify its actual import ABI and flags in bounded x86, fresh-lift8413B0/
85217F, compare both ISAs, then compose capacity growth. Retry/error/free/global
startup/whole1AB665/E3/E4 and Android gameplay remain OPEN.

## Capacity default-allocation path composed — 2026-10-26

`execute_capacity_success.py` resumes the interrupted capacity increment and
freshly lifts2790/26B0/1AF0/831A6F/8461F2 from the pinned image using unchanged
pcrecomp. Existing persistent query envelopes are reused and independently
boundary-checked; no index import/sweep. Original x86 executes all five real
bodies with an independent explicit portable heap model. Native host and
Linux/AArch64 QEMU use production GuestHeap through GuestMemory/exact-VA dispatch.
This is NOT Windows HeapAlloc execution or a complete malloc contract.

Private receipt `work/recomp-bench/capacity-review-owned/result.json`:
64/64 independent x86 publication checks,64/64 host and64/64 AArch64 matches;
both result and outer-cleanup controls differ64/64 per ISA. All eight final
GPRs/six pages compared. Coverage107/231 sites:2790=13/16,26B0=26/30,
1AF0=44/148,831A6F=5/5,8461F2=19/32. Only the empty-descriptor, null-selector,
successful1032-byte allocation path is verified. Header words are0/1024;
raw allocation publishes at H+1D0, usable start at raw+8 publishes at H+D0,
and both descriptor cursors advance by the copied string length INCLUDING NUL.
The source is on a separate tracked page outside the exclusive heap arena.
These synthetic inputs are not evidence of upstream startup ownership.

Review found/fixed two authored-fixture defects with red/green regressions:
source storage initially overlapped the allocator-owned arena; REP MOVS span
checking initially admitted segment/address-size overrides it did not model.
Only plain forward32-bit REP MOVSB/MOVSD now opt in, with full-span checks;
default reference users still reject REP. Nine public automatically discovered
tests cover these boundaries, publication mutations and transport preservation.

One newly executable original composed success path (including previously
unexecuted1AF0 allocation instructions), ZERO fully resolved dependencies.
Nonempty old-buffer release, nonnull8413B0, size/growth/failure paths, retry/errno,
heap globals/lifetime/threads/SEH, flags/FP/PC/native transient stores and
whole1AF0/26B0/openers/1AB665/E3/E4 remain OPEN. Android execution FALSE;
no startup/menu/gameplay claim. Next inspect the real nonempty-descriptor
release/allocator closure and grow this composition, not repeat empty cases.
Reproduction and baseline receipts: task-local PHASE1_REPORT.md.

## Original allocator success path composed with portable heap — 2026-10-26, iteration4

`execute_heap_success.py` freshly lifts the complete 78B/32-site body at
`8461F2` using unchanged pinned pcrecomp, but verifies ONLY the first-allocation
success path (21/32 sites). Reuses the bounded persistent F1 index envelope;
no new import, index sweep or promotion. Explicit synthetic read-only IAT slot
`A0D9A1D8` points to an exact portable service target; synthetic heap-global
`A10E0380` carries an opaque token. These are input fixtures, NOT proven startup
writes, original Windows pointers or lifetime ownership.

Original x86 runs to the actual indirect CALL. At that declared boundary an
independent unit-occupancy allocation model handles the full stdcall12 frame;
native host/AArch64 executes production `GuestHeap::invoke_allocate` through
GuestMemory/exact-VA GuestDispatch. This is a real portable allocation service,
not fixed allocator-return responses, and **NOT original Windows HeapAlloc
execution or verification**. Default reference users still reject every unknown
target; new authored tests prove missing service, unknown target, wrong handle,
invalid frames and JMP-to-service fail closed. Retry/error callees are never
bound and cannot contribute to matches.

64 cases include request0 (observed promotion to1), alignment edges,1032,
4096 and deterministic random sizes; fresh arena/service state per case.
Eight final GPRs/six full pages match original-x86-with-service on host and
Linux/AArch64 QEMU. Independent contract checks result, nonvolatiles, ESP,
service arguments/call count and all non-stack bytes. Both wrong-result and
wrong-cleanup controls compile, execute and differ64/64 on EACH ISA. Eight
registered authored tests; receipt `work/recomp-bench/heap-success-final/`.

One previously unsupported original success-path behavior is now executable;
ZERO complete dependencies newly verified. Whole malloc, exhaustion/retry
`842A91`/indirect handler, error `831B17 → 84601E`, upstream global
initialization, full `1AF0`/`26B0`, openers, whole `1AB665` and E3/E4 remain
OPEN. No flags/FP/PC/native transient-store comparison, original-code Android,
startup or gameplay claim. **HYPOTHESIS:** this portable boundary is sufficient
for a bounded default-allocator success composition from `831A6F`; that caller
has not been composed here. Next: wire the actual wrapper forward and resolve
remaining error/retry/global-ownership contracts, not repeat the success corpus.

## Portable heap service for the malloc frontier — 2026-10-26, iteration3

Added authored `ts2::GuestHeap` to production `ts2_core`, with a CTest suite
and `scripts/recomp/check_guest_heap_service.py`. Caller supplies an opaque
nonzero handle and exclusively owned, already committed page-aligned arena;
constructor checks every page, does not map memory or initialize game globals.
First-fit eight-byte-aligned allocation (including a minimum block for size0),
checked 64-bit range arithmetic, zero-fill flag8, exhaustion→NULL, exact-start
free and adjacent-extent coalescing are explicit portable policy. Unknown
handles/unsupported flags fail closed. No host pointer enters guest state.
Integer HeapAlloc adapter reads the complete frame before allocation, returns
EAX and advances ESP16 (return+stdcall12); all other integer state is retained
by service policy, NOT a measured Windows clobber contract. No IAT auto-binding.

Authored tests cover fragmentation, dirty reuse/zeroing, complete arena reuse,
invalid/double/interior free, overflow, a missing middle page, high-end4GiB,
separate memories, actual exact-VA GuestDispatch invocation, and4000 operations
against an independent unit-occupancy model. Both wrong-cleanup and lost-zero
service mutations must compile, execute and hit their exact expected failing
assertion on each ISA; compiler failures/signals/timeouts do not count.

This implements ONE portable service, not a pcrecomp translation: **zero** new
original behaviors or dependency bodies verified. `8461F2` remains unexecuted;
its heap-global `A10E0380` initialization/ownership and actual IAT binding,
retry/error paths and whole opener/1AB665/E3/E4 are still OPEN. Synthetic arena
and handle tests cannot establish those contracts. GuestMemory permissions stay
page-based; freed bytes stay mapped, no allocation-lifetime guard or complete
Windows heap/SEH/thread/realloc semantics is claimed. Android original-code
execution remains false. Reproducer/receipts: task report iteration3.

## Allocator policy dependency verified — 2026-10-26

Followed the real default-allocation frontier `831A6F → 8461F2` using bounded
persistent queries, not a new import or whole-index promotion. Of its three
direct dependencies, `8437C6` now has a fresh pinned pcrecomp body executed
against original x86:64/64 host and64/64 Linux/AArch64 QEMU, all eight final
GPRs/six full pages; independent complete final-state oracle64/64. Both wrong
result and wrong cleanup controls differ64/64 on each ISA; coverage3/3 sites.
Harness: `execute_initialization_setter.py --rva 8437C6`; six registered authored
checks in `tests/test_recomp_allocator_policy.py`. Private receipt:
`work/recomp-bench/allocator-policy-first/result.json`; reproducer in task report.

The measured getter reads word VA `0xA10DFF54` into EAX, returns with ESP+4,
retains the other GPRs and leaves all tracked pages unchanged. Global values
are explicit synthetic input (zero, nonzero, high-bit and random); **not**
verified startup writes or process lifetime. **HYPOTHESIS:** allocator retry
policy role from its caller; this does not verify retry/failure semantics.
The original NOP was initially rejected by the reference allowlist; a red/green
authored NOP test now covers that narrowly permitted instruction. Existing
memory checks, immutable pages and unknown transfer failures are unchanged.
Bounded index ERROR1/scriptCompileError=false retained; exact body boundaries
independently agree. One newly resolved native dependency, not whole malloc.

Remaining malloc closure: imported HeapAlloc at IAT RVA `D9A1D8`, heap-global
VA `A10E0380`, `842A91` retry/indirect handler path, and `831B17 → 84601E`
error-state path. Their execution/global ownership/service semantics remain
unverified. Next target is actual `8461F2` with explicit tested guest-heap
service and verified heap-handle input, not repeated standalone getter runs.
No malloc response stub, whole opener/1AB665/E3/E4, Android original-code or
startup claim. Earlier per-function authorization stops in the F1 section
are superseded by standing authorization, not repeated as blockers.

## Composed opener initializer 2570 verified (2026-10-26, iteration20)

`scripts/recomp/execute_opener_init.py` freshly lifts complete `2570` (81B,
18 sites) with its real `1A40` and `1A00` callees using unchanged pinned
pcrecomp. One new bounded read-only persistent Ghidra query resolves `2570`;
existing leaf envelopes are reused. All decoded boundaries agree; retained
ERROR1/scriptCompileError=false is advisory, not suppressed. No reimport
or whole-index reliance. All31/31 sites execute in64 original-x86 cases,
matching an independent full final-state oracle. Host and Linux/AArch64 QEMU
match64/64 separately, eight GPRs and six full pages, including nested frames.
Wrong-field and wrong-cleanup controls each differ64/64 on each ISA. No stubs.

Measured contract for aligned disjoint writable receivers: EDX addresses116
bytes; the span becomes zero EXCEPT the word at+84 becomes1. EAX=1, ECX=0,
ESP+=4, other final GPRs and neighboring bytes preserved. Four receiver positions
include the exact page end. The original all-zero HYPOTHESIS was rejected by
x86 at+84; a public regression test went red before the oracle correction.
The straight-line caller invokes1A40 once and1A00 five times. Transport tracks
all six decoded return PCs in order, resets per case, and rejects unexpected
caller/target/count; generated bodies remain verbatim.

New dependency body1 and newly executable original behavior `2570`; its two
leaf bodies are reused knowledge, not new progress. Integration remains the
diagnostic GuestMemory/exact-VA boundary, NOT whole3A50/1AB665/E3/E4 or Android.
No flags/FP/PC/native transient-store-order, invalid-pointer, alias, allocation,
callback or lifetime proof. HYPOTHESIS: aggregate descriptor initialization,
not a recovered symbol. Eight registered authored checks cover oracle, bounds,
transport sequencing, preservation and rejecting controls. Private receipt:
`work/recomp-bench/iter20-opener-verified/result.json`; commands/regressions in
task-local PHASE1_REPORT.md iteration20. Next unresolved opener bottleneck:
full26B0 capacity/allocation path through1AF0 and its actual allocator closure;
do not re-measure2570 as progress.

## Opener dependency 1A00 verified (2026-10-25, iteration19)

The next dependency recorded behind `2570` now has a fresh pinned pcrecomp
lift: `1A00`, 14 bytes/six instruction sites, no callees. One read-only bounded
persistent Ghidra query agrees with independently decoded boundaries (6/6 sites
visited); its ERROR1/scriptCompileError=false remains recorded as advisory.
64 original-x86 cases match an independent final-state oracle; host and
Linux/AArch64 QEMU each match64/64 for eight GPRs and six complete pages.
Result and cleanup controls each differ64/64 per ISA. No stubs.

Measured bounded contract: incoming EAX points to16 writable bytes; exactly
those bytes become zero, ECX=0, ESP+=4, other GPRs and tracked memory unchanged.
Four aligned receiver positions include the exact page end. The distinction
from `1A40`'s20-byte span is enforced by public neighbor-write tests.
HYPOTHESIS: buffer-descriptor initialization; no recovered symbol or upstream
ownership claim. New dependency body1; newly executable original behavior1A00;
no whole2570/openers/1AB665, production binding or Android execution gained.
Flags/FP/PC/native transient writes, invalid-pointer behavior and lifetime remain
unverified. Next compose2570 with this actual callee rather than repeat1A00.

Profile: `scripts/recomp/execute_initialization_setter.py --rva 1a00`;
six registered authored tests: `tests/test_recomp_buffer_zero_init.py`.
Private receipt: `work/recomp-bench/iter19-buffer-init/result.json`.
Reproducer and regression receipt: task-local PHASE1_REPORT.md iteration19.

## Input writer 2790 through real 26B0 (2026-10-25, bounded execution)

`execute_handle_input.py` freshly lifts both complete bodies (56/60 bytes,
16/30 instructions) using pinned, unchanged pcrecomp. Existing2790 and one new
read-only persistent26B0 envelope agree with all decoded boundaries; no import.
64 synthetic nonnull, disjoint, sufficiently capacious owned-buffer cases match
original x86 on host and Linux/AArch64 QEMU: eight final GPRs and six complete
pages. Both publication/cleanup fault controls differ64/64 on each ISA.
Coverage is36/46 instruction sites; no allocator call executes. Ten registered
public authored checks test the semantic contract, transport and mutations.
Private receipt: `work/recomp-bench/handle-input-first/result.json`.

New measured contract: root2790 consumes stack arguments H and source. It passes
source in EAX and inline descriptor H+1D0 in ECX to real26B0. In these fixtures,
descriptor+8 is an end bound; +C/+10 initially equal the owned cursor. The pair
copies source INCLUDING NUL to the cursor, advances both +C/+10 by copied bytes,
leaves the end bound unchanged, and publishes the previous cursor in H+D0.
Root returns1, restores nonvolatiles, and advances ESP4 (caller arguments remain).
Lengths0..16, two receiver/stack locations and four cursor locations are covered.
The independent semantic oracle checks result/nonvolatiles/SP and ALL non-stack
bytes; x86 supplies the remaining scratch-register/stack reference.

This changes the prior static HYPOTHESIS into bounded evidence that D0 can point
to copied, descriptor-owned input rather than the incoming source. It is NOT a
lifetime proof or a producer-established descriptor contract. Full26B0 includes
unexecuted1AF0 dependency; bounded inspection finds1AF0 (362 bytes/148 sites)
calls8413B0/831A6F. Those bodies are not lifted or followed here. Allocation,
capacity-edge/null/failure paths, service74, full1460/1AB665 and E3/E4 remain
OPEN. New native bodies2, newly executable bounded behavior2790/26B0; fully
resolved dependencies0. No flags/FP/PC/native transient writes, Android or game
startup claim. Reproducer and failed exploratory-layout notes: task report.
Next compose the copied D0 state with the existing20D0 real-producer path, or
verify the1AF0 allocation closure; do not repeat this sufficient-capacity result.

## Input-field writer frontier (2026-10-25, iteration8; static only)

`inspect_handle_writers.py` crosschecks seven bounded bodies against persistent
read-only Ghidra envelopes:20D0,2120,2790,3A50,3C50,62B0,62F0. Independent
normal-flow decoding covers413 instructions and finds eight explicit stores
whose displacement is74,D0,D4 orE0. These are **candidate fields**, not proven
handle aliases. Register constants are intersected at joins; every call kills
ALL constants, including nonvolatiles, rather than assuming an unverified ABI.
Twelve registered authored tests exercise joins, loops, partial-register kills,
call invalidation, early returns and fail-closed bounds. Private receipt:
`work/recomp-bench/handle-writers-final/result.json`.

New dependency-directed finding:2790 (56 bytes/16 instructions) has two candidate
D0 stores at279C/27BE and calls26B0, which also appears among3A50's direct calls.
The first store encodes zero; the later register-sourced value is unknown to this
conservative analysis. HYPOTHESIS: this is a separate mutation/ownership path for
20D0's input, so opener initialization alone cannot establish its lifetime.
Next inspect/verify2790's real26B0 closure before treating D0 as stable input.
Neither20D0 nor its two indexed direct callers2120/62B0 has an explicit store to
these four offsets in the decoded normal-flow bodies. Their callees' effects
remain unknown; no whole-image writer absence is inferred.

The opener contributes74/E0/D4/D0 candidates,3C50 encodesD4=1, and62F0 contains
the74 copy candidate. This does NOT independently recover a callable nonnull74
target. Earlier zero-initialization/copy findings remain historical evidence;
unknown constants here do not contradict them (calls deliberately erase facts).
No lifts, x86 reference execution, native/ISA comparisons, portable services,
lifetime proof or E3/E4 milestone gained. All implicit, aliased and callee writes
are outside this explicit-displacement inventory. No whole-index JSONL reliance.
---

## Opener dependency 1A40 verified (2026-10-25, slot9 iteration1)

The direct `3A50` dependency `1A40` now has a fresh pinned pcrecomp lift and
its first executed differential: original x86 agrees with an independent full
final-state oracle in64 cases; host and Linux/AArch64 QEMU each match64/64,
eight final GPRs and six complete4096-byte pages. Both result/cleanup controls
differ64/64 on each ISA. All7/7 instruction sites are visited. One bounded
persistent query resolves function-at and agrees on17 bytes/seven boundaries;
its ERROR1/scriptCompileError=false is retained, not suppressed.

Measured bounded contract: incoming EAX points to20 writable bytes. Exactly
those bytes become zero, ECX becomes zero, ESP+=4; the other GPRs and all other
tracked bytes remain unchanged. Four aligned receiver positions include the
exact page-end span. This is a final-state claim, not an assertion about native
store order, flags, FP, lifetime or invalid-pointer behavior. HYPOTHESIS: small
container initialization; the label is not a recovered symbol. The existing
static graph records the3A50 edge; no enclosing initializer is thereby verified.

Harness/profile: `scripts/recomp/execute_initialization_setter.py --rva 1a40`;
six public authored checks: `tests/test_recomp_opener_zero_init.py`, registered
by normal unittest discovery. Private receipt:
`work/recomp-bench/slot9-zero-init-final/result.json`; reproducer and limits in
scripts/recomp/README.md and task-local PHASE1_REPORT.md. No allocator response
stand-in, whole3A50/1AB665 verification, production binding or Android execution.
This closes one dependency body, not the nonnull1460 service contract. Next
bottom-up dependency is1A00 behind2570, or the smallest unresolved opener edge;
do not re-measure1A40 as progress. Actual H+74/H+E0/lifetime writers remain open.

## 1460 nonnull first-service-call boundary (2026-10-25, iteration6)

`scripts/recomp/probe_service_input.py` executes ONLY the original prefix through
21/82 instruction sites, stopping BEFORE indirect call14B7. In64 synthetic cases,
all eight boundary GPRs and both complete4096-byte stack/receiver pages match an
independent boundary oracle. Four boundary mutations reject64/64 each: target,
argument order, frame depth and initial buffer fill. Seven registered authored
public tests additionally exercise REP bounds, immutable code identity and the
stop-before-unmapped-callee rule. Private receipt:
`work/recomp-bench/service-input-final/result.json`.

Receiver is ESI. The first service target comes from H+74; outgoing arguments
before CALL's return-address push are `[H+E0]`, incoming stack arg0 (`[entry ESP+4]`),
and a pointer to a1024-byte local buffer initialized to0xFF. Pre-call ESP is
entry ESP-1068; the buffer begins at entry ESP-1048. Three following local words
are zeroed. This is an input/boundary contract, NOT service-output/cleanup proof.
The pointer inputs are deliberately unmapped markers, never callable stand-ins.
No real H+74 target identity, service response, callback, allocator, native lift,
AArch64 or Android execution is established. Flags/FP and whole1460/20D0 remain
unverified. HYPOTHESIS: the service fills a descriptor consumed later; buffer
contents/length semantics beyond this input boundary are unknown.

The convenience whole-image JSONL scan failed on a malformed record; no absence
or completeness inference is made from its partial results. The existing valid
persistent1460 envelope is reused and independently boundary-checked; no re-import.
Next trace the writer of H+74/H+E0 and the source of incoming1460 arg0 in20D0,
then execute the smallest real service closure. Do not re-measure this prefix.

## Alternate producer10B60 verified with real classifier closure (2026-10-25)

Standing authorization permits this dependency-directed continuation. One bounded
persistent-index query at10B60 agrees with independent decoding:61 bytes,
18 instructions, three blocks; direct callee10700 only. Fresh pinned pcrecomp
lift composes10B60 →10700 →FCB0 with original immutable table/string pages,
not authored behavior responses. All generated bodies/states/binaries remain
private at `work/recomp-bench/alternate20d0-first/`.

64 synthetic inline-storage cases cover six matches per class0..5,27 misses
and one null-input class6. Success installs the alternate first two callback
addresses (RVAs10B00/10B30), the same FCF0 slot, class byte and back-pointer,
and publishes the inline service. Miss returns zero with all non-stack state
retained. Nonvolatiles/ESP and non-stack pages independently checked against
original x86; native host and Linux/AArch64 QEMU match all eight final GPRs
and six complete pages64/64 each. Both root-result and cleanup controls
reject64/64 per ISA. Producer18/18 instructions covered; classifier21/21,
comparator23/26 (62/65 composed instructions). Five new skip-free public tests.

This resolves one producer dependency body, not whole20D0, callback invocation,
flags/FP/PC/transient writes, input lifetime, E3/E4 or Android. The two installed
alternate callbacks themselves are not executed or newly verified. A bounded
1460 query reports279 bytes/82 instructions and four indexed callees
104F0/10C80/102D0/831A6F. Independent full-flow decoding agrees on all82
boundaries but identifies only102D0/831A6F as direct calls, plus four indirect
call sites (14B7/14EF/1528/1568); indexed callees are not all encoded direct
edges. REP STOSD uses ES, with no FS/GS observed. The prior first-RET158-byte
truncation is not a full function extent. Those dependencies and the indirect service contract remain
ordinary open engineering work, not permission gates. Next resolve1460's
smallest executable branch/closure before composing20D0; do not repeat either
settled producer standalone. Reproducer: scripts/recomp/README.md.

## Campaign G1 — FCB0 dependency verified standalone (2026-10-25)

The standing authorization supersedes the dated per-target stops below.
One read-only persistent-index query at FCB0 and independent pinned decoding
agree on 51 bytes / 26 instructions / 11 blocks. There are no direct/indirect
calls, imports, absolute globals or segment operands. FCB0 is a byte-string
equality helper, not an OS module service: bounded NUL-terminated EAX/EDX
inputs compare with ASCII a–z case folding and return Boolean EAX.

Fresh unchanged pinned pcrecomp lift executes through diagnostic GuestMemory /
exact-VA GuestDispatch: 64/64 host and 64/64 Linux/AArch64 QEMU comparisons
against bounded original x86, all 26 instructions visited. Independent checks
cover Boolean EAX, EBX/EBP/ESI/EDI/ESP and all six pages; volatile ECX/EDX are
compared only to x86, not an independent authored register oracle. Result and
cleanup perturbations each differ 64/64 per ISA. No flags/FP/PC or native
transient-write comparison. Inputs are synthetic valid strings, not established
classifier caller/table semantics; no whole10700 scan, producer failure,
production E4 or Android execution claim follows.

Harness: execute_initialization_setter.py --rva fcb0; four registered authored
checks: tests/test_recomp_module_comparison.py. Private receipt:
work/recomp-bench/g1-fcb0-final/result.json. Next measurable step is to compose
real FCB0 with the existing nonzero-EDI10700 reference and image-backed table,
without altering table words or authoring callee responses. HYPOTHESIS: this
removes the immediate external-call stop, but may expose another input/range
contract. Allocator, cleanup/callback, full opener and gameplay gates stay open.

## Campaign F3 — opt-in JNI fixture boundary (2026-10-25)

Build-side only: the diagnostic library now exposes named
`MainActivity.nativeLeafDifferential`. Its default implementation explicitly
reports unavailable. A private Debug-only CMake input stages the existing pinned
9550 lift verbatim, the 64 saved bounded-x86 inputs/poststates and the production
GuestMemory / exact-VA GuestDispatch fixture slice. No startup binding or new
original function is introduced. `prepare_android_leaf.py` generates only the
embedded I/O/comparison adapter, not a replacement function body.

The new adapter matched64/64 on host and64/64 Linux/AArch64 QEMU, with register
and last-page-byte faults rejecting per ISA. The private Android APK assembled
and linted; the restored default APK also assembled/linted and excludes the
private original-function symbol. These are NOT Android execution claims.
Flags/FP/PC/transient writes, thread/lifetime/OS behavior, and real initialization
remain outside this comparison. The fixture globals are serialized by a mutex;
that does not establish original game concurrency semantics.

An owner-only bundle at `work/recomp-bench/jni-f3-bundle-final` passes local hash
preflight; `docs/ANDROID_PROBE.md` documents one explicit USB install/hash/launch/
nonce-bound JNI-result batch. No device was contacted here, no proprietary body,
state, binary or raw log is committed, and Phase1 stays incomplete. Private
build/test/audit receipts: `work/recomp-bench/jni-f3-logs/`. All16 frontiers,
cleanup28D6, contracts, full E3/E4 and20D0 gates remain unchanged.

## Campaign F2 — nonzero classifier boundary and populated guard fragment (2026-10-25)

The new `scripts/recomp/inspect_classifier_paths.py` uses the existing persistent
read-only index envelope, not a new query/import. A nonzero-EDI classifier trace
needs the indexed read-only table page at RVA `0x1050000` (indexed operand base
VA `0xA1050044`); the old zero-context fixture never read that page. The pinned
image supplies the page, not an authored module/service response. For 64 bounded
nonzero inputs, execution reaches the direct call at RVA `0x10719` to external
`0xFCB0` after seven instructions. It stops **before** that call; no external
body, return value or transient call frame is supplied. Table/module semantics,
scan completion and producer failure remain unverified. The initial unmapped
read and subsequent Unicorn target-fetch failure are retained privately, not
counted as behavior matches. HYPOTHESIS: a bounded `0xFCB0` contract is needed
before this input-domain path-set can be completed; arbitrary table zeroing
would not establish the legitimate module-failure path.

The explicitly permitted alternative is the `0x1AB665` **populated `+0x34`
early-return fragment**, using `scripts/recomp/execute_initialization_guard.py`.
A fresh whole 267-byte/83-instruction pinned lift retains all other branches;
only the root is bound through diagnostic GuestMemory/exact-VA GuestDispatch.
Opener addresses are declared solely for compilation: no opener body, response,
return edge or dispatch binding exists. Reference execution must visit exactly
ten fixed instruction addresses and reach no callee. The independent guard
contract is **AL=1, upper EAX retained**, ESP+=4, other six GPRs unchanged;
retained stack words at incoming ESP-4/-8 equal incoming ESI/EDI. Both zero and
nonzero `+0x1C` occur, and populated handles include opaque/unmapped high values
that must not be dereferenced. This is an E3 fragment only, not initialized
ownership, whole-caller E3, production E4, or Android. Exact two-ISA results,
rejecting controls and current reproducer are in task `PHASE1_REPORT.md`.
All16 frontier behaviors, cleanup `0x28D6`, receiver/input/lifetime/callback
contracts and separately owner-gated `0x20D0` remain OPEN. No target traversal
from the F1 allocator inventory occurred.

## Surrounding object and handle

- RVA `0x1AB454` initializes an outer object: its `+0x34` pointer and result
  caches `+0x80`, `+0x84`, `+0x88`, `+0x8C`, `+0x90` are set to zero.
- RVA `0x1AB665` returns early when `+0x34` is already populated or `+0x1C`
  is null. Otherwise it chooses between calls at `0x3A50` and `0x3C50` using
  a mode byte at `+0x7C` and a string at `+0x60`. It stores the returned
  pointer in `+0x34` and checks for null. On success it associates the handle
  with the outer object through `0x1030` and installs multiple callback
  addresses through small setter routines. The opener is therefore not a
  read-only query or an isolated allocation call.
- RVA `0x3A50` requests a `0x210`-byte handle from the local allocation
  wrapper at `0x831A6F`, initializes its fields and subordinate state, and
  returns null on observed failure branches. RVA `0x3C50` calls `0x3A50`,
  sets additional mode fields and invokes `0x3700`. Both creator paths call
  `0x27D0` on observed post-allocation failures.
- RVA `0x27D0` walks handle-owned nodes, invokes helper cleanup, frees
  subordinate allocations through `0x831A54`, optionally invokes a callback
  held at handle `+0xE4`, and passes the handle itself to `0x831A54`.
  It dereferences the handle before any null check; callers must not pass a
  null pointer. The allocator/free wrapper behavior is inferred from these
  call patterns, not from recovered symbols.
- Another direct creator caller around `0x63B4`/`0x63C3` copies an existing
  handle into a new one and calls `0x27D0` on its observed failure path at
  `0x64B7`. The creators and destructor are thus not exclusive to this outer
  object. The direct-call scan cannot establish a complete ownership graph.
- RVA `0x1ABE93` changes that mode byte only while `+0x34` is null.
- The two mutation paths at `0x1ABADD` and `0x1ABB52` call `0x27D0` and clear
  `+0x34` when the mode byte supplied to each mutation is nonzero or the
  subsequent `0x1240` query returns zero. The deleting path at `0x1AB640`
  calls a destructor at `0x1AB54B`; that destructor releases several other
  fields through virtual calls but does not directly touch `+0x34` or call
  `0x27D0`. This scan does not prove every lifetime edge or whether another
  owner retains the underlying allocation.

## Query and cache flow

- RVA `0x1ABD40` passes the same `+0x34` pointer to five direct accessors.
  It writes their results to the five cache fields; the ARM64-validated
  `0x1240`, `0x1250` and `0x1270` functions feed `+0x80`, `+0x8C` and
  `+0x90`, respectively. It assumes a usable pointer and does not check null.
- The two direct calls to `0x1ABD40` occur at `0x1ABB28` and `0x1ABB7F`,
  after different mutation calls and a nonzero result from accessor `0x1240`.
  The result of `0x1240` is tested before refreshing all five caches.
- Wrappers at `0x1AB770` and `0x1AB78C` check `+0x34`: when present, they
  refresh `+0x90` or `+0x8C` through `0x1270` or `0x1250`; when absent,
  return the existing cached value. These are observable cache semantics,
  so a runtime cannot replace a missing handle with a zero result without
  changing behavior.
- The wrapper at `0x1AB7E0` also refreshes or retains cache `+0x80`, but
  then calls `0x1AB8A9` with the cached value. That callee uses an indirect
  jump table. It is not a cache-only wrapper and is outside the current
  three-function read-only validation boundary. The adjacent wrappers at
  `0x1AB7A8` and `0x1AB7C4` call as-yet-unvalidated leaves `0x12D0` and
  `0x1290`.
- RVA `0x1AB860` may call the opener, then passes `+0x34` to another original
  function at `0x1160`. The callee's null behavior has not been validated.

The scan found two direct callers of `0x1AB665` (`0x1AB86C`, `0x1ABAF5`)
and two direct callers of the five-cache refresh (`0x1ABB28`, `0x1ABB7F`).
It does not rule out indirect or virtual callers. Nearby paths include virtual
calls, and their targets and ABI contracts remain outside the validated slice.

## Callback registration and release boundary

A second, bounded static pass over the same pinned image followed the opener's
direct calls at `0x1AB6B5`–`0x1AB75B` into the small setter routines. The
following are **handle-relative fields**, not outer-object fields. For setters
that take two callbacks, their order follows the arguments after the handle
pointer.

| Setter RVA | Handle fields and stored callback RVAs |
|---|---|
| `0x1070` | `+0x28` = `0x1ABA77`; `+0x2C` = `0x1AB9D9` |
| `0x1090` | `+0x30` = `0x1AB979` |
| `0x10B0` | `+0x38` = `0x1AB993` |
| `0x10C0` | `+0x3C` = `0x1ABA62`; `+0x40` = `0x1AB9C4` |
| `0x10E0` | `+0x44` = `0x1AB9AA`; also sets `+0x110` to 1 |
| `0x1120` | `+0x54` = `0x1ABA28` |
| `0x1100` | `+0x50` = `0x1ABABA` |
| `0x1110` | `+0x5C` = `0x1ABA0E` |
| `0x1130` | `+0x6C` = `0x1AB9F0` |
| `0x10A0` | `+0x34` = `0x1ABA48` |

The last three setters run after the optional `0x1140` call site. That call
occurs when outer `+0x24` is nonzero and stores `2` at handle `+0x208`. The
`0x1140` return is tested, but its observed body always returns 1. This is a
static path observation, not a tested callback outcome.

Before registration, `0x1030` receives the handle and outer pointer. It writes
the outer pointer to handle `+0`; it also writes `+4` when those two fields
were equal on entry. The creator at `0x3A50` zeroes both fields, so the newly
created handle reaches the two-field write on the observed opener path. The
callback bodies at `0x1AB979`–`0x1ABABA` take their first stack argument as
an object pointer. Most guard one of its `+0x1C`, `+0x24`, `+0x28`, `+0x2C`,
or `+0x30` fields and then call a virtual method. `0x1AB9F0` instead calls
the separate helper at `0x62F0`. These are concrete reentry paths into the
outer object's dependencies; the setter table alone does not establish which
handle operation invokes each callback, the complete argument ABI, or their
side effects.

Two callback slots have visible invocation sites in the local handle routines:
`0x1669`/`0x168C` call handle `+0x44`, and `0x1DF9`/`0x1E42` call handle
`+0x30`. At all four sites, the first pushed argument comes from handle
`+4`. The newly opened handle gets the outer pointer there through `0x1030`.
The handle-copy path around `0x644C` can instead put either its source context
or the new handle itself at `+4`, depending on a comparison. Thus `+4` is a
callback context field; it cannot be globally equated with the outer object.
Other registered fields still need call-site and ABI tracing.

The destructor's **different** indirect callback slot is handle `+0xE4`. It
is initialized to zero by `0x3A50` and is not filled by any setter in this
opener. If nonzero at teardown, `0x27D0` calls it with handle `+0xDC` as its
single pushed argument, then frees the handle. A bounded follow-up located a
producer at `0x1460`: it calls the indirect service pointer held at handle
`+0x74`, receives a context and callback in separate output slots, and writes
them together to `+0xDC` and `+0xE4` after its later setup call succeeds. On
two observed failure branches, it invokes a nonzero returned callback with
the context immediately instead of storing the pair. The creator initializes
`+0x74` to zero; the copy path around `0x642E` transfers it from an existing
handle. The origin and contract of a usable `+0x74` service pointer remain
unidentified, as do the callback's full ownership rules. The two outer-object
mutation paths call `0x27D0` before clearing outer `+0x34`; therefore a nonzero
teardown callback could run while that outer field still points at the handle. This ordering is
visible statically and must be preserved or explicitly disproved by a future
reference test.

A full raw-image search for direct `call 0x27D0` encodings found five sites:
`0x3C3E`, `0x3CA4`, `0x64B7`, `0x1ABB38`, and `0x1ABB8F`. These are the
observed creator-failure, copy-failure and mutation-release paths. Byte-search
hits cannot exclude an indirect call to the same destructor, nor prove that
every one of these direct sites is reachable in a given run.

**Next host-only boundary:** identify the actual indirect call sites for the
registered fields, the service behind `+0x74`, and the handle/outer reference
rules. Until those are evidenced and tested, dispatch must reject these
callback-bearing operations rather than approximating them. No Android device
was used for this static pass.

## Validated wrapper boundary and next integration question

The pair of wrappers `0x1AB770` and `0x1AB78C` passed 64/64 bounded x86 oracle,
Windows host and physical ARM64 state comparisons, covering null and non-null
handles, retained/refreshed caches, return state and guest-memory writes. Each
wrapper directly calls only one already validated leaf. The private bytes,
generated C and reference states remain hash-pinned under ignored `work/`; see
[LOCAL_VALIDATION.md](LOCAL_VALIDATION.md). This result establishes only the
cache semantics of those two calls. Any later runtime model of the full outer
object still needs checked guest memory, explicit handle lifetime rules,
fail-closed dispatch and reference validation for every reached service,
especially creator callbacks, release, mutation and the jump-table path.

## Campaign D verification correction (2026-10-24)

The dated static description below remains historical evidence. Its ~94-byte
`0x9550` extent ends at the early return and omits reachable local switch arms.
The bounded whole graph has **49 instructions / 120 reachable bytes and six
switch destinations**. The Campaign C 135/136 figure counts composed
instructions, not switch arms. Campaign D standalone leaf and thunk experiments
reach all six destinations, including invalid-byte arm `0x95c2`.

`eab04f6` (leaf) and `e504b28` (thunk plus real leaf) record 64/64 host and
64/64 Linux/AArch64 QEMU comparisons each, eight GPRs and six full pages, with
49/49 and 51/51 instruction coverage respectively. Two authored bridge-fault
controls reject on each ISA. This does not establish flags/FP/PC/transient-write
parity, exhaustive UTF-8 semantics, arbitrary invalid/truncated or regressing
ranges, copy/rebase/thread safety, production binding or Android execution.
The historical raw-truncated budget exhaustion is not erased by these fixtures.
Private receipts: `work/recomp-bench/{leaf-d1,thunk-d2}/result.json`; exact
commands and limitations: task-local `PHASE1_REPORT.md`, Campaign D entries.

Continuation root audit `37b5218` also corrects the proposed next closure:
`0x1AB665` does not call the verified wrapper pair. `0x20D0` selects a producer
indirectly and its EDI is unknown in the bounded prefix; the `0x3A50` path's
never-fails argument below must not be generalized to it. Neither continuation
root has a whole-caller reference/native comparison. Opener/callback scope,
alternate producer/service dependencies and actual input contracts need explicit
owner decisions; no additional callee traversal is authorized by this correction.

## Campaign E E2 callback setter10B0 — continuation from02dcc25

10B0 now has a fresh unchanged pinned pcrecomp lift and first executed
original-x86 differential:12 bytes/four instructions/one block. Cached E1
persistent-Ghidra envelope reused readOnly/no analysis, ERROR1 retained,
no truncation; pinned image checked before/after. All64 original-x86 cases
match the independent oracle: handle+38=value, EAX=value, ECX=handle,
ESP+=4, other final GPRs and tracked bytes unchanged. Zero/high-bit/edge/random
values and two aligned placements are synthetic valid inputs, not verified
producer/lifetime states. The stored callback is data only, never invoked.

Verbatim lift through diagnostic GuestMemory/exact-VA GuestDispatch matches
64/64 host and64/64 Linux/AArch64 QEMU. Wrong-slot and wrong-cleanup controls
each differ64/64 per ISA. Eight final GPRs/six full pages only: no flags/FP/PC,
transient-write parity, callback ABI, E3/E4, production binding or Android.
Three public checks in tests/test_recomp_initialization_setter.py;39 focused
checks pass. Private receipt work/recomp-bench/setter-e14-final/result.json;
exact commands, pins, costs and baseline results in task-local PHASE1_REPORT.md.
Newly resolved dependencies1, first-executed RVAs1; android_executed=false.

Next distinct E1-inventory call-free candidate10960. The earlier graph's
unverified-candidate list is historical, not the current verified count.
All16 frontier addresses, cleanup indirect28D6 and receiver/input/producer/
lifetime/callback contracts remain unresolved; external expansion needs a
bounded owner decision and20D0 stays separately gated. **HYPOTHESIS:** these
service contracts dominate whole-initialization progress, not small setters.
No settled-body reruns, graph sweep, external body expansion or new import.

## Campaign E E2 callback setter1100 — 2026-10-24

One further E1-inventory dependency now has its first executed differential:
1100,12 bytes/four instructions/one block. Fresh unchanged pinned pcrecomp lift
from the pinned image, using cached E1 persistent-Ghidra metadata; no graph
sweep, re-import or external body expansion. All four boundaries agree.
64 original-x86 cases independently match the final contract: object+50=value,
EAX=value, ECX=object, ESP+=4; all other GPRs and tracked bytes unchanged.
Zero/high-bit/random values and two object/stack placements; synthetic aligned
objects, not verified opener producer/lifetime states. Callback values are
stored, never invoked.

Verbatim generated body executes through diagnostic GuestMemory/exact-VA
GuestDispatch:64/64 host and64/64 Linux/AArch64 QEMU matches. Wrong-slot(+4
shift) and wrong-cleanup(+8 extra) each differ64/64 on each ISA. Eight final
GPRs/six full pages compared, not flags/FP/PC/transient writes. No production
binding, E3/E4, whole initialization or Android execution. Three new authored
skip-free checks in tests/test_recomp_initialization_setter.py (24 total).
Private receipt work/recomp-bench/setter-e9-final/result.json; exact reproducer,
pins and regression evidence in task-local PHASE1_REPORT.md. Newly resolved
dependencies1, first-executed RVAs1. Earlier receipts' harness pins are historical.

Next distinct in-inventory candidate1110, subject to its bounded contract.
All16 external frontier addresses, cleanup indirect28D6 and receiver/input/
producer/lifetime/callback contracts still block whole-caller composition;
external expansion needs a bounded owner decision,20D0 separately owner-gated.
**HYPOTHESIS:** actual service contracts, not the remaining small setters, are
the whole-initialization bottleneck. No settled-body executions repeated.

## Campaign E E2 paired callback setter10C0 — 2026-10-24

10C0 now gains its first executed differential:19 bytes/six instructions,
one block, fresh unchanged pinned pcrecomp lift from image63a545db...9985.
The fixed-inventory initialization harness reuses E1's read-only Ghidra envelope;
all six instruction boundaries agree with independent decoding.64 original-x86
cases match the independent oracle: handle+3C=first callback, handle+40=second,
EAX=handle, ECX=first, EDX=second, ESP+=4.16 equal and48 unequal pairs cover
edge/random values and two object/stack placements. These are synthetic valid
objects, not verified producer/lifetime contracts.

The verbatim generated body matches64/64 host and64/64 Linux/AArch64 QEMU
through diagnostic GuestMemory/exact-VA GuestDispatch. Wrong-slot and cleanup
controls each differ64/64 per ISA; crash/malformed output is not a behavioral
kill. Eight final GPRs/six full pages compared; no flags/FP/PC/native transient
writes or store ordering. Neither callback is invoked. No E3/E4, production
binding, original startup or Android execution is claimed. Newly resolved
dependencies1; first-executed RVAs1.

Harness: `scripts/recomp/execute_initialization_setter.py --rva 10c0`;
three new authored skip-free tests in tests/test_recomp_initialization_setter.py.
Private receipt paired-e8-final/result.json; exact reproducer, pins and limits
in task-local PHASE1_REPORT.md. Prior target receipts' harness pins remain
historical. Next distinct in-inventory candidate1100; do not repeat settled
units.16 external frontier addresses, cleanup indirect28D6 and receiver/input/
lifetime/callback contracts still block whole initialization;20D0 separately
owner-gated. **HYPOTHESIS:** service contracts, not these setter leaves, remain
the whole-caller bottleneck.

## Campaign E E2 dual-effect setter10E0 — 2026-10-24

The next fixed E1 dependency gains its first executed differential:10E0,
22 bytes/five instructions/one block. Fresh unchanged pinned pcrecomp lift,
image63a545db and cached persistent-Ghidra10e0 envelope; every instruction
boundary matches independent decoding. No saved-body fallback or callee stub.
64 original-x86 cases independently oracle-match both handle+44=input callback
and the separate32-bit handle+110=1 update. EAX=handle, ECX=input, ESP+=4;
other GPRs and every other tracked byte unchanged. The volatile-register
polarity is NOT the1090/10A0 contract. State inputs0,1,all-ones,2/random and
two object/stack placements cover changed and already-one states. These are
synthetic aligned objects, not verified producer writes/lifetimes.

Verbatim lift:64/64 host and64/64 Linux/AArch64 QEMU through diagnostic
GuestMemory/exact-VA GuestDispatch;5/5 original instructions visited.
Wrong-slot and wrong-cleanup controls each differ64/64 per ISA. Compared:
eight final GPRs/six full pages, not flags/FP/PC/native transient writes.
Callback data is stored, never invoked. No E3/E4, production binding or Android.
Four added public checks, focused18/18, exercise both independent writes,
register polarity, input isolation, verbatim transport and index rejection.
Private receipt: work/recomp-bench/dual-e7-final/result.json; reproduction and
pins: the Phase 1 report (private record). Newly resolved dependencies1,
first-executed RVAs1; prior1030/1090/10A0 harness pins are historical.

Next distinct in-inventory candidate10C0 has paired callback stores; do not
repeat this unit or the settled set. All16 external frontier addresses,
cleanup indirect28D6 and receiver/input/lifetime/callback contracts remain
open;20D0 separately owner-gated. External-body expansion needs a bounded
owner decision. **HYPOTHESIS:** these service contracts still dominate whole
initialization; another verified data setter does not establish an opener.

## Campaign E E2 association1030 — 2026-10-24

One more initialization dependency now executes independently: `0x1030`,
28 bytes/11 instructions/three blocks. Cached E1 read-only Ghidra envelope
`init-e3-logs/1030.json.env.json` reused; every instruction boundary independently
checked against the pinned image. Fresh unchanged pcrecomp API lift, no body
fallback or authored callee. Original-x86 reference matches an independent
association ABI oracle64/64, visiting11/11 instructions and both paths32 times.

Measured contract for valid aligned objects: store the supplied context at
handle+0; also update handle+4 only if +0 and +4 were equal on entry. EAX returns
the handle and ESP advances4. Equal path: ECX becomes supplied context, EDX
unchanged. Unequal path: ECX retains old+4, EDX becomes supplied context. Other
GPRs and complete tracked pages remain unchanged. Cases include creator-like
zero/zero, unequal contexts, edge/random values and two object/stack placements
on each branch. These are synthetic states, not actual producer/lifetime proof.

The verbatim lift matches64/64 host and64/64 Linux/AArch64 QEMU cases through
the existing diagnostic GuestMemory/exact-VA GuestDispatch bridge. Wrong-slot
(+4 shifted writes) and wrong-cleanup(+8 extra) controls each differ64/64
per ISA; malformed/crashed output is not a behavioral kill. Eight final GPRs
and six full pages compared; no flags/FP/PC/native transient-write comparison.
No callback invoked, production binding, E3/E4 or Android execution claimed.

Harness `scripts/recomp/execute_initialization_setter.py --rva 1030`, four new
skip-free public checks in `tests/test_recomp_initialization_setter.py` (14 total).
Private receipt `work/recomp-bench/association-e6-final/result.json`; reproducer
and pins in task-local PHASE1_REPORT.md. Newly resolved dependencies1,
first-executed RVAs1. Prior setter receipts remain historical source pins.
Next distinct candidate10E0 has a callback store plus a separate state write;
no reason to repeat1030/1090/10A0. The16 external frontier addresses, cleanup
indirect28D6, callback/receiver/input/lifetime contracts and owner-gated20D0
remain unresolved. **HYPOTHESIS:** these service contracts, not the association
leaf, remain the whole-initialization bottleneck.

## Campaign E E2 callback setter10A0 — 2026-10-24

One additional root-relevant dependency is now executed, not merely inspected:
10A0,12 bytes/four instructions. The extended fixed-inventory
`execute_initialization_setter.py --rva 10a0` reuses its E1 read-only Ghidra
envelope, verifies the pinned image and unchanged pcrecomp, and freshly lifts
this target.64 original-x86 cases independently oracle-match object+34 write,
EAX=value, ECX=object and ESP+=4. Verbatim lifted body matches64/64 host and
64/64 Linux/AArch64 QEMU through diagnostic GuestMemory/exact-VA GuestDispatch.
Wrong-slot(+38 instead of+34) and extra-cleanup(+8) controls each differ64/64
per ISA; malformed output does not count as a kill. Eight GPRs/six full pages
compared, not flags/FP/PC/transient native accesses. Inputs are synthetic aligned
objects, not verified opener/producer/lifetime contracts. Callback stored only.

Private `work/recomp-bench/setter-e5-final/result.json`; reproducible command,
timings, reference pin and baseline checks in task-local PHASE1_REPORT.md.
Three new authored tests plus expanded index checks; focused10/10 skip-free.
Newly resolved dependencies1; first-executed RVAs1. No E3/E4, production binding
or Android execution. All16 external frontier addresses, cleanup indirect and
receiver/input/lifetime/callback obligations remain open;20D0 remains gated.
Next distinct in-inventory E2 target: association1030 (not repeated setters),
subject to its bounded data/ABI contract; external targets need owner decision.
**HYPOTHESIS:** remaining leaf work can proceed independently, but cannot close
the initialization caller without actual allocation/setup/cleanup services.
The1090 section's source pin is historical at eaea6bc; no1090 execution repeated.

## Campaign E E2 callback setter1090 — 2026-10-24

The root-relevant12-byte/four-instruction setter1090 now has a **fresh pcrecomp
lift and executed differential**, rather than merely call-free graph status.
`scripts/recomp/execute_initialization_setter.py` uses unchanged pinned pcrecomp,
the pinned analysis image and cached read-only E1 index metadata.64 original-x86
cases match an independent oracle: stack arg1 is stored at object+30; EAX holds
the value, ECX the object, ESP advances4 (callee does not pop arguments). All
other final GPRs and all six tracked pages match. Inputs cover zero/high-bit/
actual registered callback values, random values, two object and stack offsets.
No callback is invoked and no producer/lifetime contract is claimed.

The verbatim generated body executes through the diagnostic GuestMemory and
exact-VA GuestDispatch bridge.64/64 host and64/64 Linux/AArch64 QEMU states
match the same fresh x86 reference. Wrong-slot(+34 instead of+30) and wrong
cleanup(+8 extra) bridge controls differ64/64 each on each ISA; malformed/partial
outputs cannot count as behavioral kills. Seven authored skip-free public tests
register the harness contracts in the existing suite. Flags/FP/PC and native
transient accesses are not compared; Android execution remains false. This is
one newly resolved dependency and one first-executed RVA, **not E3/E4**, game
startup or production registration. Private receipt: setter-e4-final/result.json;
reproducer and validation in task-local PHASE1_REPORT.md and recomp README.

The16 external frontier addresses, cleanup indirect call and receiver/input/
lifetime/callback contracts from E1 remain open. Next distinct E2 unit: one of
the remaining root setters (10A0), not a repeat of1090.20D0 remains owner-gated.

## Campaign E E2 callback setter1110 — 2026-10-24

Next fixed initialization dependency verified independently:1110,12 bytes/four
instructions/one block. Fresh unchanged pinned pcrecomp lift from image63a545db,
checked against the cached E1 read-only persistent-Ghidra envelope (standing
ERROR1 retained); every instruction boundary agrees with independent decoding.
64 original-x86 cases match an independent oracle: object+5C=value, EAX=value,
ECX=object, ESP+=4; remaining GPRs/page bytes unchanged. Edge/random values and
two object/stack placements; synthetic valid objects, not producer/lifetime proof.

Verbatim generated body:64/64 host and64/64 Linux/AArch64 QEMU matches through
diagnostic GuestMemory/exact-VA GuestDispatch. Wrong-slot and wrong-cleanup
controls each differ64/64 on each ISA; malformed output cannot count as a kill.
Eight final GPRs/six full pages, not flags/FP/PC/native transient writes.
No callback invocation, production registration, E3/E4 or Android execution.
Three authored public checks, focused27/27; harness
`scripts/recomp/execute_initialization_setter.py --rva 1110`, private receipt
`work/recomp-bench/setter-e10-final/result.json`. Reproducer/pins in task-local
PHASE1_REPORT.md. Newly resolved dependencies1; first-executed RVAs1. Prior
receipts retain historical harness pins; settled bodies were not re-executed.

Reflection: E2 leaf progress is real but does not resolve the16 external
frontier addresses, cleanup indirect28D6 or receiver/input/producer/lifetime/
callback contracts. **HYPOTHESIS:** those service contracts remain the actual
whole-caller bottleneck. External expansion needs a bounded owner decision;
20D0 separately owner-gated. Next distinct in-inventory candidate1120, not
another graph sweep or repeated leaf. Android/runtime/validator gates remain.

## Campaign E E2 callback setter1120 — 2026-10-24

Next fixed E1-inventory unit:1120,12 bytes/four instructions/one block.
Harness `scripts/recomp/execute_initialization_setter.py --rva 1120` adds only
this pinned target, reusing E1's read-only persistent-Ghidra envelope. Public
checks in tests/test_recomp_initialization_setter.py cover the full independent
oracle, isolation, edge/random values, two object/stack placements, wrong slot/
cleanup/volatile registers, verbatim transport and exact index rejection.
The measured contract is object+54=value, EAX=value, ECX=object, ESP+=4;
other GPRs and tracked bytes unchanged. These are synthetic aligned objects;
callback values are stored as data, never invoked. No producer/lifetime proof.

Fresh unchanged pinned pcrecomp lift:64 original-x86 independent-oracle
matches; verbatim body64/64 host+64/64 Linux/AArch64 QEMU through diagnostic
GuestMemory/exact-VA dispatch. Wrong-slot and wrong-cleanup each differ64/64
per ISA. Eight final GPRs/six full pages, not flags/FP/PC/transient writes.
Newly resolved dependencies1; first-executed RVAs1; Android false.
Execution receipt and regression results: task-local PHASE1_REPORT.md,
Campaign E iteration11; private work/recomp-bench/setter-e11-final/result.json.
No E3/E4, production binding, whole initialization or Android claim follows.
The16 external frontier addresses, cleanup indirect28D6 and receiver/input/
producer/lifetime/callback contracts remain open. External expansion needs a
bounded owner decision;20D0 separately owner-gated. Next distinct inventory
candidate1130, not another settled-body execution or graph sweep.
**HYPOTHESIS:** service contracts remain the whole-caller bottleneck.

## Campaign E continuation —10700 EDI-zero opener path (starting54aee23)

E2 advances from call-free units to a **path-restricted** dependency:
`scripts/recomp/execute_initialization_setter.py --rva 10700` and
`tests/test_recomp_initialization_classifier.py`. Cached read-only persistent
Ghidra envelope `init-e3-logs/10700.json.env.json` is reused without querying
or importing again. Indexed49B/21 instructions/seven blocks; the older0x60-byte
inspection bound is not its function size. The whole body is freshly lifted,
not replaced with a constant-return hand implementation.

Only the already-established opener context EDI=0 is tested. Original x86
visits exactly four instructions, never the externalFCB0 branch. Independent
contract: EAX=6, ESP+=4, other GPRs and all six tracked pages unchanged.
The scanning path (17 unvisited instructions) remains **unverified**. Native
transport declares FCB0's address solely to compile the retained branch;
there is no callee body, dispatch registration, service response or new frontier
translation. Both direct-return and exact-VA dispatch reject that external edge.
The first compile failure (missing address declaration) is retained separately.

Detailed results, controls, pins and reproducer are in the latest task-local
PHASE1_REPORT.md. This is not whole10700 verification, E3/E4, production
initialization or Android. **HYPOTHESIS:** the next distinct bounded increment
is109D0 with real10700 execution under the same zero context, retaining every
producer write and nested frame in the comparison. Do not infer its other
caller20D0's inputs or expand the16 external frontier addresses/cleanup
indirect28D6. Receiver/input/lifetime/callback and Android gates remain open.

## Campaign E continuation — descriptor getter10960 (starting a18f9ba)

E2 now covers the last call-free candidate from the fixed E1 inventory:
`scripts/recomp/execute_initialization_setter.py --rva 10960` and
`tests/test_recomp_initialization_descriptor.py`. Cached persistent Ghidra
`init-e3-logs/10960.json.env.json` supplies read-only/no-analysis provenance;
no new query/import or frontier-body inspection. Its indexed extent is6B,
**two instructions**, not the historical “one-instruction getter” shorthand
below. The return value is a descriptor address, not validated descriptor
semantics, contents, lifetime or a service implementation.

The public exact-target regression exposed the old transport's four-digit-RVA
substitution bug:10960 generated an over-wide VA and failed compilation. The
fix formats BASE+RVA numerically before substituting identifier text, never
rewrites the generated body, and keeps the exact-VA assertion. Initial failed
receipts are retained privately, not reported as native matches. Getter controls
alter EAX and cleanup independently; wrong-slot is intentionally disallowed for
this no-store unit. Detailed final evidence is in the latest task report.

**HYPOTHESIS:** external service and input contracts, not call-free leaves,
remain the whole-initialization bottleneck. All16 external frontier addresses,
cleanup indirect28D6 and receiver/producer/lifetime/callback contracts stay open.
Next distinct bounded E2 dependency:10700 on the opener's already-established
EDI-zero path, then109D0 with real callee execution. Reconfirm that this can be
isolated without executing externalFCB0; otherwise stop-and-record for a bounded
owner decision. Do not silently expand the frontier or the separately gated20D0.
No E3/E4, production startup, Android rendering or gameplay follows from this unit.

## Campaign E producer109D0 zero-context comparison — 2026-10-24

`scripts/recomp/execute_initialization_producer.py` now freshly lifts the whole
61B/18-instruction producer with the real49B/21-instruction10700 callee.
Cached persistent read-only index envelopes reused; unchanged pinned image and
pcrecomp checked before/after. Private final receipt:
`work/recomp-bench/producer-e17-outer-control/result.json`. Six public skip-free
checks in `tests/test_recomp_initialization_producer.py` cover the authored
contract, nested frames, exact dispatch, provenance and behavioral controls.

**Measured:**64 original-x86 independent-oracle matches;64/64 host and64/64
Linux/AArch64 QEMU native matches through diagnostic GuestMemory/GuestDispatch.
Wrong object-slot and **outer-only** cleanup controls each differ64/64 per ISA
with complete parseable outputs. Third argument is0 in every case, incoming EDI
varies and is preserved, real callee runs on the established EDI-zero path.
Only16/18 producer and4/21 classifier instructions execute; producer failure
and classifier scanning paths remain unverified. No FCB0 execution or binding.

Independent post-state contract covers eight final GPRs and six full4096B
pages: EAX=1, ECX=obj, ESP+=4, saved incoming EDI and nested return word retained
below initial ESP, object+0/+4/+34 callback addresses, +49=6, +4C=link,
publication[link]=obj. Callback values are data, not invoked. Object and link
are separate bounded aligned storage in these fixtures; this is not inline
ownership/lifetime proof or an executed opener. Flags/FP/PC/transient native
writes excluded. Android false, E3/E4 still open.

The first attempt's EAX=link oracle was disproven (all page bytes matched,
only EAX differed); corrected to the success Boolean1 after a red regression.
A second attempt faulted nested cleanup and produced rejected rows, correctly
excluded as behavioral kills. Final control changes outer cleanup only. Failed
receipts are retained; exact reproducers/pins/costs in the task report.

**HYPOTHESIS:** external service/input/lifetime contracts now dominate fuller
opener composition. All16 frontier addresses and cleanup indirect28D6 remain
open;20D0 remains separately owner-gated. Next distinct authorized work can
provision pinned Android prerequisites for A4 without touching app/gates.
No settled body needs another standalone green run; no game startup follows.

## Campaign F1 allocator boundary — 2026-10-25 (static inventory only)

Campaign F explicitly authorizes the previously requested read-only probe; the
Campaign E authority stop is historical. Exactly ONE persistent query at
`0x8461F2` (64 instructions, 16 references, 8 callers, 16 callees, no pseudocode)
and one independent pinned-image window of at most `0x400` bytes were inspected.
No discovered target was followed, lifted or executed. Harness:
`scripts/recomp/inspect_allocator_boundary.py`; five authored public checks:
`tests/test_recomp_allocator_boundary.py`. Private query and result:
`work/recomp-bench/allocator-f1-logs/` and `allocator-f1-final/result.json`.

Independent normal-flow decoding reaches 32 instructions / 78 bytes, 9 blocks,
36 edges, ending with a plain return at `0x84623F`. Its independent linear
boundaries agree with all 32 indexed instructions. The query has no instruction
or callee truncation, but references/callers are capped; WARN0/ERROR1 is retained.
The indexed name `__malloc_base`, unknown calling convention and zero recovered
parameters are metadata, NOT a validated no-argument ABI. No explicit FS/GS
operand was observed in this window. Encoded RET cleanup is zero; net stack
and callee effects remain unverified.

| Dependency kind | Observed address / metadata | Status |
|---|---|---|
| Direct call | `0x8437C6` | Recorded, body not inspected |
| Direct call | `0x842A91` | Recorded, body not inspected |
| Direct call | `0x831B17` | Recorded, body not inspected |
| Indirect IAT call at `0x846224` | Slot RVA `0xD9A1D8`, import `KERNEL32.dll!HeapAlloc` | Import metadata only; no implementation/binding |
| Other absolute memory operand | VA `0xA10E0380` | Global address only, contents/ownership not inspected |

**HYPOTHESIS / proposal only:** the next allocator-specific scope could start
with these three direct callees, the HeapAlloc service contract and the global
initialization/lifetime contract, instead of opening all 16 initialization
frontier targets. This is a smaller *first-hop inventory*, not proof of a smaller
transitive closure: helper bodies can reveal further dependencies. Owner approval
is still required before following them or implementing heap semantics. A bounded
allocator body does not resolve allocation, failure/retry, lifetime or cleanup.
No dependency newly gains a native body; E3/E4 and Android execution remain false.
The other 15 frontier targets, cleanup indirect `0x28D6`, receiver/input/callback
contracts, and separately owner-gated `0x20D0` remain open. F2 in-graph path
verification and F3 build-side JNI integration remain the authorized next queue,
not blocked by this proposal-only stop.

## Campaign E inline producer contract — iteration7 (starting8cbbb10)

The separate-storage limitation above is now tested explicitly, without
executing the opener or allocator. `execute_initialization_producer.py` accepts
`--layout inline`: a bounded0x210-byte handle H, publication slot H+0x78,
and service object H+0x7C share a page. The separate default remains unchanged;
arbitrary overlap and out-of-handle layouts reject before the oracle runs.
Three new authored tests in `tests/test_recomp_initialization_inline.py`
check all final registers/pages, inline publication/back-pointer fields,
non-mutating deterministic inputs and rejection of incorrect overlap/fields.
They fail before the layout extension and pass after it.

The independent oracle locates the publication write in the object's page
rather than assuming a separate page. Real109D0/10700 bodies, nested frames,
exact dispatch and the existing two behavioral controls remain unchanged.
This tests a fixed self-referential storage layout, **not** allocation,
object lifetime, rebasing, callback invocation or whole-opener behavior.
Private receipts and final execution results are recorded in the iteration7
section of task-local PHASE1_REPORT.md. No frontier body or20D0 inspected.
E3/E4 and the16 external targets/cleanup indirect28D6 remain open.

## Campaign E initialization dependency graph — 2026-10-24

Campaign E's renewed owner authority supersedes the historical Campaign D scope
stop for **read-only** `0x1AB665` initialization analysis, not the separate
`0x20D0` register/input gate. This pass reuses the pinned `37b5218` root receipt;
it does not repeat that root audit or the settled leaf/closure experiments.

Harness: `scripts/recomp/inspect_initialization_graph.py`; seven authored,
skip-free public tests: `tests/test_recomp_initialization_graph.py`. Private
receipts/index envelopes: `work/recomp-bench/init-e3-final/` and
`work/recomp-bench/init-e3-logs/`. The image is checked before/after inspection;
the persistent Ghidra project is queried read-only, never re-imported. Fixed
investigation inventory: at most22 nodes (including the reused root), 0x400
bytes per newly inspected body; unlisted edges stop without reading their bodies.

**Classification and bounded closure candidate (not a translation result):**

- **(a) Already verified, reused:** `0x1070` is the only previously verified
  callee reached. The settled query/accessor/wrapper bodies are not reached and
  cannot stand in for this initialization graph.
- **(b) Newly needed inside this bounded investigation:** root `0x1AB665`;
  association/setters `0x1030,0x1090,0x10A0,0x10B0,0x10C0,0x10E0,0x1100,
  0x1110,0x1120,0x1130,0x1140`; openers `0x3A50,0x3C50`; cleanup `0x27D0`;
  mode helper `0x3700`; wrappers `0x831A54,0x831A6F`; producer/descriptor
  dependencies `0x109D0,0x10960,0x10700`. These **21 nodes include the root**.
  Twenty bounded bodies were newly inspected, not lifted or executed.
- **(c) External frontier — stop for a bounded decision before translating:**
  `0x1000,0x1330,0x17A0,0x1820,0x1A40,0x1AA0,0x1AF0,0x2570,0x25D0,
  0x26B0,0xFCB0,0x10AF0,0x10B60,0x122F0,0x8461B8`, plus the normal-flow
  escape address `0x8461F2`. A separate **zero-instruction**, read-only index
  query resolves this address as function-at, named `__malloc_base`; that symbol
  is metadata, not a validated allocation implementation/ABI. “External”
  here means outside this fixed investigation inventory, **not necessarily an
  OS import**, missing code, or a new domain. No such body was decoded/lifted.

| Inspected node | Observed outgoing boundaries (RVAs) |
|---|---|
| `1AB665` | Existing14 direct edges: association/setters above plus1070 and3A50/3C50 |
| `3A50` | `1A40,2570,26B0,27D0,10960,109D0,122F0,831A6F` |
| `3C50` | `27D0,3700,3A50,10AF0,10B60` |
| `27D0` | `1000,17A0,1AA0,25D0,831A54`; one unresolved indirect call |
| `3700` | `1330,1820,1AF0,26B0` |
| `831A54` | `8461B8` (existing authored release ABI is not a verified lifted body) |
| `831A6F` | Five instructions then normal flow escapes the0x400 window to8461F2; incomplete decode, not a returning leaf |
| `109D0` | `10700` |
| `10700` | `FCB0` (syntactic edge; no branch-feasibility proof) |
| Association/setters and10960 | No calls in their bounded decoded bodies |

This produces **41 recorded edges** including the escape and cleanup indirect
edge. The escape is retained explicitly instead of silently treating the
allocation wrapper as call-free. Nineteen new bodies have complete bounded
normal-flow decoding; the allocation wrapper does not. Full indexed boundary
agreement holds for20/21 graph nodes (the reused root plus19 new bodies).
The allocation wrapper's decoder is incomplete despite its five indexed
instructions. Reference/caller caps and the standing Ghidra log ERROR are
retained individually in the private receipts. An index gap never means absence
of executable code. The zero-instruction frontier metadata query, including its
ERROR1 and read-only provenance, is retained separately under init-e3-logs.

**Next E2 units:** the eleven new association/setter bodies plus10960 are
12 call-free *candidates*, not verified translations. Pick a root-relevant setter
(e.g.1090) for fresh pcrecomp lift, >=32 original-x86 cases, host/AArch64 execution
and rejecting controls before moving upward. The larger success/cleanup/mode
composition needs the frontier decision and verified input/producer/lifetime
contracts. Installing callback addresses as data does not verify those callback
bodies or invocation ABIs. The cleanup indirect edge remains unresolved here;
the historical handle+E4 observation is not a bound executable callback contract.

**HYPOTHESIS:** the full opener path is blocked on allocation, nested setup,
mode and cleanup contracts rather than the already verified query leaves.
This static graph narrows that hypothesis; it supplies no native bodies,
reference states, feasible-path proof, Windows service, production binding,
game startup or Android execution. `composed_execution_ready=false` and
`bounded_decodes_complete=false`; return status2 records boundaries, not a pass.
No `20D0` traversal, app/gate/campaign change or proprietary promotion occurred.

## Classifier scan composed with real FCB0 — Campaign G iteration2 (2026-10-25)

`execute_classifier_scan.py` closes the bounded nonzero-EDI10700 execution gap:
fresh pinned lifts of10700 andFCB0, exact nested return1071E, real GuestMemory/
exact-VA dispatch, original image-backed six-entry pointer table at1050044 and
its pointed-to strings. Table and string pages remain immutable; no fabricated
callee result or rewritten table participates. One bounded persistent query10700
agrees with independent decoding (49B/21 instructions); priorFCB0 index reused.
All derived bodies, strings and states remain private.

64 valid synthetic NUL-terminated inputs cover all six match indices (six cases
each),27 misses returningFFFFFFFF, and one null-input result6. Case-folded
matches and prefix/suffix mismatches are included. Original-x86 execution passes
an independent value/nonvolatile/ESP/non-stack-page contract. Verbatim native
bodies match all eight final GPRs and six complete pages **64/64 host and64/64
Linux/AArch64 QEMU**. Root-only wrong-result/cleanup controls each differ64/64
per ISA. Coverage21/21 classifier plus23/26 comparator instructions; the three
unvisited comparator instructions are not promoted as covered by this composition
(standalone G1 independently covered26/26).

Receipt `work/recomp-bench/g2-scan-verified/result.json`, reference SHA256
49142185e35ca6f69993d52e1cacb81fd13893344e9cfeef08f3e7d930a83598;
public skip-free tests `tests/test_recomp_classifier_scan.py`. Reproducer in
`scripts/recomp/README.md`. New dependency bodies:0 (FCB0 already settled);
newly executable behavior:10700 scan/match/miss and two-body composition.

No producer/caller input ownership, arbitrary invalid pointer, whole1AB665,
allocator/cleanup/callback invocation, E3/E4 production binding, flags/FP/PC/native
transient writes, Android execution or startup/gameplay is established. Next:
compose this path with109D0 nonzero third argument to verify both its success
and failure side effects before following20D0's actual register/input contract.
These are ordinary authorized work, not renewed permission stops.

## 102D0 direct dependency verified (2026-10-25)

The earlier6-byte/two-instruction index-only finding below now has a fresh
pinned pcrecomp lift and executed original-x86/host/Linux-AArch64 comparison:
64/64 per ISA, all eight final GPRs/six complete pages, two rejecting controls
per ISA, coverage2/2. The observed contract is constant EAX1912, ESP+=4,
other GPRs preserved and tracked memory unchanged. No arguments/receiver are
consumed. HYPOTHESIS: this is a size query for1460's allocation path; its name
is a harness label, not a recovered symbol or verified allocator contract.

Reproducer: `scripts/recomp/execute_initialization_setter.py --rva 102D0`
with the existing102D0 persistent envelope; full command, private receipt and
limits are in the Phase 1 report (private record). Six public authored
checks are in `tests/test_recomp_service_size.py`. This resolves one standalone
direct dependency, not the1460 nonnull path, whole20D0/1AB665 or production
integration. No flags/FP/PC/transient-write or Android execution claim.
Next: bind the real H+74 target and smallest callback/allocator closure;
unknown calls remain hard failures. Historical unexecuted finding below stands
as the dated prior state rather than being silently overwritten.

## 1460 null-provider return fragment verified (2026-10-25)

New harness `scripts/recomp/execute_service_guard.py` reuses the persistent1460
index, pins the full279-byte body and freshly lifts all82 instructions through
unchanged pcrecomp. Only the null `[ESI+0x74]` branch is behaviorally verified:
64 synthetic cases match original x86, an independent full final-state oracle,
host native execution and Linux/AArch64 QEMU. ESI supplies the receiver; return
EAX=18, EDX=0, ESP+=4, other GPRs restored/preserved. Non-stack pages remain
unchanged; saved EBP and EDI words remain on the scratch stack. The meaning of
status18 is not established. Arbitrary initial GPRs prevent confusing this
register ABI with incoming EAX at20D0.

Coverage13/82 instructions, zero calls. Eight final GPRs and six complete pages
are compared; two result/cleanup controls each differ64/64 on both ISAs.
Six registered authored tests cover scope, frames, retention and strict parsing.
Private receipt: `work/recomp-bench/service1460-final/result.json`; exact command
and source pins there, reproduction in scripts/recomp/README.md. The native bridge
registers1460 ONLY; other targets remain hard failures, never authored responses.

No full dependency resolution is counted: nonnull provider, REP STOSD, the four
indirect sites, direct102D0/831A6F, callbacks/heap/ownership and whole20D0 remain
OPEN. One additional bounded persistent query102D0 agrees with independent
first-return inspection on6 bytes/two instructions/no calls, but no102D0 lift or
execution is claimed. Next test is the smallest nonnull-provider/service closure,
not another null-guard run. Whole1AB665/E3/E4, flags/FP/PC/native transient writes,
Android and startup/gameplay remain unverified.

## 20D0 actual first-call register/input contract (2026-10-25)

`probe_producer_input.py` reuses the persistent Ghidra index, independently
crosschecks all26 root instruction boundaries and executes original x86 until
BEFORE call site20F6.64 synthetic receiver cases cover13 prefix instructions,
selecting109D0 in16 and10B60 in48. No callee executes, no response is authored,
and no newly verified translation/native execution is counted.

Measured partial ABI: incoming EAX is receiver H; ESI becomes H, saving incoming
ESI on the stack. The receiver's+D4 word chooses main109D0 when zero, alternate
10B60 otherwise (including high-bit/all-bits-set values). The three outgoing
arguments, in argument order, are `H+7C`, `H+78`, `[H+D0]`; ESP before CALL is
incoming ESP minus16 (three arguments plus saved ESI). Incoming EBX/EBP/EDI
remain unchanged; all non-stack bytes and every stack byte outside those four
words remain unchanged. This deliberately does NOT assert scratch GPR values
or flags. Null/non-null D0 fields are independent of the producer selector.

This resolves a gap in the earlier static unknown-EDI observation without
erasing it: caller-prefix EDI is still arbitrary, but it is NOT the source of
producer argument3. The producer's verified argument handling must receive
`[H+D0]`; the other opener's zero-input proof cannot be imported. H+D0's caller
ownership/lifetime is still unknown. Initial zero-filled exploratory state gave
a false zero-argument HYPOTHESIS, rejected by randomized receiver execution.

Receipt `work/recomp-bench/input20d0-receipt/result.json` succeeds; three boundary
mutations reject64/64 each. Eight registered authored tests are skip-free.
This is original-x86 prefix evidence only: no lift, native host, AArch64,
Android, full20D0 return or production integration claim. Next resolve1460 and
compose20D0's main path; then real10B60 and the incoming caller field writers.
Full1AB665/E3/E4, allocation, cleanup and callback invocation remain open.

## Producer nonzero-input composition verified (2026-10-25)

`execute_classifier_scan.py --producer-index ...` now executes the real
109D0 → 10700 → FCB0 chain with original image-backed table/string pages.
Fresh pinned lifts, unchanged upstream, no authored behavior responses.
Private receipt: `work/recomp-bench/producer-scan-final/result.json`;
reproducer and limitations: task-local PHASE1_REPORT.md and scripts/recomp/README.md.

64 bounded synthetic fixtures: six matches for each index0..5, 27 misses, one
null-input class6. Successful producer calls publish the inline service pointer,
its established callback/back-pointer fields, and the selected class byte.
Failure returns zero and preserves every non-stack byte (including the old
publication slot and service storage). Incoming EDI is restored on both paths.
This is measured original x86 behavior, independently checked for result,
nonvolatiles, ESP and non-stack pages. Host and Linux/AArch64 QEMU each match
all eight final GPRs and all six complete pages in64/64 cases. Root result and
cleanup controls each differ64/64 per ISA. Producer18/18 and classifier21/21
instructions visited; comparator23/26 in this composition, total62/65.

No newly resolved body: this wires settled bodies forward to previously
unsupported producer success/failure behavior. It does not prove20D0's incoming
register/input contract, allocation/lifetime/callback invocation, whole1AB665,
E3/E4 production registration, flags/FP/PC/native transient writes, Android or
game startup. Next dependency-directed task:20D0 actual input/register binding.
Standing full-image authorization applies; this is ordinary engineering work.

## Calloc tail success composition (2026-10-28)

`execute_calloc_success.py --wrapper-index` freshly lifts83A371(11B/5 sites)
and849A00(93B/39) and preserves their actual tail frame through checked
GuestMemory/exact-VA GuestDispatch. Reused persistent Ghidra queries agree on
boundaries; original x86 executes both bodies with an independent portable
zeroing MODEL, while native execution uses production GuestHeap. This is NOT
Windows HeapAlloc verification or original startup heap/global ownership.

Private `work/recomp-bench/calloc-tail-first/result.json`:64/64 full final GPR/
six-page matches on host and Linux/AArch64 QEMU; result/cleanup controls each
reject64/64 per ISA. Coverage33/44 including thunk5/5. Eleven authored calloc
tests are registered via Python discovery. ONE newly executable success
composition, ZERO all-path dependencies resolved; AndroidFALSE. Error/retry/
overflow, flags/FP/PC/transient writes, actual1820 creation and full initialization
remain open. Reproducer and timings in task-local PHASE1_REPORT.md.

NEXT actual caller-owned1820 creation after183D; HYPOTHESIS: the verified
success tail fits its observed64×4 request, but prior occupancy, publication
and downstream dependencies still require composed comparison. Do not repeat
isolated calloc/no-create receipts. No startup/menu/gameplay/E3/E4 claim.

## Default allocation tail caller success (2026-10-26, iteration5)

`execute_heap_success.py --wrapper-index ...` freshly lifts actual `831A6F`
(11B/5 instructions) and actual `8461F2` (78B/32), with the pinned unmodified
pcrecomp API. Reused persistent `831A6F` index agrees exactly; ERROR1 retained.
The wrapper uses an external **tail JMP**, not an ordinary CALL. The general
normal-flow decoder correctly rejects that edge; a separate pinned bounded
wrapper decoder permits only this final direct target. Transport preserves both
generated bodies verbatim and passes the existing return frame through exact-VA
GuestDispatch/GuestMemory, never pushes an invented tail return address.

Private `work/recomp-bench/default-success-first/result.json`: original x86
plus independent occupancy-model service passes64/64; native production
GuestHeap host64/64 and Linux/AArch64 QEMU64/64. Full eight final GPRs/six
pages compared; visited26/37 sites including all5 wrapper sites. Wrong-result
and wrong-cleanup controls each differ64/64 on each ISA. Inputs include0,528,
1032,4096 and alignment/random sizes; one fresh allocation per case. Seven
registered public tests use authored fixtures, not game bytes.

One newly executable original **successful path**, zero fully resolved allocator
dependencies. Windows HeapAlloc is not executed/verified: both sides explicitly
substitute independently implemented portable allocation services. Heap token,
IAT/global data and arena are synthetic read-only inputs, not original startup
ownership. No retry/error/exhaustion/flags/FP/PC/transient-store/lifetime proof,
Android execution, full1AF0/26B0, whole opener/1AB665/E3/E4 or game startup.
Next: wire this successful default allocation into the capacity path only after
resolving its next real dependencies; retain retry/errno/global startup work.

## Capacity entry prefix through `0x1AF0` (2026-10-26)

`probe_capacity_service.py` records original-x86 prefixes only, never executes
or supplies a response for an external heap call. Persistent bounded1AF0 query
plus independent decode agree on362B/148 instructions (advisory ERROR1 retained).
Private `work/recomp-bench/capacity-prefix-verified/result.json`:64 cases,
35/194 sites across2790/26B0/1AF0. All reach call1C00→831A6F, pending request1032
bytes at ESP, entry stack delta−36, all non-stack pages unchanged. The explicit
null allocator selector at receiver+1D4 matters: the older sufficient-capacity
fixture left it random and fails on an unmapped pointer read when capacity is
exhausted. Eleven public authored checks include this regression and rejecting
boundary mutations; no original bytes/states published.

HYPOTHESIS: null selector selects default allocation. These32 empty/32 full
synthetic descriptors do not establish upstream initialization/ownership, general
size arithmetic, nonnull8413B0 behavior or heap lifetime. No new native body,
complete-function differential, AArch64/Android execution, whole opener/1AB665
or E4 claim. Next: actual831A6F default allocator dependency/service closure,
not another sufficient-capacity repeat or a stand-in allocation response.

## The nested text-service behind `0x1290`/`0x12D0` is resolved (2026-10-24)

Owner-authorized bounded probe (result of the decision requested at 08:05Z; budget:
32 metadata hits, 2 producer bodies at ≤0x400 bytes). Evidence is disassembly of the
hash-pinned analysis image plus two read-only Ghidra metadata queries
(`work/supervisor-session-20261024/ghidra-fcf0.json.env.json`,
`ghidra-109d0.json.env.json`, image SHA-256 `63a545db…9985`).

Verified, at instruction level:

* `0x1290` and `0x12D0` (17 instructions each) guard on `[H+0x100] != 0`. When set
  they load `S = [H+0x78]` and invoke `[S+0x34]` with four pushed arguments —
  `(S, [H+0x108], [H+0x100], &H+0x1C8)` for `0x1290` and `&H+0x1CC` for `0x12D0` —
  cdecl-style, **caller cleans 16 bytes**; the return value is discarded; afterwards
  `[H+0x108] := [H+0x100]`. `0x1290` returns `[H+0x1C8] + 1`, `0x12D0` returns
  `[H+0x1CC]`. `ECX` carries no argument (the `push ecx` pushes its value).
* The **only** writers of the slot value `0xA000FCF0` are `0x109FE` (inside `0x109D0`,
  main path) and `0x10B8E` (inside the alternate producer `0x10B60`), both as stored
  data — Ghidra reports exactly two references, both `DATA`. So **both opener paths
  install the same `[S+0x34]` target**; no other function can be that target.
* Producer on the `0x3A50` path: `0x109D0(&H+0x7C, &H+0x78, 0)` builds the service
  **inline** in the handle: `[H+0x78] = &H+0x7C`, `+0x00 = 0xA0010970`,
  `+0x04 = 0xA00109A0`, `+0x34 = 0xA000FCF0` (i.e. handle offset `+0xB0`), `+0x49 = 6`
  (the encoding class returned by `0x10700`), `+0x4C = &H+0x78` (back-pointer). It is a member of
  the 0x210-byte allocation, so `S` and `H` share one lifetime; there is nothing
  separate to free. `0x3A50` does **not** pre-zero `+0x78/+0x7C` and does not test
  the producer's return value, so a failed producer leaves the service uninitialized
  — a lifetime obligation for any runtime model. In this call site `EDI = 0`, and
  `0x10700` returns 6 on that path, so the producer **cannot fail here** (verified
  0x60-byte body; the scanning branch applies only when `EDI != 0`).
* `[S+0x34]` is a two-instruction thunk at `0xFCF0`:
  `mov dword [esp+4], 0xA0E17AB0` then `jmp 0xA0009550` — it replaces `arg0` (the
  self-pointer) with a static data object and tail-calls the real callee.
* The real callee `0x9550` (ends `ret` at `0x95AD`, ~94 bytes) is a **leaf**: no
  imports, no heap, no further indirect calls. It walks text bytes over
  `[arg1..arg2)` = `[[H+0x108]..[H+0x100])`, classifies each byte through a 256-entry
  table at `0xA0E17AB0 + 0x4C` (switch via a local jump table at `0x95C8`),
  increments `*(&H+0x1C8)` per decoded unit and maintains `[H+0x1CC]`. Hypothesis
  (not established): UTF-8 code-point advance/count over a text range, which matches
  the accessors returning "count + 1" and "index".

What this settles for the closure of `0x1ABD40`: the indirect edge is a **static
target** — VA `0xA000FCF0` (thunk) → RVA `0x9550` (leaf) — so `0x1290`/`0x12D0` are
liftable with exact-VA dispatch, and a composed x86 reference can execute the real
callee with image-backed pages plus an initial handle state equal to the producer's
output. `0x12D0`'s only difference is the output slot.

Still unknown (recorded, not silently expanded): who writes `[H+0x100]`/`[H+0x108]`
(the text range) and under what lifetime rules; how the handle-copy paths
(`0x63B4`–`0x64B7`) rebase the self-referential `+0x78/+0x7C` pair; what `0x20D0`
(the other caller of `0x109D0`) does with it; the `0x10B60` body beyond its stored
`+0x34` value; the exact encoding semantics of the class table. None of these block
the static-target conclusion.

## Text-range ownership: who writes `H+0x100`/`H+0x108` (2026-10-24, owner-authorized probe 2)

Bounded per the decision recorded in `2a61d33` (operand-level scan of all `.text`, 2
producer bodies ≤0x400 B, 2 Ghidra metadata queries — inside the proposed bounds).
`.text` contains exactly 15 stores to `+0x100` and 5 to `+0x108`; every one was read in
context.

Verified:

* **Single-owner mutation.** Every store to `[H+0x100]` in the two dispatcher bodies
  (`0x2EC0`–`0x3034`, `0x3230`–`0x332C`) is guarded by `cmp ebp, [H+0x78]` — the same
  self-referential service pointer the producer installs — and only the bound service
  may commit a new range end. The dispatchers return per-message codes (`1`,`2`,`4`,
  `0xA`–`0xF`) and call service methods through `[service+0x10]/+0x14`.
* **Publish-after-write.** In `0x3208`–`0x3264` bytes are copied first and only then is
  `[H+0x100] := ` the new end. Combined with the reentrancy flag at `[esi+0x1c]` (set
  around the nested `call 0x2D10`, cleared after) this is single-threaded, message-pump
  ownership: consumers (`0x1290`/`0x12D0`) can never observe text newer than its end.
* **Cursor-only advance.** `[H+0x108]` is written only by (a) opener zero-init, (b) the
  accessors themselves (`:= [H+0x100]` after a refresh), and (c) buffer-attach paths
  (`0x1C89`, `0x295C`: `:= [H+0xc]`, the buffer start). The attach path also rebinds the
  `+0xF8` callback to validated leaf `0xA0001240`, confirming these are the same 0x210
  handle class; `+0x104/+0xfc` are the retained/refreshed-cache pair already validated
  for the `0x1AB770` wrappers.
* **Leaf and decoder semantics confirmed at body level.** `0x9650` (referenced only as
  data from descriptor tables `0xE17980/AF0/C60/DD0` next to the text globals) is a
  **UTF-8→UTF-16 transcoder** including surrogate-pair emission — the same class table
  (`descriptor+0x4C`) the leaf `0x9550` advances over. The earlier UTF-8 hypothesis is
  now corroborated by direct decode of the companion body; the unvisited leaf arm
  `0x95c2` is the invalid/continuation-byte step (class 10), reachable with crafted
  bytes and therefore testable, not exotic.
* `0x10960` is a one-instruction getter returning the alternate-path descriptor
  `0xA0E17D90`; its only caller is the opener `0x3A50`.

Not established (recorded, not assumed): whether message-supplied end values can move
the end pointer **backwards** below the current cursor (no local clamp is visible; the
invariant would then be a caller contract); full reentrancy-flag protocol beyond
set/clear; thread-safety outside the observed message-pump discipline (no locks seen —
none needed single-threaded). Consequence for the existing M2 reference: its authored
handle state satisfies exactly these invariants (end published from a buffer, cursor ≤
end, bound service present), so the static evidence is consistent with the already
executed 64/64 comparisons; it does not replace the behavioral validation, and no
production binding is claimed by this probe.
