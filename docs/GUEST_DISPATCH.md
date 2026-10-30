# Bounded guest dispatch

`native/include/ts2/guest_dispatch.hpp` adds an exact 32-bit VA registry beside
`GuestMemory`. This is host-tested runtime infrastructure, **not game integration**.
It does not replace the private probe's existing guard or change its allowlist.

## Storage-query selector boundary — run3 iteration49

`tools/ptd_query_probe.py` + eight authored tests check8480BF, without binding
storage to the runtime. After bootstrap: `python3 tools/ptd_query_probe.py --index
work/phase1-run3-049/query.json`. ONE persistent query after cache search;
23 instruction boundaries/mnemonics over63 bytes match pinned independent decode,
not operands/pseudocode. Four references/four callers/two callees untruncated;
standing CA-bundle ERROR retained. 256 development x86/oracle matches compare
all8 GPRs, full4096-byte stack, defined logic flags+DF, ordered calls and immutable
pages. Three wrong cleanup models reject. Authored tests never open private code.

The selector requests resolver847E6C/cdecl(33, nameE06E5C, beginE0A05C,
endE0A064). PE metadata independently identifies FlsGetValue, candidate IDs21/16,
TlsGetValue at import D9A2C8, and initial guard pointer140FE0 at D9A71C.
A nonzero resolver result is held in ESI, passed in ECX to the guard, then called
with the unchanged32-bit index; the wrapper restores ESI/EBP and uses RET4.
A zero result instead restores those registers and TAIL-jumps to TlsGetValue:
that provider sees the original return/index at entry-SP, not a nested frame.
Both paths finish at entry-SP+8 and return the entire provider EAX word, including
zero/high-bit/FFFFFFFF. Resolver and provider may clobber ECX/EDX in the tested
contract; the injected guard preserves state. These are dependency contracts,
not tested actual guard/OS behavior or a claim that the query preserves last-error.

Do NOT alias847E6C to the earlier82A212 resolver: the call target, cache index33
and candidate list differ. Cookie-encoded-cache naming remains HYPOTHESIS until
a separately tested resolver contract exists. An initial metadata assertion
wrongly expected IDs0/1; it failed before x86 execution and was corrected to
independently read21/16 (initial failure retained). No original bytes changed.
No real resolver/guard/FLS/TLS/lifecycle, heap ownership, SEH/races/reentry/native
lift/ARM64/startup/gameplay. Historical hook SIGBUS remains open. NEXT compose
this cached query wrapper with the existing-slot/release harness to remove the
8480BF interception, with explicit nested stack/error effects; NO fresh query
needed. Then resolve847E6C's actual cache/dependencies (cache search first).
Actual8480FE/849A00/845CF9, full828A9D/844495, factory/+70 order remain open.

## Composed release error path — run3 iteration48

`tools/heap_error_composed_probe.py` + eight authored tests execute the cached
8461B8 release wrapper,831A7A mapper,831B17 accessor and84601E existing-slot
provider in ONE bounded development x86 context:198 oracle matches and two
wrong-cleanup models rejected. Cached index/decode checks agree on125 instruction
boundaries/mnemonics, not operands/pseudocode. Reproduce after bootstrap:
`python3 tools/heap_error_composed_probe.py`. No fresh Ghidra query or runtime
binding. Only HeapFree, Get/SetLastError and8480BF remain injected; the mapper
and two error helpers are no longer intercepted. The original table is shared
input, not an independent mapping oracle; authored high-bit substitutions test
priority over both fallback intervals.

The independent composed oracle checks all eight registers, full4096-byte stack,
branch-defined flags+DF, ordered API requests, both error slots and last-error
restoration. A query deliberately disturbs last-error; SetLastError must restore
it. ExistingFFFFFFFF is normalized by the actual provider, so the actual accessor
selects fallback104F750; an existing mapped high-bit pointer selects pointer+10.
The actual release store changes ONLY that selected word, preserving the other.
Null context and nonzero HeapFree results must leave both words untouched.
Nested provider frames save EBX/EDI (not the release wrapper's ESI mapping);
checking only final ESP would miss a wrong stack model. Release caller cleanup
at8461E5 pops its error argument into ECX, overwriting the mapper's miss-path
scratch14. Authored x86 confirms that cleanup behavior. Wrong query/set cleanup
models must reject. Eight public tests use authored bodies, never private inputs.

This is composition of original bodies in a reference emulator, NOT a native
lift or actual heap/thread services. Only one safe mapped PTD fixture and the
existing sentinel are supported. IndexFFFFFFFF, zero query/slow paths, unchecked
pointers and out-of-body execution reject, not successful fallback emulation.
No real8480BF/8480FE/849A00/845CF9, heap ownership, FLS/TLS lifecycle, SEH,
races/reentry, ARM64, startup or gameplay. PTD/errno names remain HYPOTHESIS;
historical hook SIGBUS stays open. NEXT resolve8480BF's storage-query boundary
(cache search first, at most ONE persistent query if absent), reusing the existing
resolver/loader checks where relevant. Do not grow the matrix into guessed
allocation/ownership behavior or bind an inferred service.
Full828A9D/844495 and factory/+70 ordering remain unresolved.

## OS-error mapping boundary — run3 iteration47

`tools/os_error_probe.py` + eight authored tests check831A7A, without a runtime
binding. Reproduce after bootstrap: `python3 tools/os_error_probe.py --index
work/phase1-run3-047/mapper.json`. ONE persistent query after cache search;
29 indexed boundaries/mnemonics/67 bytes agree with pinned independent decode,
NOT operands/pseudocode. Three references/three callers/no callees untruncated;
standing CA-bundle ERROR retained. 561 development x86/oracle matches compare
all8 registers, full4096-byte stack, defined arithmetic flags+DF and immutable
code/table/return pages. The original45-entry table at E073F0 stays private;
it is shared input data, not an independent behavior oracle.

The function performs a FIRST exact-key lookup in45 eight-byte records, returning
the second word unchanged. Only on miss: unsigned19..36 inclusive maps to13,
unsigned188..202 inclusive maps to8, everything else maps to22 (including zero
if absent from the table). Exact entries override intervals; duplicate keys use
the first match. Authored table substitutions exercise first/last hits and
priority over both intervals, including high-bit return values. Cdecl leaves the
argument caller-owned; ECX keeps the input on hits/first interval, otherwise14.
Other GPRs are preserved. No guest OS service is called by this body.

The indexed CRT name is HYPOTHESIS, not a recovered-symbol contract. No heap,
errno storage, thread lifecycle/FLS/TLS, SEH/races/reentry/native lift/ARM64/
startup/gameplay is implemented. Historical hook SIGBUS remains open. NEXT
compose cached release/mapper/accessor/existing-provider boundaries in a bounded
host check before any heap binding; no new query required. Actual8480BF/8480FE,
849A00/845CF9 and heap ownership remain unsupported. Earlier sections retain
historical unresolved status; this increment resolves mapper behavior only.

## Lazy-provider request ordering — run3 iteration46

`tools/ptd_lazy_probe.py` + eight authored tests extend the cached84601E
provider evidence without changing the existing-path harness or binding runtime
services. Reproduce after bootstrap: `python3 tools/ptd_lazy_probe.py --index
work/phase1-run3-045/provider.json`. No new query. 648 original-body x86/oracle
matches check full8regs/full stack/events/defined flags+DF/immutable pages;
67 cached indexed boundaries/mnemonics agree, NOT operands or pseudocode.

Invalid indexFFFFFFFF skips query but STILL requests write(index,FFFFFFFF)
through8480FE/stdcall8; zero query result takes the same path. Failed sentinel
request returns zero without allocation. Any nonzero response requests
849A00/cdecl(1,364). A zero allocation requests write(index,0), then
8461B8/cdecl(0). Nonzero allocation requests write(index,pointer); failed
publication requests write(index,0) BEFORE free(pointer), without initialization.
Successful publication calls845CF9/cdecl(pointer,address10E002C), then
free(0), returning the pointer. A newFFFFFFFF pointer is NOT normalized like
an existingFFFFFFFF value. Rollback/initializer/free responses are ignored in
the injected contract. Saved last error is restored on every tested path.
Wrong setter/allocator/free cleanup models reject. Authored dependencies preserve
flags and optionally clobber ECX/EDX; pointer/locale memory remains unmapped.

These are request-order/ABI results, not real storage or allocation behavior.
PTD/storage/locale naming remains HYPOTHESIS. No actual8480FE/849A00/845CF9,
FLS/TLS/publication atomicity/ownership/destructors/SEH/races/reentry/native lift/
ARM64/startup/gameplay is modeled. Historical hook SIGBUS remains open. Before
heap integration, resolve831A7A error mapping (cache first, at most ONE query if
absent); provider composition still needs checked storage/allocation/init services.
Full828A9D/844495 and factory/+70 ordering remain unresolved.

## Existing-slot provider path — run3 iteration45

`tools/ptd_existing_probe.py` + seven authored tests check only the existing-value
path of84601E. Reproduce after bootstrap: `python3 tools/ptd_existing_probe.py
--index work/phase1-run3-045/provider.json`. ONE persistent query agrees with
pinned decode on67 boundaries/mnemonics/177 bytes, NOT operands/pseudocode.
384 original-body x86/oracle matches check all8 registers, full stack, ordered
calls, defined logic flags+DF and immutable non-stack pages. No runtime binding.

The path saves GetLastError, reads index104F89C, and (unless indexFFFFFFFF)
queries8480BF/stdcall4. A nonzero result bypasses allocation:FFFFFFFF becomes
zero, while every other nonzero value is returned unchanged. It restores the
saved last error through SetLastError/stdcall4, ignoring that provider's EAX.
Wrong query/set caller-cleanup models reject. Authored APIs preserve flags;
optional ECX/EDX clobbers are checked. Pointer pages remain unmapped.

Zero query result and indexFFFFFFFF take lazy-initialization paths explicitly
rejected by this harness, NOT treated as null returns. Thread-storage/PTD naming
remains HYPOTHESIS;8480BF and both APIs are injected. No real FLS/TLS, allocation,
ownership, destructor/SEH/races/reentry/native lift/ARM64/startup/gameplay proven.
Historical hook SIGBUS remains open. NEXT use this cached full177-byte provider
query for the slow-path sentinel/publication/rollback contract; no fresh query
needed. Error mapper831A7A and full828A9D/844495 remain unresolved.

## Error-slot accessor boundary — run3 iteration44

`tools/error_slot_probe.py` + seven authored tests check `831B17`, without a
production binding. Reproduce after bootstrap: `python3 tools/error_slot_probe.py
--index work/phase1-run3-044/accessor.json`. ONE persistent query agrees with
pinned independent decode on7 boundaries/mnemonics/19 bytes, NOT operands or
pseudocode. References60/callers40 capped. 160 original-body x86/oracle matches
check all8 registers, full stack, ordered event, defined flags+DF and non-stack
immutability. AF excluded after null TEST; included after nonnull ADD.

The no-argument cdecl accessor calls84601E once. If its injected return is zero,
EAX becomes address104F750; otherwise EAX is provider-result+10 modulo2^32.
Neither PTD nor fallback is dereferenced (both remain unmapped in the harness).
Nonnull FFFFFFF0 therefore returns zero, not the fallback; no overflow guard.
Provider ECX/EDX clobbers survive, nonvolatiles are preserved. Wrong provider
callee-pop4 rejects. The fixed-address return must not be mistaken for a load
of the slot contents or an unconditional current-thread offset.

PTD/errno naming remains HYPOTHESIS;84601E is injected, not real thread storage.
No actual provider/lifecycle/FLS/TLS destructor/heap ownership/error mapping,
SEH/races/reentry/native lift/ARM64/startup/gameplay is validated. Historical
hook SIGBUS stays open. NEXT84601E provider contract, cache first and at most
ONE query if absent;831A7A error mapping remains unresolved before heap binding.

## Downstream heap-release boundary — run3 iteration43

`tools/heap_release_probe.py` + seven authored tests check `8461B8`; no
production binding. Reproduce after bootstrap: `python3 tools/heap_release_probe.py
--index work/phase1-run3-043/index.json`. ONE persistent query matches pinned
independent decode on22 boundaries/mnemonics over58 bytes, NOT operands or
pseudocode. Reference/caller lists capped; not complete inventories. PE import
metadata identifies HeapFree at D9A1DC and GetLastError at D9A118.
480 original-body x86/oracle matches check all8 registers, full stack, ordered
calls, defined arithmetic flags+DF (AF excluded after TEST), and non-stack
immutability except exactly one authored errno slot. Null skips dependencies
and retains input EAX. Nonnull forwards the global10E0380 heap value, flags0,
and pointer to HeapFree/stdcall12; no static-PTD exemption or heap-zero guard.
Any nonzero API result succeeds and is retained, not normalized to boolean.
Failure calls GetLastError, then831A7A/cdecl(error), then831B17/cdecl(), and
stores the mapper result through the accessor return. Final EAX is that slot
pointer, NOT a failure boolean. ESI/nonvolatile state survives; injected volatile
clobbers survive except the caller POP overwrites ECX before the accessor.
Wrong HeapFree caller-pop and mapper callee-pop models reject.

HeapFree, GetLastError, mapper and accessor are authored providers: actual heap
ownership/error translation/PTD accessor semantics remain unimplemented. The
errno interpretation is HYPOTHESIS from this call/store pattern, not a recovered
symbol. No thread exit/FLS/TLS destructor, SEH/races/reentry/native lift/ARM64/
startup/gameplay evidence. Historical hook SIGBUS remains open. NEXT establish
831B17 slot-provider contract from cache (ONE query if absent) before any heap
adapter;831A7A mapping also unresolved. Do not treat EAX as a free success flag.

## Free-wrapper boundary — run3 iteration42

`tools/heap_free_probe.py` + seven authored tests check `831A54` without a
production binding. Reproduce after bootstrap: `python3 tools/heap_free_probe.py
--index work/phase1-run3-042/index.json`. ONE persistent query agrees with pinned
independent decode on11 boundaries/mnemonics/27 bytes, NOT operands/pseudocode.
Caller/reference inventories are truncated and are NOT complete call graphs.
448 original-body x86/oracle matches: all pointers (including null and the PTD
static exemption address) forwarded unchanged to8461B8 with EAX zero on entry.
Downstream and wrapper are cdecl. Full provider EAX survives; caller POP replaces
ECX with argument; authored EDX/defined-flags+DF clobbers survive. All8 registers,
full stack, ordered events and immutable non-stack pages checked. Context pages
are unmapped. Wrong downstream callee-pop4 rejects by ECX, even though LEAVE
repairs ESP and allows a normal return; an authored regression proves why an
ESP-only check is insufficient. The zero local is not a proven ownership field.

Provider effects are injected, not heap allocation/free or an OS implementation.
No actual ownership, allocator policy, FLS/thread exit, TLS fallback destructor,
SEH/reentry/races/native lift/ARM64/startup/gameplay established. Full lifecycle
remains HYPOTHESIS. Historical hook SIGBUS open. Next inspect cached8461B8
contract (at most one query if absent), not bind a guessed heap service.

## PTD destruction callback boundary — run3 iteration41

`tools/ptd_callback_probe.py` + six authored tests check `828AF0`, without a
production binding. Reproduce after bootstrap: `python3 tools/ptd_callback_probe.py
--index work/phase1-run3-041/index.json`. ONE persistent query agrees with pinned
independent decode on12 boundaries/mnemonics over28 bytes, NOT operands/pseudocode.
448 original-body x86/oracle cases: null and exactly static address `10DFB58`
skip free; adjacent/high-bit/FFFFFFFF contexts are forwarded unchanged to
`831A54` with cdecl caller cleanup. Callback itself uses callee-pop4. No context
page is mapped: this body does not dereference its argument, even on free path.
Provider EAX survives; caller POP replaces provider ECX with context; authored
EDX/flag clobbers survive. Skipped paths leave EAX=context, not a boolean result.
All8 registers/full stack/ordered events/non-stack immutability/defined flags+DF
checked (AF excluded only for null TEST; CMP AF checked). Wrong free-pop4 rejects.
Provider effects are authored, NOT allocator behavior. No actual allocation/free,
FLS invocation/thread exit, TLS fallback destructor, slot ownership, reentry,
SEH/races, native lift, ARM64 or composed startup. Lifecycle equivalence remains
**HYPOTHESIS**. Query CA-bundle ERROR and historical hook SIGBUS remain open.
Initial range26 truncated RET's operand and failed ESP comparison; corrected to28,
with full instruction-coverage rejection and authored truncated-RET regression.
NEXT reuse cached allocator `831A54` evidence to establish the callback's actual
free contract before any lifecycle adapter; at most one query if absent. Do not
infer that TLS fallback automatically invokes this callback at thread exit.

## PTD free selector boundary — run3 iteration40

`tools/ptd_free_probe.py` + seven authored tests check `82A338`, without a
production binding. ONE persistent query matches pinned independent decode on
21 boundaries/mnemonics over59 bytes, not operands/pseudocode. Reproduce after
bootstrap: `python3 tools/ptd_free_probe.py --index work/phase1-run3-040/index.json`.
256 original-body x86/oracle cases cover both resolution paths, full provider
EAX, boundary indexes and register salts. PE metadata confirms `FlsFree` request,
candidate IDs0/2 and `TlsFree` IAT at D9A2D0. Resolver numeric1/name/begin/end
uses cdecl caller cleanup. Dynamic path enters authored guard with ECX=target
before calling it; fallback CALLS imported TLS (not allocation's tail jump).
BOTH provider paths consume exactly one index with callee-pop4. Caller still
owns its input word; full provider EAX is returned, with no sentinel filtering.
Wrong resolver-pop16 and either provider-no-pop reject. All8 registers, full
stack, defined flags+DF, ordered events/arguments/return/ESP/ECX and non-stack
immutability checked. Providers preserve all except authored EAX; guard is
preservation-only. No actual lookup/free/callback/lifetime/slot/thread-exit,
provider clobbers, SEH/reentry/races, native lift, ARM64 or startup composition.
Lifecycle equivalence remains **HYPOTHESIS**; query CA-bundle ERROR and historical
hook SIGBUS remain unresolved. NEXT `828AF0` callback (reuse cache; at most one
query if absent), then lifecycle evidence before any service adapter.

## PTD cleanup boundary — run3 iteration39

`tools/ptd_cleanup_probe.py` and six authored tests check `828C16` without a
production binding. ONE persistent query agrees with pinned independent decode
on9 boundaries/mnemonics over27 bytes, not operands/pseudocode. Reproduce after
bootstrap: `python3 tools/ptd_cleanup_probe.py --index work/phase1-run3-039/index.json`.
384 original-body x86/oracle cases cover sentinel/live indexes, provider EAX,
register salts and injected slot interference. FFFFFFFF skips the dependency;
zero is valid. Live index is passed to `82A338` with cdecl caller cleanup. The
slot still contains the live index at call entry; AFTER normal return it becomes
FFFFFFFF regardless of provider result or injected slot change. AL becomes1,
not full EAX=1: upper bits come from provider (or sentinel on skipped path).
ECX receives the popped argument on the live path. Wrong callee-pop4 rejects.
All8 registers, full stack/data page, defined flags+DF, ordered event and immutable
code/return pages checked. AF excluded (OR path); providers preserve flags/state
except authored EAX and optional slot interference. No actual free/Windows/slot
lifetime, callback, provider clobbers, SEH/reentry/races, native lift, ARM64 or
startup composition demonstrated. Unconditional reset is a normal-return fact,
NOT proof that freeing succeeds. Lifecycle equivalence remains **HYPOTHESIS**.
Known query CA-bundle ERROR and historical hook SIGBUS remain. NEXT cached
`82A338` free selector (one query if absent), then `828AF0` callback before adapter.

## PTD set selector service boundary — run3 iteration38

`tools/ptd_set_probe.py` + seven authored tests check pending `82A3AE`.
ONE persistent query:22 boundaries/mnemonics over62 bytes agree with pinned
independent decode, not operands/pseudocode. PE metadata identifies requested
`FlsSetValue`, candidate IDs0/2, imported fallback `TlsSetValue` at D9A2CC.
Resolver receives numeric3/name/begin/end with cdecl caller cleanup. Nonzero
resolution enters the injected guard with ECX=target then calls target; zero
resolution CALLS the fallback (unlike allocation's tail jump). Both providers
receive exact index/value words and require callee-pop8. Original caller still
owns its two input words. Full EAX retained, including high-bit/FFFFFFFF.

512 original-body x86/oracle cases check all8 registers, full stack, defined
flags plus DF, ordered arguments/return words/ESP/ECX and non-stack page
immutability. Wrong resolver-pop16 and either provider-no-pop reject. Reproduce:
`python3 tools/ptd_set_probe.py --index work/phase1-run3-038/index.json` after
bootstrap; omit --index for cached-image-only execution. Providers preserve all
except authored EAX; guard preserves everything. No actual lookup/guard/OS
service, slot storage, callback/ownership/free/thread-exit behavior, provider
clobbers, SEH/reentry/races, native lift, ARM64 or startup composition proven.
PTD lifecycle equivalence remains **HYPOTHESIS**; no runtime binding added.
NEXT cleanup828C16 then callback828AF0 from cache/at most one query per iteration
before choosing any adapter. Standing query CA-bundle ERROR/hook SIGBUS remain.

## Allocation selector service boundary — run3 iteration37

`tools/ptd_alloc_probe.py` + seven authored tests resolve the pending `82A2FD`
selector without adding an OS service or dispatch binding. ONE persistent query;
22 indexed boundaries/mnemonics over59 bytes match pinned independent decoding
(not operands/pseudocode). Independent PE metadata identifies fallback IAT
`D9A2C4` as `TlsAlloc`; the resolver's requested export is `FlsAlloc`, with
candidate IDs0/2. The guard pointer at `D9A71C` initially targets `140FE0`.
These are static identities, not proof of live resolution or guard behavior.

64 original-body x86/oracle cases: cdecl resolver receives index0/name/begin/end;
nonzero target enters the guard with target in ECX, then calls that target with
one callback argument (callee pops4). Null target tail-jumps to imported TLS
allocation with NO callback argument and the ORIGINAL caller return word.
Both paths retain full unsigned EAX, including zero and FFFFFFFF; saved ESI/EBP
restored. Wrong resolver-pop16 and allocation-no-pop models reject. Full stack,
all8 registers, ordered call arguments/ECX/return/ESP and defined status flags
plus DF checked; mapped non-stack pages must remain unchanged. AF excluded after
TEST. Reproduce after bootstrap: `python3 tools/ptd_alloc_probe.py`, optionally
`--index work/phase1-run3-037/query.json` (private cached query).

Resolver and OS providers supply authored EAX; guard is a preservation-only
boundary. No actual lookup/guard/FlsAlloc/TlsAlloc, callback registration or
invocation, allocation ownership/free/thread-exit behavior, provider clobbers,
SEH/races/reentry, native lift, ARM64 or startup execution is validated. In
particular the fallback does not itself register a destructor callback. General
PTD lifecycle equivalence remains **HYPOTHESIS**, not a portable TLS contract.
Known query CA-bundle ERROR and historical hook SIGBUS remain open. NEXT inspect
cached `82A3AE` (at most one query if absent), then cleanup/callback lifetime,
before choosing a native adapter; do not bind a guessed FLS implementation.

## PTD initialization dependency boundary — run3 iteration36

`tools/ptd_init_probe.py` and six authored tests verify the pending `828BE3`
body (51 bytes). ONE persistent query,19 indexed boundaries/mnemonics agreeing
with pinned independent Capstone decoding; NOT an operand/pseudocode comparison.
Index library labels suggest PTD/FLS initialization, allocation and setting;
these names remain **HYPOTHESIS**, not actual OS-service identification.

128 original-body x86/oracle cases check all8 registers, defined status flags
plus DF (AF excluded after TEST/XOR), full stack/index-page state and ordered
arguments/return words/ESP plus index-word visibility at dependency entry.
`82A2FD` receives callback address828AF0. Its result is stored at104F5A0 BEFORE
checking against FFFFFFFF. Zero is valid. Non-sentinel result reaches82A3AE
with index and value address10DFB58; FULL EAX zero calls828C16 before returning
AL0; full nonzero returns AL1, preserving upper EAX. Sentinel returns FFFFFF00,
not zero. Both argument-taking helpers require cdecl caller cleanup; wrong
callee-pop4 rejects. Cleanup itself is an injected no-argument call, NOT its body.

Reproduce after bootstrap: `python3 tools/ptd_init_probe.py`, optionally
`--index work/phase1-run3-036/query.json`. Authored providers set EAX and preserve
other registers/flags, with no memory effects. Therefore failure leaves the
stored index unchanged ONLY under this fixture; actual cleanup may change it.
No real allocation/FLS/TLS, callback invocation, ownership, provider clobbers,
SEH/reentry/race, native lift, ARM64 or startup is validated. VALUE/callback
addresses are argument values, not dereferenced objects. No production binding
or success stub. Standing query CA-bundle ERROR/historical hook SIGBUS remain.
NEXT inspect cached82A2FD (one query if absent), identify real service/fallback
before adapter. Full828A9D/844495 and factory/+70 ordering remain unresolved.

## Cleanup import boundary — run3 iteration35

`tools/lock_cleanup_probe.py` rechecks pinned original `82A1E3` in a bounded,
hook-free development x86 runner. ONE persistent query agrees on all17 indexed
boundaries/mnemonics across47 bytes; this comparison does not claim operand or
pseudocode agreement. Independent PE imports identify slot `D9A160` as
`KERNEL32.dll!DeleteCriticalSection`. Three indexed callers include previously
pending `828A9D`, as well as `828A7E` and `82A1A7`; caller coverage is not a
complete reachability proof.

The body snapshots entry counter `10DFC28`, walks addresses in reverse stride24
from `10DFC10 + 24*(count-1)`, and decrements the shared counter AFTER each call.
An authored provider changing that shared word does NOT change local loop length.
Zero count bypasses the provider. Return writes AL1, not full EAX1; caller owns
arguments, and the injected provider must pop its single argument.80 cases match
all8 registers, complete stack/data pages, ordered argument/counter/return-word/
ESP events and defined CF/PF/ZF/SF/OF plus DF; IAT remains unchanged. Wrong
cdecl/no-pop rejects. Six public tests use authored fixtures, not game code.

Reproduce after bootstrap: `python3 tools/lock_cleanup_probe.py`, optionally
`--index work/phase1-run3-035/query82A1E3.json` using that cached private query.
Counts above1 and counter interference are synthetic arithmetic stress, NOT
proof of a multi-lock table (prior initialization only demonstrated one slot).
No actual DeleteCriticalSection, lock ownership, provider clobber contract,
callback/reentry/throw/SEH/race behavior, native lift, ARM64 or startup is tested.
No lock service, IAT/dispatch binding or success stub added. Known query
CA-bundle ERROR/historical hook SIGBUS remain. Next inspect pending `828BE3`
from cached evidence, with at most one targeted query if absent, before choosing
another runtime dependency. Full `828A9D`/`844495` semantics and factory/+70
ordering remain open.

## Checked two-candidate resolver policy — run3 iteration34

`guest_resolver.hpp/.cpp` provide `legacy_resolve_two`: caller-owned checked
function/module cache words, exactly two explicit candidate names and slots,
existing helper policy, and a separate fail-closed export provider. Zero is
unresolved; FFFFFFFF is unavailable. Cached functions bypass every candidate
read/service. Negative module entries skip; failed loads negative-cache and
advance; first usable module stops even on zero export. Full unsigned results
are retained. Cold layout overlap/wrap rejects (safety policy, not original SEH).
No globals or host library loading. Prior module writes/provider effects survive
exceptions; missing providers throw, never synthesize unavailable cache values.

This deliberately models ONLY the observed argument4 / indices1,2 value/cache
slice, not arbitrary resolver arguments, original name-table decoding, x86 ABI,
atomic XCHG, concurrent resolver races/loser FreeLibrary, recursive provider
reentry, module lifetime, real Windows services, TLS/error ownership or startup.
The caller must serialize and prevent providers mutating layout/cache memory.
No IAT or dispatch binding is installed. Safety guards are authored policy.

After bootstrap and `scripts/test-host.sh`, reproduce:

```sh
python3 tools/resolver_composed_probe.py --native build/host/ts2_guest_resolver_probe
```

720 native/oracle/pinned-composed-x86 result/cache/external-request matches plus
720 cache reentries. Native reentry uses unavailable services and invalid candidate
slots; x86 reentry separately unmaps dependency pages. Native transport verifies
input pages and cache-page bytes outside the three words unchanged. Synthetic
names/prefix and authored load/error/export responses are NOT OS modules. Native
unit tests additionally cover missing services, partial effects on throw,
unmapped/overlap/wrap safety, isolation, and sentinel-export behavior (the latter
is authored, not part of the 720 differential vectors). Two Python transport
controls reject malformed/extra/missing/wrong output and stderr/nonzero exit.
No native guest registers/flags/stack or ARM64 evidence. The then-pending
`82A1E3` cleanup boundary is checked in iteration35 above; it is not a parent
resolver or a demonstrated callback. Do not requery these three settled bodies.

## Resolver/helper/comparator reference composition — run3 iteration33

`python3 tools/resolver_composed_probe.py` executes pinned original resolver
82A212, helper82A2B2 and comparator845B53 together, with synthetic two-module
names and prefix, authored load/error/export responses, no hooks, and a bounded
single-step budget. 720 cases plus720 same-memory cache reentries match the
independent value/event oracle; selected-module path counts240/195/285 (none).
Failure of a load/retry advances; failure of export stops and negative-caches.
Unit8-only differences do not trigger retry. High unsigned handles/export values
remain full-width. Reentry unmaps names/table/IAT/candidate array and forbids all
dependency calls, proving positive/negative cache bypass in this fixture.

The shared runner checks exact ordered calls/arguments/return RVAs/ESP, final
EAX/ESP, module/cache page, callee-saved registers, input/IAT pages and caller
words. Public authored controls reject helper register/stack/input/IAT mutation,
looping and missing cache bypass without needing the private image. Neither
native resolver nor real OS/module ownership/FreeLibrary/concurrency/SEH,
full stack/flags/volatile registers, original name contents, ARM64 or startup is
validated. No runtime cache, IAT, dispatch or module-provider binding is added.
Next: checked caller-owned resolver state composed with the existing helper
policy and explicit export provider, retaining fail-closed missing services.

## Explicit comparator/service composition — run3 iteration32

`CheckedGuestLoaderServices` opts into `guest_wide_compare` with a non-owning
reference to one explicit `GuestMemory`; its final comparison method cannot be
replaced by authored return values. Memory must outlive the adapter. Load/error
still throw unless implemented by a caller-owned derived service. It maps no
fixed operand, loads no module, owns no handle, and performs no IAT/dispatch
binding. Missing comparison memory propagates a C++ safety exception, with prior
provider effects retained and no fallback call; NOT modeled guest SEH.

`tests/guest_loader_composed_tests.cpp` checks bypass paths with unmapped operands,
comparison-failure stop, two-memory isolation, equal/nonzero comparison outcomes
and unavailable service defaults. `tools/guest_loader_composed_probe.cpp` plus
`tools/loader_composed_probe.py` compare native result/ordered external requests
against a declarative oracle and original helper82A2B2 executing actual845B53.
Reproduce after bootstrap and host build:

```sh
python3 tools/loader_composed_probe.py --native build/host/ts2_guest_loader_composed_probe
```

The fixed comparison-operand VA contains **authored** units, not original text;
load/error responses remain authored. Vectors distinguish seventh-unit mismatch
from differences beyond the seven-unit bound and include NUL/case/high-unit,
unmapped bypass and retry-failure cases. The x86 side separately checks ordered
call arguments/return words/ESP, callee-saved registers, unchanged IAT/input pages
and caller words; the native side has no x86 ABI/register/flags contract. Tests
reject authored wrong results, cleanup, saved-register and input-write mutations,
and malformed/partial/nonzero/stderr native transports. No flags/full stack,
actual OS modules/error ownership, exceptions, concurrency, ARM64 or startup
validation. Next: compose resolver82A212 with this helper/comparator in a bounded
reference fixture before runtime cache/provider integration; no more queries of
these established bodies. Known hook SIGBUS/CA-bundle ERROR remain unresolved.

## Checked wide-unit comparator — run3 iteration31

`GuestMemory::read16` validates the complete two-byte range before reading
little-endian data (including unaligned/high addresses). `guest_wide_compare`
in `guest_loader_policy.hpp/.cpp` consumes raw unsigned 16-bit units and returns
exact subtraction modulo 2^32. It reads no pointers at count zero and stops on
mismatch, equal NUL or count. It does not prevalidate an unused suffix. Wide
address arithmetic and checked reads reject wrap/uncommitted spans, rather than
wrapping into a committed low address. Read failures throw C++ exceptions, NOT
Windows access violations/guest SEH; inputs must not be concurrently mutated.
The guest-library label remains HYPOTHESIS; no host wchar_t/locale APIs are used.

Authored `tests/guest_wide_compare_tests.cpp` checks read16 endian/unaligned and
null/guard/overflow rejection, UINT32_MAX counts with immediate termination,
no suffix read, exact non-normalized difference, exact bounds and address-space
end. `tools/guest_wide_compare_probe.cpp` accepts bounded authored unit vectors,
places them at high addresses next to guards, and checks entire input pages
unchanged. Optional differential command (after worker bootstrap/build):

```sh
python3 tools/wide_compare_probe.py --native build/host/ts2_guest_wide_compare_probe
```

This compares native results with the independent oracle on the same 906 vectors
whose pinned original x86 results are checked in that invocation. Transport tests
reject malformed/extra/missing/wrong results and stderr/nonzero exits. Limits:
count0..32 differential; no original strings exposed, native register/flags/stack
ABI adapter, provider/dispatch/IAT binding, module services, helper composition,
ARM64/Android or startup validation. Native pointer failures are safety policy,
not independently validated original exception behavior. Next compose the checked
comparator with the policy using explicit load/error providers and compare the
composed helper against x86 before proposing any production binding.

## Comparator reference, not yet a provider — run3 iteration30

`python3 tools/wide_compare_probe.py` (after worker bootstrap) compares906
bounded cases from pinned private845B53 against an unsigned16-unit oracle.
Exact EAX is first-unit difference modulo2^32, stopping at mismatch/equal NUL
or count units; count0 performs no input read. Case-sensitive, not sign-only,
not signed16, not host wchar_t. Six authored runner/oracle tests need no game
input. One persistent query and independent boundaries agree27instructions/
58bytes; library-name attribution remains HYPOTHESIS.

Checks cover exact-bound guard-ended spans, unaligned/high-address inputs,
callee-saved registers/returnESP/caller words and no input writes. No full stack,
flags/volatile state, native/ARM64, invalid-pointer exception semantics or
composed startup evidence. `GuestLoaderServices.compare` still requires an
explicit caller provider; none is installed automatically. Next implement a
checked guest-memory uint16 comparator and compare it to this reference before
policy composition. Original prefix identity/OS meaning remain HYPOTHESIS.

## Portable loader-policy boundary — run3 iteration29

`guest_loader_policy.hpp/.cpp` implement the settled `82A2B2` decision policy
with an explicit caller-owned `GuestLoaderServices&`. Every name, comparator
operand, handle and result is `uint32_t`, never a host pointer. Default service
methods throw operation-specific unavailable errors; a provider's explicit zero
is a real response, not a missing-service substitute. Exceptions propagate with
no retry and no rollback of prior provider effects. No global provider exists.

The policy issues load(name,0,0x800), returns any nonzero word unchanged, otherwise
queries error. Only87 invokes compare(name,base+E06E20,7); zero returns0 and
nonzero permits exactly one load(name,0,0), returning its full word including0.
The comparator remains provider-owned; string/case/locale semantics and helper
OS role are **HYPOTHESIS**, not implemented by assuming a host string function.

`tests/guest_loader_policy_tests.cpp` checks 768 authored combinations including
four name words, exact ordered arguments and failure at each reached dependency,
plus missing load/error/comparator defaults. `tools/guest_loader_policy_probe.cpp`
is a bounded host transport for the *same library implementation*. After
`scripts/test-host.sh`, reproduce the independent private-image comparison:

```sh
python3 tools/loader_policy_probe.py --native build/host/ts2_guest_loader_policy_probe
```

384 x86/oracle/native-policy cases compare result and ordered dependency args.
The x86-only checks still cover call return RVAs/ESP, final ESP/callee-saved,
IAT and caller words; the portable policy does NOT implement these ABI effects.
`tests/test_loader_policy_native.py` tests transport rejection, not original code.

Still NOT modelled: original comparator, actual Win32 load/error behavior, name
validation/decoding, module ownership/unloading, thread-local error, exceptions
as guest SEH, concurrency, resolver/helper composition, x86 register/flags/stack
adapter, automatic IAT/dispatch registration, ARM64 or original game startup.
This adds no host library loading, success stub, renderer or Android integration.
Next establish comparator845B53 semantics before supplying a real comparison
provider; then test composition with the resolver rather than new leaf counts.
All existing startup/resource-order and external Android validation gates remain.

## Resolver load-helper policy — run3 iteration28

`python3 tools/loader_policy_probe.py` reuses cached `82A2B2` evidence and the
same fixed ignored image/full SHA pin as the resolver probe. No new Ghidra query
or original bytes in Git/output. Development-only bounded x86 comparison passes
384 cases, path counts288/72/8/16 (initial success / other error / comparison
zero / retry). First LoadLibraryExW request passes name,0,0x800. Nonzero return
is retained without querying error. On zero, GetLastError is consulted; only87
reaches the three-argument comparator at845B53 (name,prefixRvaE06E20,7).
A zero comparison returns0 without retry; nonzero retries with name,0,0 once,
retaining the complete returned pointer or0. This is not unconditional fallback.
Comparator string/case/locale semantics and helper OS role remain **HYPOTHESIS**.

Eight authored tests in `tests/test_loader_policy_probe.py` need no game image.
They cover policy boundaries, pointer retention, failure0 versus sentinel, authored
x86 return/API stdcall/comparator cdecl cleanup, sanitized pin failure, and
register/stack/IAT/caller-argument/budget mutations. The separate private-image
command compares ordered calls/args/return RVAs/call ESP, EAX/final ESP,
callee-saved registers, entire IAT page and caller return/argument words.
API/comparator outputs and cleanup are AUTHORED; neither Windows services nor
the original comparator execute. No full stack/flags/volatile comparison,
exceptions, native/ARM64, resolver composition, production binding or startup.
Known CA-bundle ERROR and old hook SIGBUS remain unresolved. Next useful increment
is a fail-closed portable policy boundary with explicit providers and native/x86
comparison, not more dependency counts or another query of these settled bodies.

## Reproducible resolver probe — run3 iteration27

`python3 tools/resolver_probe.py` now reproduces iteration26's settled finding
without its private Python script chain. It opens only the existing ignored image,
verifies the complete pinned SHA-256 and PE32/base, then executes only the bounded
160-byte resolver in development-only Unicorn. No original bytes are embedded in
Git or emitted. The persistent Ghidra index/cache is unchanged; no new query.

288 cases and 288 same-memory cache reentries pass (144 first module, 72 second,
72 unavailable). Comparison covers ordered calls/arguments/return RVAs/call ESP,
EAX, final ESP, callee-saved registers and the full cache page. Dependency pages
are unmapped for reentry. Providers are authored return streams/cleanup, not OS
services; unexpected calls (including FreeLibrary) or instruction-budget overflow
fail. Seven authored tests in `tests/test_resolver_probe.py` run without game
inputs: wrong search/cache/pointer models reject, as do synthetic x86 register,
stack, adjacent-memory and loop mutations. These are harness tests, not native
mutations of the original resolver. Missing/mismatched image fails, never skips.

No full stack/flags/volatile register comparison, concurrency/races, real helper,
native lift, ARM64 or startup execution is established. The runner deliberately
is not integrated into the APK or production dispatch. Next dependency remains
cached helper82A2B2's flags/error/retry policy; its OS role is HYPOTHESIS.

## Resolver candidate selection — run3 iteration26

Cached `82A212` reused (no repeat query). The function and module caches are
separate: argument4 uses function slot `10DFC84`; module indices1/2 use
`10DFC6C`/`10DFC70`. A negative module sentinel skips that candidate. A zero
module slot invokes helper `82A2B2` with its table-supplied wide-name pointer;
a zero helper result becomes a negative module cache entry. Only failure to
obtain a usable module advances to the next candidate. **Export failure does
not advance**: the first usable module is passed to GetProcAddress, and a zero
export result becomes a negative function cache entry immediately. Do not
implement this as an export search across every module.

Private hook-free x86 checks pass288 cases (144 first-module,72 second-module,
72 no-usable-module), plus288 same-memory function-cache reentries with candidate,
name-table and IAT pages unmapped. Ordered calls, exact arguments, return words,
call-entry ESP, EAX, callee-saved GPRs, final ESP and entire cache page match an
independent selection/cache oracle. Candidate storage is authored with actual
indices1/2; helper/API outputs and cdecl/plain-return versus stdcall/pop8 effects
are AUTHORED, not OS behavior. No full stack/flags/final volatile-state comparison,
original helper execution, validated race/FreeLibrary path, concurrency, native
lift, ARM64, parent/startup composition or production binding.

ONE new persistent query `82A2B2` agrees with independently decoded27 instructions/
75bytes/operands; listed sections untruncated. PE independently identifies its
LoadLibraryExW calls at `82A2BF`/`82A2F1` (IAT `D9A2D4`) and GetLastError at
`82A2C9` (IAT `D9A118`). Imported helper name/system-directory purpose remains
**HYPOTHESIS**. Its flags, error-dependent retry and comparison-helper contract
are NOT yet validated: reuse this cached query next, not another query. Known
CA-bundle ERROR and earlier hook SIGBUS remain open. No runtime service added.

## Resolver cache boundary — run3 iteration25

ONE persistent query `82A212` agrees with independent pinned decoding of67
instructions/160bytes/operands; listed sections untruncated. Automatic function
name/CRT role remains **HYPOTHESIS**. PE metadata independently identifies
`D9A120`/`D9A124` as FreeLibrary/GetProcAddress. The lock adapter's candidate
range `E06E7C..E06E84` contains indices1,2; the referenced UTF-16 name table
contains `api-ms-win-core-synch-l1-2-0`, then `kernel32`. These are static request
inputs, not evidence that either library loads or exports the requested function.

For the observed numeric argument4, function-cache slot is `10DFC84`. A nonzero
cached word other thanFFFFFFFF returns the entire pointer unchanged. FFFFFFFF
returns0 without consulting name/candidate range. With zero cache and an empty
range, the body storesFFFFFFFF using XCHG and returns0; later calls bypass the
range. Thus "not attempted" and "failed resolution" cannot share a zero-cache
model. This does NOT prove a thread-safe loader/cache or permission to seed a
production cache with pointers or failures.

Private hook-free x86 checks pass256 cases:192 positive hits,32 negative hits,
32 empty-range misses;32 additional same-memory negative-cache reentries pass.
Compare EAX, callee-saved GPRs, final ESP and entire cache data page. Cached hits
use unmapped name/nonempty candidate ranges; reentries likewise prove bypass.
No dependency calls execute. No full stack, flags, final volatile registers,
nonempty resolution, API/module-helper effects, exceptions, concurrency, native
lift, ARM64 or parent startup comparison. Three alternative oracle models differ
in160/32/32 cases; these are NOT compiled negative controls. No runtime binding.

Failed private helper attempts: guessed extent, missing capstone import, then
signed-displacement/alias textual differences. Final comparison normalizes only
those representations modulo32 bits and retains exact boundaries/operands. The
initial hash-failure triage was mistaken: the pinned hash passed; the extent
assertion failed. Known query CA-bundle ERROR and old hook SIGBUS remain open.
Next reuse cached resolver evidence for nonempty candidate/API paths before a
bridge; next unresolved load helper is `82A2B2`. Do not repeat `82A212` query.
Other startup dependencies and factory/resource +70 order remain unresolved.

## Lock API adapter boundary — run3 iteration24

ONE persistent query `82A3EC` matches independent pinned decoding of all25
instructions/71bytes/operands; listed sections untruncated. CRT function naming
and the purpose of indirect slot `D9A71C` remain **HYPOTHESIS**. Independent PE
import metadata identifies fallback IAT `D9A2C0` as
`KERNEL32.dll!InitializeCriticalSectionAndSpinCount`; the resolver argument at
`E06E84` contains the name `InitializeCriticalSectionEx`. This establishes an
API dependency, not actual resolution or OS behavior.

Call `82A401` invokes `82A212` with four arguments (numeric4, name, begin/end
addresses); caller releases16 bytes. Nonzero full EAX selects the resolved path:
`82A41A` invokes slot `D9A71C` with ECX holding the resolved pointer, then
`82A420` calls that pointer with object/spin/flags. Zero selects the fallback
at `82A42A` with object/spin ONLY, even for nonzero flags. This adapter itself
does not reject those flags. It returns full API EAX unchanged and plain RET;
caller owns its12 input bytes. Resolver/slot/API semantics remain unimplemented.

Private hook-free x86 tests pass256 authored cases,128 per path, including96
fallback cases with nonzero flags. Exact arguments, ordered calls, return words,
immediate/final ESP, all8 GPRs, entire stack/IAT pages and defined status flags
exceptAF plus DF match independent oracles. Resolver uses authored cdecl return;
slot preserves state; APIs use authored stdcall pop12/pop8. These are test
assumptions, not demonstrated actual callee contracts. Initial flag oracle
omitted SF for a high-bit resolved pointer; corrected without changing bytes or
existing tests. No original dependency/native lift/ARM64/real locks, exceptions,
concurrency, allocation, resolver failure semantics or composed startup proven.
No dispatch/IAT/service binding. Known query CA-bundle ERROR and prior hook
SIGBUS remain. Next ONE query `82A212` with explicit private output, to establish
resolver/cache behavior before choosing any runtime bridge. Other startup and
resource +70 ordering questions remain open; mount order unchanged.

## First lock-initializer candidate — run3 iteration23

ONE persistent query `82A1A7` agrees with pinned independent decoding on all
23 instructions/60 bytes and operands; listed sections are untruncated. Library
labels for this body and its callees suggest CRT lock initialization, but remain
**HYPOTHESIS**. The body supplies object RVA `10DFC10`, numeric argument4000
and flags0 to `82A3EC` at `82A1B8`, then releases 12 argument bytes. It tests
**full EAX**, unlike its parent's AL-only gate. Nonzero increments the word at
`10DFC28` modulo2^32 and returns AL1. Zero calls `82A1E3`, then returns AL0.
The apparent stride24 loop executes once if the helper preserves ESI: ESI starts
at0 and becomes24 before comparison against24. No multi-lock initialization is
established. Upper24 EAX are retained, contrary to a literal reading of the
indexed pseudocode's full-width return0/1.

Private hook-free x86 checks pass512 authored return/counter/register cases:
448 success,64 failure. They compare ordered calls, exact three arguments,
immediate return words/ESP, eight GPRs, full stack/global pages and defined
status flags except AF plus preserved DF. Counter wraparound is covered. All23
operand substitutions reject. Low-byte gate, overwrite-counter and omitted
failure-call alternatives differ in192/336/64 cases; these are oracle-model
sensitivity checks, not compiled native negative controls.

Original callees do NOT execute: injected EAX returns preserve other registers,
flags and memory and use authored plain-return cleanup. Thus no actual critical
section layout, synchronization, allocation/failure/cleanup effects, Windows ABI,
threading, exceptions, native lift, ARM64 or parent startup composition is proven.
No service or dispatch binding added. Query CA-bundle ERROR/prior hook SIGBUS
remain open. Next ONE query `82A3EC` with explicit private output, then independent
instruction validation to identify the actual OS dependency before implementation.
`82A1E3`/`828BE3`, parent `844495`/`828A9D` and resource +70 order stay unresolved.

## Next startup initialization gate — run3 iteration22

One persistent query at `828A7E` matches an independent pinned decode of all
12 instructions/31 bytes and operands. Library label `___vcrt_initialize` is
HYPOTHESIS, not validated CRT semantics. The body calls `82A1A7` first and tests
**AL**, not full EAX. Only nonzero AL reaches `828BE3`. Its nonzero AL yields
AL=1; zero AL calls `82A1E3` before returning AL=0. A zero first result returns
AL=0 without either later call. HYPOTHESIS: the third call undoes the first;
no ownership, allocation, cleanup or failure semantics are established.

Private hook-free x86 checks cover 1024 authored callee-return combinations and
initial register states: ordered call targets/return words, immediate and final
ESP, all eight GPRs, complete stack page and defined CF/PF/ZF/SF/OF (not AF).
Plain RET consumes only the guest return word. EAX upper24 remain from the last
injected callee: neither a full-EAX BOOL gate nor zero-extended BOOL result is
valid for this body. Twelve operand substitutions reject; wrong full-EAX gate,
zero-extended result and missing third-call models are distinguished.

This executes ONLY the short original body with authored callee return injections,
not any original dependency, native lift, CRT service, exception/failure effect,
ARM64 or composed startup. No production binding/profile or OS service added.
Known query CA-bundle ERROR and earlier hook SIGBUS remain unresolved. Next ONE
query `82A1A7` with explicit private output, then independent validation of its
actual dependency before runtime implementation. `828BE3`/`82A1E3`, parent
`844495`/`828A9D` and resource attachment order remain unresolved.

## Private native CPU-init adapter — run3 iteration21

The private pinned adapter in `work/phase1-run3-021/adapt.py` routes only the six
independently decoded CPU instruction sites in 824F84 through explicit
`GuestCpu` calls. All other instructions retain the pinned lifter's unsupported
emission rejection. The sole PE-resolved processor-feature import has an authored
stdcall provider, with argument/return-word and immediate return-ESP checks.
No host CPUID/ARM64 detection, production profile or game binding is introduced.
The generated module compiles separately from the case driver; integer state,
checked narrow stack/data memory, CPU policy and request log are explicit inputs.

Comparison is deliberately bounded to the iteration19 unknown-vendor/model-zero
envelope: authored CPU/import outputs, initially-zero data pages, request
order/site/leaf/subleaf, EAX, callee-saved registers and final ESP. It does NOT
compare full stack, flags, final volatile registers, real CPU instruction effects,
Win32 service semantics, exception behavior, concurrency, ARM64 or game startup.
A candidate SSE2-only profile remains HYPOTHESIS, not a selected runtime policy.
Private result and negative-control manifests, test outcomes and reproduction
commands are recorded in the task-local PHASE1_REPORT.md. Native agreement in
this envelope does not establish that the lifter implements the advertised ISA.

Next resolve the parent's next unconditional dependency 828A7E using at most one
persistent query and independent instruction checks; do not register this isolated
CPU initializer as proof of composed startup. 844495/828A9D and resource attachment
ordering remain unresolved.

## Explicit guest CPU response boundary — run3 iteration20

`guest_cpu.hpp` / `guest_cpu.cpp` add `GuestCpu`, constructed from explicit
CPUID `(leaf, subleaf) -> EAX/EBX/ECX/EDX` and XCR `index -> uint64` responses.
Const methods take the caller's `GuestRegisters`; callers own/pass the policy
per context, with no global current CPU or host CPUID/ARM64 feature detection.
There is deliberately **no default game profile**. Empty configuration rejects
all requests. Duplicate keys reject construction, including identical repeats.

- CPUID consumes unsigned EAX/ECX and assigns all four output GPRs, including
  explicit zero responses. No max-leaf, subleaf-zero or nearest-key fallback.
- XGETBV consumes only ECX, writes EAX=low32/EDX=high32, preserves ECX/EBX.
- Both preserve ESP/EBP/ESI/EDI and opaque EFLAGS. A missing request throws
  `std::out_of_range` with its unsigned hexadecimal key **before any register
  mutation**. This is a stop/diagnostic contract, not guest #UD/#GP delivery.
- The table does not validate feature consistency or implement the advertised
  ISA. Inventing a response does not establish a safe runtime capability policy.
  In particular an explicit zero is not an automatic unsupported-leaf response.

`tests/guest_cpu_tests.cpp` exercises 128 varying register/flag states, two
interleaved configurations, high-bit leaf/subleaf/output words, zero outputs,
64-bit XCR splitting, exact missing-key diagnostics, unchanged rejected state,
empty configuration and duplicate rejection. These are authored contract tests,
NOT an independent original-game or physical CPU differential. Reproduce with
`build/host/ts2_guest_cpu_tests` after `scripts/test-host.sh`.

Still **not modelled**: instruction availability/privilege/exception semantics,
CPUID serialization, scheduling, XSETBV, mutable XCR state, Win32 processor
feature queries, SIMD/x87 state, complete thread context or lifter integration.
The pinned non-MSVC CPUID macro and unsupported XGETBV remain unsafe/unbound;
this boundary alone does not replace either in generated code. No dispatcher
signature change, automatic IAT binding or original function registration.
Next: a pinned, private native CPU-init adapter must reject every unsupported
instruction and explicitly route verified CPU sites here before comparison with
the saved x86 request/global-page oracle. Never allow a dead advanced path to
justify a silently unsupported emitted instruction.

## Guest-CPU request envelope — run3 iteration19

Cached824F84 reused, zero new queries.1536 hook-free x86 cases match an
independent declarative oracle in an unknown-vendor/model-zero envelope. CPU
instructions are NOT executed: single-step original non-CPU instructions,
intercept exact CPUID/XGETBV boundaries and inject authored output registers.
Import BOOL0/1/high-bit; maxleaf0/1/6/7; all ECX20/27/28 combinations; leaf7
EBX5/9; XCR0=0/2/4/6. Check CPU request sites/order/leaf/subleaf, complete
initially-zero final data pages, EAX0, callee-saved GPRs and return ESP. No full
stack/flags/volatile-state comparison, native/ARM64/service/startup validation.

New exclusions: leaf1 requested even with maxleaf0. ECX20 AND27 AND28 gate
XGETBV in this envelope; XCR0 bits1/2 both required beyond level2. Candidate
SSE2-only profile (PF10 true/maxleaf1/unknown vendor+model0/EDX25+26/ECX0)
avoids XGETBV, leaves10DF81C=1/104F518=3. PF false leaves0/1; both return0.
Thus EAX cannot adjudicate capability policy. HYPOTHESIS conservative guest-x86
envelope only, NOT evidence of lifter ISA coverage or safety for the full game.
Three differing profiles distinguished; forbidden XGETBV request rejects.
Initial pre-XGETBV EAX oracle mistake corrected to ECX-only input, log retained.

Pinned upstream check with authored instruction fixtures adds a critical native
exclusion: CPUID emits its macro, whose non-MSVC branch performs no register
writes; XGETBV is unsupported and the unchanged private lift guard rejects it.
Thus a naïve Linux/ARM64 lift cannot inherit even this bounded x86 result.
Private `python3 work/phase1-run3-019/check_profile.py` and `check_lifter.py`
in the same directory after bootstrap; lifter check0 (source/emission, not a
compiled CPU execution test). No upstream changes or guard bypass.
No production CPU provider/binding or new modeled service, no host ARM64 feature
copy. Next require explicit fail-closed per-context CPU providers and reject
unsupported lifted instructions before private native comparison; never treat
unexecuted advanced paths as permission for silent no-ops. Parent828A7E/844495/
828A9D unresolved. All P0/P1 open; host7/7+60 passes, Android/acceptance blocked.

## Processor-feature boundary — run3 iteration18

ONE persistent query824F84; independent pinned decoding matches100 indexed
boundaries (instruction list truncated),11 operand contracts/11 substitutions.
Known CA-bundle ERROR remains. Independent PE import lookup confirms824F9A
calls KERNEL32!IsProcessorFeaturePresent via IATD9A2A0, argument10. The return
is tested as full EAX, not AL. Before the call,10DF81C is cleared and bit0 ORed
into104F518, retaining other bits. Zero result returns0 via8252AD/LEAVE/plain
RET; nonzero reaches CPUID824FB3 with EAX/ECX0. XGETBV825160 also decoded.
HYPOTHESIS: guest-x86 ISA initialization; not validated native feature policy.

72 hook-free x86 cases use ONE authored stdcall import return/argument-record
injection, not a service implementation.24 false cases compare eight GPRs,
defined status flags excluding AF/full stack/two global words;48 nonzero cases
stop BEFORE CPUID, check input registers/ESP/argument/words. No original import,
CPU instruction, whole-function/global-page/native/ARM64/startup proof, runtime
binding or success stub. Import identity does not make return0 semantically safe.
Reproduce private `python3 work/phase1-run3-018/check_target.py` after bootstrap.

Next reuse cached query and pinned full decode, no repeat query: explicit
conservative guest-x86 feature profile plus CPUID/XGETBV guard/reachability tests
before binding. Host ARM64 capabilities must not be copied into x86 feature bits.
Parent828A7E/844495/828A9D unresolved. Prior hook SIGBUS remains; no production
ABI change or new modeled service. Host7/7+60 passes; Android/acceptance blocked.

## Next unresolved initialization dependency — run3 iteration17

ONE persistent query824AF8 plus independent pinned decoding matches22 indexed
boundaries/57 bytes;14 operand contracts/14 mutations checked. CRT symbol name
is HYPOTHESIS, not validated service semantics. Real caller pushes1 at824733;
CALL824735 returns82473A. Argument-zero branch writes byte10DF7F0, skipped for
this actual nonzero argument.824B08→824F84 precedes824B0D→828A7E. Subsequent
AL-only gates select824B1A→844495 and, on its failure,824B25→828A9D with0,
followed by caller popECX. Plain RET does not remove caller argument.

108 hook-free x86 cases check ONLY this original body with FOUR authored
return/effect injections, NOT original dependencies. Order/count, AL, ESP/EBP,
argument/return words and global byte/neighbor match an independent oracle.
No native lift/registration, real CRT service, full flags/register/page state,
exceptions, initializer/prologue composition, ARM64 or startup validation added.
Reproduce private `python3 work/phase1-run3-017/check_target.py` after bootstrap.
Known query CA-bundle ERROR and prior hook SIGBUS remain. Next ONE query824F84,
earliest unconditional unresolved dependency; no production success stubs.

## Private native normal-frame adapter — run 3 iteration 16

The pinned 825BB0 prologue now compiles separately with explicit GuestRegisters,
GuestMemory and GuestFs arguments; stack/cookie words retain narrow checked
spans. An authored entry adapter supplies the two pinned pushes/CALL return;
helper RET reads its real guest stack return word into output EIP. This is not
a new dispatcher ABI or production handler. Cached index reused, zero queries.

128 native Linux x86_64 cases match fresh hook-free x86/independent frame oracle
and the saved states: eight GPRs, defined flags (AF excluded), EIP, complete
stack/FS pages; native cookie data page unchanged. Four wrong driver models
(FS base/plain return/scope/cookie) produce field-specific differences, and two
invalid-memory cases reject. The initial braced-proxy/macro syntax failure is
retained privately; fixed by parentheses without changing upstream or fixtures.

Normal frame setup is now a compiled bounded dependency, NOT Windows SEH.
HYPOTHESIS compiler frame role; exception dispatch, handler/unwind, full TEB/TLS,
concurrency, initializer composition, ARM64 and startup remain unvalidated.
No binding or success stub; errors are nontransactional. Prior hook SIGBUS and
known query CA-bundle ERROR remain. Reproduce after bootstrap with
`python3 work/phase1-run3-016/adapt.py` (owner-only ignored fixture). Next inspect
824AF8, target of unsupported CALL824735, before advancing beyond push824733.

## Entry-connected frame boundary — run 3 iteration 15

The continuation at RVA824727 first calls indexed __SEH_prolog4 at825BB0.
One persistent query plus independent pinned operand/boundary checks identify
this dependency, not an automatically registered handler. Private hook-free x86
execution of two pushes/CALL/helper RET matches an independent frame oracle in
128 cases: eight GPRs, defined flags (AF excluded), EIP, complete stack/FS pages
and unchanged cookie page, zero/GDT sentinels. Nine comparator mutations reject.

Relative to continuation-entry ESP, normal helper return leaves ESP minus56,
EBP minus4 and FS head minus20. Stack contains encoded scope/frame-cookie state,
a saved bottom ESP and try-level -2. A plain return restoring entry ESP/EBP or
ignoring FS is therefore not sufficient. HYPOTHESIS: compiler SEH frame; this is
NOT exception dispatch/unwind or handler validation. The existing GuestFs data
boundary does not supply those semantics. No production handler/native adapter,
concurrency, ARM64 or startup validation. Known query CA-bundle ERROR, truncated
reference/caller inventories and earlier hook SIGBUS retained. Next private
native prologue comparison must retain full saved states before binding; next
unsupported call at824735 targets824AF8. See task report / private work/phase1-run3-015/.

## Contract

- `bind(va, function)` accepts a nonzero guest VA and a non-null authored/native
  function pointer. Duplicate VAs throw rather than silently replacing a handler.
  Populate the registry before use; concurrent binding/execution is unsupported.
- `invoke(va, registers, memory)` calls exactly that registered handler. No range,
  nearest-address, RVA fallback, or guest-code execution is permitted. An unknown
  target throws `UnresolvedGuestCall` with the complete unsigned target and a
  hexadecimal diagnostic, before touching call state or guest memory.
- `GuestRegisters` contains eight 32-bit GPRs and an opaque 32-bit EFLAGS value.
  There is no implicit push/pop, return-address processing, flag masking, argument
  conversion or cdecl/stdcall/thiscall cleanup. Each future adapter must implement
  and independently validate its own ABI effects.
- Handlers receive the same checked `GuestMemory` and const dispatcher, allowing
  nested callbacks without global current-register/current-memory pointers.
  Guest vtable entries remain guest data read with `read32`, never host vtables.
- Memory and handler errors propagate; failure is not converted into a successful
  guest result. Calls are **not transactional**: changes made by a handler before
  it throws remain visible. The runtime must stop and diagnose unsupported calls,
  not catch the error and continue as though a guest service succeeded.

This is not a complete thread context: EIP, x87/SSE, FS/TEB/TLS, SEH, guest
exceptions, scheduling and lifetimes are absent from dispatch. The separate
`GuestFs` data-access boundary below is not a complete FS/thread model.
Dispatch neither makes allocated data
executable nor automatically registers anything from a PE or Ghidra project.
`load_guest_image()` now provides a separate checked PE32 data mapping boundary
(see `GUEST_IMAGE.md`), not an entry invocation or dispatch binding. Imports/IAT,
relocations, TLS callbacks, stack/return ABI and original startup remain unmodelled.
The entry-connected dependency at RVA 8258A9 is now a private bounded x86
cookie/complement reference (run 3 iteration 11), not a registered handler.
Its helper at 82585C calls PE-resolved GetSystemTimeAsFileTime,
GetCurrentThreadId, GetCurrentProcessId and QueryPerformanceCounter; none has a
production guest ABI/service here. Injected helper results in a reference fixture
do not implement those APIs or validate original startup. See the task report.

Run 3 iteration 12 privately checks the helper with **256/256** bounded Unicorn
cases against an independent data-flow/frame oracle. Real indirect CALLs execute
through a synthetic IAT; four authored API handlers inject outputs and emulate
stdcall returns (they are not Windows implementations). Comparison covers EAX,
callee-saved GPRs, return ESP, complete tracked stack page and API argument/return
locations/order. Four wrong source/address models reject. The result depends on
both halves of FILETIME and performance-counter output, both IDs and a guest
stack-local address. QPC BOOL is ignored under these authored-output cases;
this does NOT establish behavior when a real QPC failure leaves output unwritten.
Volatile-register clobbers are injected; flags/volatile final state, actual API
semantics, time epochs/units, ID lifetimes, failure policy, native lift and ARM64
remain unvalidated. No service or dispatch binding was added. Next: private
pinned native helper adapter compared with these saved x86 states before designing
production providers; never substitute a constant cookie or success stub.

## Private native entropy-helper adapter — run 3 iteration 13

Pinned pcrecomp now lifts only helper 82585C into a separately compiled private
module using explicit GuestRegisters/GuestMemory and per-call authored providers.
Four generated IAT operands must equal the PE-resolved addresses before call
transformation; stack words use a narrow checked proxy. No production handler or
service is registered. Cached persistent-index evidence reused, no fresh query.

Native comparison covers EAX, callee-saved GPRs, return ESP and the entire tracked
stack page against 256 fresh hook-free x86/oracle cases and the saved input/result
vectors. The providers check API order, stack/output arguments, FILETIME zeroing
and explicit return-boundary ESP, and inject the same authored outputs/clobbers.
These are not Windows implementations. Wrong output/cleanup and invalid-memory
checks accompany the private comparison; see the task report for final results.

New exclusion: a deliberately wrong QPC cleanup adjustment can be hidden by the
helper's frame teardown. Final return ESP alone is not a sufficient API ABI test;
the private fixture therefore checks the provider-return boundary separately.
Flags boundary export/import is explicitly disabled and flags/final volatile
registers are NOT compared. There is no modeled EIP/exception transfer, real API
failure policy, native time/ID semantics, security quality, ARM64 or startup proof.
Next compose the cookie initializer with this helper and compare their combined
call/return/data state privately; the earlier initializer reference injected the
helper result, so neither separate result establishes composition correctness.

## Private initializer/helper composition — run 3 iteration 14

The private checked-memory fixture now compiles initializer 8258A9 together
with the previously lifted helper 82585C. **320/320 Linux x86_64 native cases**
match fresh hook-free x86 execution: EAX, callee-saved GPRs, return ESP and entire
4 KiB stack/data pages. Independent arithmetic/frame oracles also check both
pages, cookie/complement and preserved-register/return effects. Helper executes
in 160 cases and is bypassed in 160; forced entropy values cover default-cookie
collision, zero/low-word normalization and high-word retention. Six deliberate
ABI/provider/memory/comparator errors reject. No production binding is added.

Composition-specific exclusion: the helper enters at outer ESP minus **12**
(two initializer register saves plus CALL), not minus 4 or the outer entry ESP.
That changes its address-dependent entropy term and the full retained stack.
The first fixture attempt failed this API-boundary assertion; the independent
frame model was corrected, with the failure retained privately. A second fixture
failure corrected the lifter's symbolic direct-call spelling, retaining exact
instruction-target and return-address checks. Image/upstream/old tests unchanged.

API providers remain authored injections, not Windows implementations. Boundary
flags import/export stays disabled; flags, final ECX/EDX, EIP/exception transfer,
real API failures/units/ID lifetime/security quality, concurrency and ARM64 remain
unvalidated. This is a composed bounded dependency, NOT original entry/startup
execution; the initializer's cookie role remains HYPOTHESIS. Cached persistent
index evidence reused; zero queries/imports, known CA-bundle ERROR retained.
Reproduce privately: `python3 work/phase1-run3-014/compose.py` after bootstrap.
Next inspect cached entry-continuation 824727 evidence and identify its first
unsupported call/service before extending any production runtime. Factory/+70
ordering remains undetermined; no automatic package precedence is enabled.

## Evidence and next experiment

`tests/guest_dispatch_tests.cpp` uses only authored code and independent expected
register/memory values: high-bit guest stack/object/vtable addresses, nested
32-bit virtual target lookup, unknown/misaligned/RVA-only targets, duplicate/null
bindings, unchanged stack/flags/non-result registers, and propagated failures.
38 checks passed on the Linux x86_64 host. No original x86 differential comparison
or Android execution is claimed for this interface.

Reproduce after sourcing `scripts/campaign/worker-env.sh` on this machine:

```sh
cmake --build build/host --target ts2_guest_dispatch_tests --parallel 2
build/host/ts2_guest_dispatch_tests
scripts/test-host.sh
```

## Private wrapper adapter — iteration 2

The bounded experiment above now passes **64/64 Linux x86_64 host cases**.
Private driver: `work/phase1-iteration-002/dispatch_probe.py`; generated source,
binary, full states and logs remain ignored. It reuses the existing wrapper
harness without editing it, verifies pinned upstream source files and all four
function hashes plus the complete analysis-image hash, reruns Unicorn and the
independent oracle, and requires exact agreement with the saved 64-case reference.
No new function range, Ghidra import or protection recovery was needed.

The private adapter changes generated entry signatures to receive explicit
`GuestRegisters`, `GuestMemory` and `GuestDispatch`. Integer register references
use that call state; lazy flags are materialized at each call boundary and
restored from it. The two direct leaf calls become exact-VA dispatch calls with
the reviewed guest return addresses pushed onto the checked guest stack. A word
proxy routes generated memory reads/writes through `GuestMemory`, **retaining the
old narrow outer/handle/stack span guard**, rather than allowing everything in
the committed test window. This is a pinned four-function transformation, not a
general-purpose lifter backend. No production auto-registration is enabled.

All eight GPRs, defined flags, return-stack effects and complete byte-level
tracked memory deltas match. Existing branch-specific undefined-AF policy is
unchanged. Three comparator mutations (GPR, ZF, memory byte) are rejected.
Additional checks reject an unregistered leaf, uncommitted memory, a read/write
crossing the declared span and uint32 address wraparound. A dispatch failure is
not rolled back; the harness stops rather than treating it as a guest success.

Reproduce privately after the normal bootstrap:

```sh
python work/phase1-iteration-002/dispatch_probe.py
```

Results: `work/phase1-iteration-002/result.json`. This script and its original-code
inputs are intentionally absent from a fresh clone. It compiles with the local
Zig 0.14.0 C++ frontend, not the Android NDK. **No ARM64, Android, startup or game
integration evidence** is established by this run. The original historical C
probe's device pass does not transfer to the changed C++ adapter.

Next: separate the private generated entry module from the case driver and test
independent register/memory instances before connecting it to any runtime owner.
Then select one evidenced callback boundary and reference-test its ABI; do not
infer callback ownership from the cache-only group. Callback-bearing creators,
releases and the jump-table path remain unsupported (see
`OBJECT_QUERY_CALLER.md`).

## Separate private entry module — iteration 3

Private `work/phase1-iteration-003/dispatch_probe.py` now emits `entries.cpp`,
`entries.hpp`, a shared narrow `adapter_memory.hpp`, and a separate case driver.
The entry module compiles to its own object before linking the driver; no case
initialization, saved reference or test entry point is in the entry module.
The original iteration-2 driver and historical fixtures remain unchanged.

A single immutable dispatcher serves two independently allocated guest memories
and register states. The 64 cases alternate between them using identical guest
addresses, checking the inactive context's nine register/flag fields and all
262,144 tracked bytes after every call. All 64 active contexts still match fresh
Unicorn, the independent oracle and the saved reference for GPRs, defined flags,
stack effects and full byte-memory deltas. Test-driver injection of a change to
the inactive register state or memory is rejected with distinct exits 45/46.
Prior comparator mutations and dispatch/memory/span/overflow negatives still pass.
This tests sequential isolation, **not concurrency or callback reentry**.

Reproduce privately with `python work/phase1-iteration-003/dispatch_probe.py`
after the usual bootstrap. Evidence is in that directory's `result.json` and
compile/run logs. Host regressions pass (CTest 5/5, Python 54 tests/no skips).
Android build remains blocked by missing SDK configuration; trusted acceptance
remains blocked by the unset validator. No ARM64 adapter execution or game
integration is claimed. `nm` is absent, so a separate symbol audit was unavailable;
an empty output file from the attempted command is not audit evidence.

HYPOTHESIS: this separation is sufficient for a later bounded runtime owner to
link the entries without sharing mutable current-context globals. The evidence
covers these four functions only. Further cache-only refactoring has diminishing
value: next reuse the persistent Ghidra index for a bounded startup/resource
service dependency (the documented factory at RVA `0x1D3E20`), identify a concrete
unsupported ABI/service, and retain independent reference validation before
implementing it. Do not infer handle/callback lifetimes or automatic package order.

## Checked FS data boundary — iteration 7

`native/include/ts2/guest_fs.hpp` supplies an explicit per-context uint32 FS base
and only `read32(memory, offset)` / `write32(memory, offset, value)`. It uses a
64-bit base+offset calculation and rejects sums or four-byte spans beyond 4 GiB
before narrowing. Committed-span and little-endian accesses remain delegated to
`GuestMemory`. Invalid writes reject before modifying any byte. Base zero does
not enable the protected null page. The last word at `0xFFFFFFFC` is valid if
committed. An unaligned word is supported when its complete span is committed.

This is deliberately stricter than hardware modulo-32-bit address formation:
wraparound is an unsupported adapter input, not silently accepted x86 behavior.
There are no descriptor limits/privileges, selector loading, TEB allocation,
exception dispatch/unwind, TLS callbacks, scheduler or global current-thread
state. Owners must explicitly associate each FS base with their memory/context;
`GuestDispatch::Function` remains unchanged. No factory is registered or enabled.

Authored `tests/guest_fs_tests.cpp`: **33 checks pass** on Linux x86_64, including
two bases in one memory, the same base in separate memories, unaligned bytes,
page-boundary failure atomicity, uncommitted/null access, end-of-address-space
words and overflow whose wrapped destination would otherwise be committed.
Expected values use direct checked linear-memory reads and fixed byte constants,
not an x86 emulator. A focused CMake target build and CTest `guest_fs` pass;
the full post-change host suite and Android/ARM64 execution remain unverified.

```sh
. scripts/campaign/worker-env.sh
cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --target ts2_guest_fs_tests --parallel 2
ctest --test-dir build/host -R '^guest_fs$' --output-on-failure
```

Next: privately connect this boundary to the hash-pinned compiled factory prefix
and compare the iteration-6 saved independent states. These authored FS checks
alone do not validate original code or show that the factory is startup-reachable.

## Private compiled-prefix comparison — iteration 8

Private `work/phase1-iteration-008/prefix_adapter.py` now lifts only the ten
previously pinned pre-allocation instructions, compiling the entry separately
from the fixture driver. Image, prefix and upstream lifter hashes are checked.
The original allocator call is excluded. The two exact FS operands route through
`GuestFs`; stack operands retain a narrow checked stack-page proxy. Register and
memory state are explicit arguments; no current-context globals or production
registry bindings are introduced. The unchanged production dispatch ABI is not
used to pretend this larger context is an integer-only registered function.

**64/64 Linux x86_64 native cases match** the iteration-6 saved segmented x86
states and the independent frame oracle: eight GPRs, selected preserved flags
(mask `0xED7`), complete 4 KiB stack and FS pages. A separate output EIP marks the
synthetic pre-allocation stop; it is not instruction stepping or a guest return.
The flat FS-zero reference is deliberately unsupported by `GuestMemory`'s null
page protection, not silently relocated and claimed as an exact execution.

Two contexts alternate separate memories and different nonzero FS bases. Each
call checks the peer's GPRs/flags/EIP and every tracked stack/FS/sentinel byte;
the active sentinel page is also unchanged. Four deliberate peer contaminations
reject. Five comparator mutations reject, as do seven invalid FS/stack inputs
(null/uncommitted/overflow FS, bad/wrapping/out-of-span stack, absent memory).
Failures are not transactional: earlier pushes/register updates may remain.

Reproduce privately after bootstrap:

```sh
python work/phase1-iteration-008/prefix_adapter.py
```

Result manifest, hashes, bounded compile/run logs and private derived code stay
in that ignored directory. Initial strict FS matching failed because the lifter
emits decimal zero rather than the assumed hexadecimal spelling; exact matching
was corrected without changing bytes, lifter, operands or range checks. Existing
production fixtures still pass FS 33 and dispatch 38 checks. No production source
changed. The full host suite was not rerun by this worker (`bg_task` unavailable).

This is neither full Windows SEH/unwind nor ARM64/game/startup evidence. No fresh
Unicorn run or write trace is claimed; the saved-state provenance and unresolved
hook SIGBUS remain recorded in the task report. Next use the persistent Ghidra
index to resolve the factory's data-registration/startup reachability before
expanding beyond this prefix or implementing guessed allocator/SEH services.

## Factory range-initializer evidence — iteration 9

Private bounded static check `work/phase1-iteration-009/check_registration.py`
reuses the three iteration-4 persistent Ghidra query envelopes (hash/image and
read-only provenance checked; known CA-bundle ERROR retained). No fresh query was
launched: the required background-task tool is unavailable. Independent
PE/Capstone inspection finds the factory pointer at `0xDA51DC` inside the range
`[0xDA51CC, 0xDA5214)`. Exact instruction ranges at `0x1D3BE2` and `0xD90870`
both initialize global words `0x10CC098`/`0x10CC09C` to those same endpoints.
The factory is the fifth word in that 18-word range. Eight deliberate operand
or truncation mismatches reject. Image and checked instruction hashes are private.

Important limitation: only the first 17 words point into executable sections;
the eighteenth points into data. Thus a contiguous-code-pointer scan would
misidentify the initialized range. This is **not** proven to be a homogeneous
factory array, vtable, registration loop or startup execution. Raw reference
hits are candidates, not decoded callers. No allocator or factory is bound.

HYPOTHESIS: the global range owner around `0x1D3Bxx` exposes registration or
lookup. Next query the existing index at `0x1D3BE2` and `0xD90870`, then trace
the range's consumer and invocation stride before interpreting any table entry
as an automatically called factory. The exact function boundary/startup chain
and indirect invocation remain unproven. Focused FS33/dispatch38 still pass;
no new x86 runtime, ARM64, Android or gameplay evidence follows.
