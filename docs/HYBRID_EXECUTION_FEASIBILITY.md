# Hybrid execution feasibility: static recompilation vs an embedded x86-32 interpreter vs whole-program dynamic translation

Status: **analysis only** — FAST FORWARD deliverable D (2026-10-27). Nothing was built, no
proof of concept was executed, no gate was changed, no existing file was edited. Siblings:
`docs/STARTUP_CRITPATH.md` (deliverable C, the Lane A graph referenced throughout),
`docs/ARCHITECTURE.md` (the decision questioned here),
`work/campaign-logs/recompilation-pricing-20261024.md` (the cost model).

## 0. Answer first

**Do not change direction now. Keep (A) static recompilation as the product
architecture and the shipping critical path. Adopt (B) in one specific, narrow form —
an in-process x86-32 interpreter used as a *startup-path discovery instrument*,
development-time only — starting with the one-day boundary proof of specification 9.
Convert (B) into a shipped residual executor only if the measured thresholds in 8.3
are met *and* the owner amends the architecture decision. Reject (C) outright.**

Why, in one line each:

- (B)'s real prize is **not** speed and **not** final architecture; it is that an
  interpreter needs no function boundaries, no recovered call graph and no per-function
  verification in order to *execute* code. Lane A's blocking unknowns are exactly what a
  static closure cannot supply — `docs/STARTUP_CRITPATH.md:45-57` leaves the entrypoint
  frame, the executed Win32/TLS/SEH import surface, lifetime producers and opener→spine
  edges unpinned, and the Ghidra direct-call closure cannot bound them (**Established,
  measured here**: `0x1AB665` → 92 functions / 7,080 bytes, entry `0x8248A3` → **1**
  function, its recorded callee list being empty — `work/ghidra-index/functions.jsonl`).
- (B) buys **none** of what the project actually costs most: the service surface (438 direct
  imports across 17 DLLs including `d3d9!Direct3DCreate9` and eight `steam_api.dll`
  functions — `docs/PROTECTION_DIAGNOSIS.md:49-52`) and the per-callee contract work the
  pricing report books as "stops and asks" (`:250`). An interpreter calls the same imports.
- (C) is the already-excluded architecture (`docs/ARCHITECTURE.md:8-9`,
  `the mission brief (private record):15`), the only one exposed to Android executable-memory
  policy, and an order of magnitude dearer than (B) for a smaller prize here.

### 0.1 Evidence labels

- **Established** — cited to a file:line here, or measured by me read-only against the
  private index during this analysis (each measurement names its source).
- **Estimate** — engineering judgment with the reasoning shown. No Estimate is a
  measurement: the project has **no benchmark harness**, so every performance claim about
  the port is explicitly unsourced (`the project status archive (private record):1902-1903`).
- **Open** — unknown, with the cheapest way to find out.

Upstream paths below (`runtime/…`, `docs/HYBRID.md`, `tools/…`) are relative to the pinned
pcrecomp tree at `work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/` (ignored; only its MIT
`LICENSE` is vendored at `third_party/pcrecomp/LICENSE`).

## 1. The three candidates, precisely

| | Definition in this port | What ships |
|---|---|---|
| **(A)** | Today's architecture: pinned pcrecomp lifts selected original x86-32 functions to C, compiled for AArch64, executed against `GuestMemory` through exact-VA `GuestDispatch`; unlifted target = fail closed (`native/src/guest_dispatch.cpp:24`). | Native ARM64 code only. |
| **(B)** | (A) **plus** an in-process x86-32 instruction interpreter owning one shared guest-CPU state, used as the fallback executor for the *residual* (addresses not lifted), including dynamic import trampolines and indirect targets. No Windows API reimplementation, no PE loader, no second process. | Native ARM64 lifted hot path + a small interpreter for the residual. |
| **(C)** | Whole-program dynamic binary translation of the recovered code range to AArch64 at runtime (FEX/davmemu/Box86 class), with a generated-code cache, self-modifying-code invalidation and thread-queue locking. | A runtime translator driving the original program. |

(B) is *not* (C) with "smaller scope" pasted on: (B) never takes over the process, never
generates host code, and degrades to today's behaviour when the interpreter is disabled
(6.2).

## 2. Ground truth today (Established)

| Fact | Value | Source |
|---|---|---|
| Image functions / index records | 44,151 / 43,724 | `docs/VERIFIED_LEDGER.md:146-147` |
| Verified addresses (strict ledger) | **46** (≈0.10 %), 11 at T1, 0 at T2 | `docs/VERIFIED_LEDGER.md:141-144,147,39` |
| Measured cost per tractable function | **40–125 min**; +30–90 min per *new ABI/lifetime/service class* | pricing report `:141-143` |
| Measured extrapolation to image | 3.6 / 10.5 / **12.3** years unattended; 126 years at the "12.5 % need 25 h of environment work" tier | pricing report `:157-160` |
| Factory v1 support gate | full-window decode, `ret` terminator, **no calls at all**, ALU/mov whitelist; thunk and virtual-dispatch classes unsupported | `scripts/verify-factory/README.md:26-30`; `scripts/verify-factory/factory.py:45-51` |
| Factory v1 measured yield | 12 leaf-getter candidates → **1** verified, 6 rejections, 5 quarantines | `scripts/verify-factory/README.md:47-52` |
| Startup graph | SEED; entrypoint frame, executed import surface, lifetime producers, opener→spine edges all unpinned | `docs/STARTUP_CRITPATH.md:45-57` |
| Game execution today | **none proven**: "P0 actual game runtime/gameplay OPEN: no original-runtime Android APK, real asset menu, lot input or 120-second game session proven" | `tasks/android-phase1/OPEN_QUESTIONS.md:30-32` |
| Function shape (measured here) | median **32 instructions / 86 bytes**, mean 72 / 223 B, p90 162 instr | `work/ghidra-index/functions.jsonl` (`instrWalked`, `sizeBytes`) |
| Static edge density (measured here) | 34,612 records expose callee edges, 104,590 edges, 23,486 distinct targets, **20,260 records have zero recorded callers**, only 195 truncated pseudocodes | same |
| Class census | thunk 223, leaf-getter 449, leaf-setter 908, small-leaf 7,517, **branchy 30,683**, large 3,944, unknown 0 | `work/ghidra-index/triage.json` |
| ISA families in evidence (measured here) | 693 records contain a `switch` in pseudocode; 251 reference `_CxxThrowException`; but `_except_handler3`, `in_FS_OFFSET`, `VirtualProtect` and `FlushInstructionCache` appear in **0** of 43,724 records, and `__CxxFrameHandler`/`TlsGetValue`/`RaiseException` in only 2/2/3 | same, substring counts |
| Runtime state shape | `GuestRegisters` = 9 × `uint32_t` (8 GPRs + `eflags`), "Integer-only call state, not a complete x86 thread context" | `native/include/ts2/guest_dispatch.hpp:9-14` |
| Memory model | 4 GiB `mmap(PROT_NONE, MAP_NORESERVE)` reservation, `commit()` = `mprotect(PROT_READ|PROT_WRITE)`, every access through `checked()` = one `std::map` lookup, `throw` on uncommitted | `native/src/guest_memory.cpp:11,14,23,31-35` |
| Code pages / threads | guest code is data and "never receive executable permission"; each guest thread needs integer/x87/SSE/flags, stack, FS/TEB, TLS with explicit handoff | `docs/ARCHITECTURE.md:69-71,80-84` |
| Dev-time reference runner | `unicorn==2.1.4` (Python), and pcrecomp's own 372/372 differential cases are Unicorn-referenced | `tools/requirements.txt:3`; `docs/RESEARCH.md:34` |
| Upstream hybrid support | pcrecomp is MIT and already contains a lifted↔real-code boundary | `docs/RESEARCH.md:10`; `third_party/pcrecomp/LICENSE:1` |

Two facts dominate everything below: the factory's automation currently covers a class that
*cannot contain a call*, so it cannot express startup code at all; and the pricing report's
own conclusion is that the bottleneck is **environment/contract discovery, not
translation** — exactly the axis an interpreter does *not* move.

## 3. (a) Guest memory model unification

**Today.** One GuestMemory instance owns a 4 GiB reservation and guest VAs are
`base_ + address` (`native/src/guest_memory.cpp:14,35`). That flat, single-window design is
the property that makes (B) cheap here: an interpreter needs no shadow mapping, no
page-table emulation and no guest→host address translation layer — guest VA *is*
`base_ + va`, and guest ESP is a plain guest VA in `GuestRegisters::esp`.

**What a hybrid needs, and what is missing.**

1. **A fast path.** `checked()` is a red-black tree lookup plus a range test on every
   access, and *throws* on an uncommitted address (`native/src/guest_memory.cpp:31-35`).
   For an interpreter executing ~32 instructions per median function with 1–2 memory
   operands each, that lookup dominates the per-instruction budget — Estimate: it is the
   single largest implementation cost in (B). Required change: keep the 4 GiB reservation
   and the committed-range *semantics*, add a page-state array (≤256 KiB of metadata for
   the whole window) so an access is a bounds check plus an array index, and make
   "uncommitted" a guard-page fault or an error code rather than a C++ exception on the hot
   path. This is a *shared* improvement: `docs/RECOMPILATION.md:120-121` already records
   that generated lifted code "still use upstream macros, not the checked GuestMemory
   class", so **(A) has the same integration gap today**.
2. **The image stays data, and one `GuestMemory` instance stays the only one.** No option
   needs executable guest pages ((C) alone fights `docs/ARCHITECTURE.md:69-71`), and
   page-size handling is already `sysconf`-driven (`native/src/guest_memory.cpp:11`,
   `docs/ARCHITECTURE.md:108`). An interpreter owning *its own* memory would fork the heap
   and the guest stack and invalidate the existing receipts, which compare whole 4 KiB
   stack pages; both executors must take the same instance by reference, as
   `GuestDispatch::Function` already does (`native/include/ts2/guest_dispatch.hpp:28`).

**Verdict on (a):** the cheapest of the four hard problems, ~0.5–1 engineer-week
(Estimate), and a prerequisite (A) already has outstanding. It should never block a
decision.

## 4. (b) Calling-convention bridging

**The good news is structural.** Arguments live on the guest stack inside `GuestMemory` and
results are guest-width (`EAX`, optionally `EDX`, `st(0)`), so no host ABI is ever involved
at a guest↔guest boundary. `thiscall` (`ECX`), `stdcall` (callee cleanup), `cdecl` (caller
cleanup) and hidden-pointer struct returns are therefore *the same problem* for (B) as for
(A): MSVC conventions need no marshalling layer, only agreement about **who cleans the
stack** — which this project already treats as a per-function, differentially tested fact
(three wrong cleanup models are recorded as deliberate rejections in
`docs/GUEST_DISPATCH.md:16,47,63`).

**The boundary rules that do need designing** are the ones upstream already wrote down for
exactly this situation: pcrecomp's hybrid mode seeds `ebp` with a *host* frame pointer so
stack walking cannot cross into guest frames (`docs/HYBRID.md:29`), puts the marshalling
block **before** that seed so a nested crossing cannot smash the outer frame
(`docs/HYBRID.md:48`), and captures the returned pointer out of `EDX` **before** the callee
clobbers it (`docs/HYBRID.md:73`). Upstream also routes calls through an explicit thunk /
slot table instead of patching call sites (`runtime/hybrid/hybrid.h:70-80`), reports the
callee's stack cleanup as part of the boundary contract — `(result | arg_bytes_cleaned
<< 32)` (`runtime/hybrid/hybrid.h:52-66`) — and moves the x87 stack explicitly, because a
function returning float/double returns it in `st(0)`, not `eax`
(`runtime/hybrid/hybrid.h:113-146`). That cleanup-as-return-value shape is worth copying:
it turns *who popped the arguments* into a measured fact at every crossing.

**Two facts that constrain (B) here, and are easy to miss.** Upstream's hybrid
implementation is **MSVC x86-32 `__asm`** (`runtime/hybrid/hybrid.c:4` — "32-bit x86, MSVC
(uses `__asm`)"), so its "real code" side is real x86 machine code on an x86 host; **on
AArch64 there is no such thing**. The design is reusable, the implementation is not: option
(B) *is* the substitution "real machine code → interpreter", and that substitution is what
must be built and tested here. Separately, upstream's CPU-struct runtime assumes a
**32-bit host** so memory operands dereference host pointers directly
(`runtime/recomp32_cpu/cpu.h:9-13`); ours is a 64-bit host with checked accessors, so that
runtime cannot be adopted wholesale — but its *state shape* can, and that shape is what
keeps transitions cheap.

**Concrete bridging spec (both directions).**

1. The interpreter exposes `void invoke(uint32_t va, CpuState&, GuestMemory&)`, registered
   for a VA *range* or bound per-address lazily; `GuestDispatch::invoke` gains an optional
   fallback hook before it throws (`native/src/guest_dispatch.cpp:24`), so fail-closed
   stays the default and no existing verified adapter changes.
2. On entry, the callee saves the caller's `CpuState` pointer and the guest return VA,
   executes until that return VA is reached, then reads `EAX`/`EDX`/`st(0)`-dirty and the
   resulting ESP. Stack cleanup is **read off the guest ESP delta**, never assumed — the
   same discipline that produced today's cleanup receipts.
3. Nested crossing must be legal to depth N (upstream's Rule 2 failure mode: a callback
   re-entering lifted code smashes the outer frame's locals — `docs/HYBRID.md:48-72`). Test
   P3 exists only for this.
4. Host-side services stay exactly as they are (`GuestDispatch::Function` adapters,
   `native/include/ts2/guest_dispatch.hpp:28`); a host 64-bit vtable is still never
   copied into guest memory (`docs/ARCHITECTURE.md:78`), and upstream's real→lifted vtable
   routing (`docs/HYBRID.md:89-111`) stays out of scope until a real caller demands it.

**Cost (Estimate):** 2–4 days for the boundary plus 1 week for the ABI-lifecycle matrix
(cleanup × struct-return × float-return × reentrancy depth). The risk is not difficulty but
that **every** convention bug presents as a wrong contract — the bug class the pricing
report measures at 72 human-minutes each (`:18`).

## 5. (c) FPU/SSE, SEH and TLS synchronization across the boundary

### 5.1 What the state model looks like today (Established)

`GuestRegisters` has no x87 register stack, no tag word, no MXCSR, no SSE file and one
`eflags` placeholder (`native/include/ts2/guest_dispatch.hpp:9-14`). `GuestFs` is an
explicit flat 32-bit data base with no TEB, no selector limits and **no exception
dispatch** (`native/include/ts2/guest_fs.hpp:7-10`). `GuestCpu` answers CPUID/XGETBV from an
authored table and is documented as "a stop/diagnostic boundary, NOT guest #UD/#GP
delivery" (`native/include/ts2/guest_cpu.hpp:21-23`). Receipts record x87/SSE as
**unobserved** rather than handled (`tasks/android-phase1/OPEN_QUESTIONS.md:4598`), while
the architecture already demands guest exceptions "operate on guest records, not ARM C++
exceptions" and calls out x87 precision (`docs/ARCHITECTURE.md:80-84`).

### 5.2 Why this is where (A) and (B) actually differ

The measurement above finds 251 of 43,724 records referencing `_CxxThrowException` and 693
with a `switch` in their pseudocode, while `_except_handler3` and `in_FS_OFFSET` appear in
none and `__CxxFrameHandler`/`TlsGetValue` in two each. Read carefully (**Open**, because
absence in Ghidra pseudocode is bounded negative evidence, not proof): C++ EH *is* present
in the recovered image, while MSVC `__try/__except` and visible TLS-relative accesses are
not showing up at this index's granularity — which is precisely the code shape a runtime
executor has to handle and a static index does not see.

- Under **(A)** each of {x87, SSE, SEH, TLS, last-error} is a **per-family rig** extended for
  every function that touches it, plus a per-function verification: the pricing report
  measures a new ABI class at +30–90 minutes of analysis *before* implementation (`:143`),
  and 23 bespoke rigs produced 46 ledger addresses.
- Under **(B)** each is a **one-time component** inside the interpreter, after which every
  function — lifted or not — gets uniform semantics. pcrecomp (MIT) already supplies the
  portable model worth mining rather than reinventing: an x87 stack as `double _st[8]` with
  `fp_top`/`fpu_cw`; an SSE file as a *union* file (scalar SSE single really is 32-bit, and
  computing `addss` in double rounds differently — `runtime/recomp32_cpu/cpu.h:36-58`);
  `fs_base` with `FS_RD*/FS_WR*` falling back to ordinary memory for a simulated per-thread
  TIB on non-Windows hosts (`cpu.h:90-94,135-143`); and `runtime/native32/eh32.c`, a
  guest-side C++ EH dispatcher walking the guest `fs:[0]` chain into per-function setjmp pads
  (`eh32.c:1-28`). **That is a reference design for exactly these families, and (A) can
  reuse it too.**

### 5.3 The synchronization rule that makes the boundary cheap

Do **not** synchronise FP/SSE/SEH state across the boundary. Make it *owned*:

- One `CpuState` per guest thread, holding GPRs, lazy flags, x87 stack + top + control
  word, SSE file + MXCSR, `fs_base`, the guest SEH chain head and last-error — precisely
  the set `tasks/android-phase1/OPEN_QUESTIONS.md:6149-6150` still lists as open ("callback
  ABI/lifetimes, x87/SSE, TLS/SEH, services, startup and renderer remain open").
- A **single active `CpuState *`** plus an owning-executor flag: entered from lifted code
  by publishing the state and becoming active, restored on return; a lifted FP user runs
  only while the interpreter is inactive on that state, or the interpreter invalidates its
  cached FP state on return.
- Lazy FP: each lifted function records "touches x87/SSE" statically (the lifter already
  knows the mnemonic set); state is materialised at a crossing only if either side touches
  it, so integer-only crossings cost nothing extra — the whole point, given the measured
  32-instruction median function.

**Estimate:** 1–2 engineer-weeks for the FP-family decision plus its differential tests, 1–2
weeks for an SEH-dispatchable `CpuState` (model `fs:[0]`, deliver exceptions raised by
divide-by-zero / access violation / `int3` / `RaiseException` into the guest chain, keep
`SetUnhandledExceptionFilter`-style host escapes as loud stops). **Open, and the single best
early measurement:** how much of the *startup* path actually depends on x87/SSE/SEH — an
interpreter-hours question, not a grepping question.

## 6. (d) Transition overhead, interpreter speed penalty, and the Wine question

### 6.1 Overhead arithmetic (Estimate, from the state design — not measured)

The project has no benchmark harness (`the project status archive (private record):1902-1903`), so
these are reasoning, explicitly not results.

| Quantity | Estimate | Basis |
|---|---|---|
| Function-granularity crossing, integer-only, state-in-memory | ~25–100 host cycles one-way | host C call + spill (≈10–30) + publish/restore active-state bookkeeping (≈10–30) + return-VA frame bookkeeping (≈5–15) + optional trace record (≈5–20) |
| Same crossing, eager x87+SSE sync | +50–300 cycles | 8×16 B x87 + 8×16 B SSE + control/MXCSR round-tripped per crossing; **this is why 5.3 makes it lazy** |
| Interpreted guest instruction | ~5–20 host cycles | decode-cached switch/indirect-thread interpreter on a 4–6-wide ARM core |
| Lifted native equivalent | ~1–2 host cycles | ordinary compiled C |
| **Whole-interpreter penalty** | **~5–20×** vs lifted code | ratio of the two rows above |

Consequence, and it is the design rule that decides whether (B) is viable at all: with a
median function of **32 instructions** (Established, §2), one interpreted call costs roughly
160–640 cycles of work while a crossing pair costs 50–200 → **crossing at function
granularity costs roughly 10–60 %** on median-sized functions and *less* on bigger ones.
Crossing per basic block or per indirect branch (5–20 cycles against a 3–10-instruction
block) costs **multiple times** the interpreted work. Therefore:

1. Cross only at **function** granularity: when the interpreter calls a lifted function, the
   *subtree* returns to the interpreter's frame, not to the outer caller.
2. Hot small leaves (`thunk` 223 / `leaf-getter` 449 / `leaf-setter` 908; `0x14323F` has
   1,071 recorded callers) are where crossings dominate — and are exactly what the factory
   already verifies. So (B) needs a **hotness-driven promotion loop**: profile → hand hot
   addresses to the existing lift+verify pipeline → they become native. (B) and (A)
   converge, which is the strongest argument for section 8.
3. Interpretation is acceptable where the port needs it *first* (menu/init is
   setup-dominated, Estimate), never for live simulation or the render loop: (B) means
   "interpret the residual until it is measured hot", never "interpret everything".

### 6.2 Is a narrow in-process interpreter "materially different" from Wine/Box86?

The exclusions are literal: "No Wine, Box86, Winlator, runtime x86 interpreter, or full
system emulator is part of the product" (`docs/ARCHITECTURE.md:8-9`); "Product architecture
remains native compiled code and portable OS/API bridges, not Wine, Winlator, Box86 or an
x86 interpreter shipped in the APK. Unicorn/x86 emulation may be used privately as
**development-time reference tests**" (`the mission brief (private record):15`).

Different in kind, on five axes (all Established as properties of the systems):

| Axis | Wine / Box86 / Winlator / (C) | Narrow in-process interpreter (B) |
|---|---|---|
| Who drives the process | the original PE, loaded by a loader, is the program | our `main`, our loader policy, our entry discipline; guest code runs only when we call it |
| API surface | must reimplement the whole Win32/NT/COM/D3D surface at product quality | we implement only the individual contracts we have already differentially pinned; nothing is *emulated*, it is *authored* |
| ISA coverage requirement | complete enough for arbitrary third-party binaries | complete enough for MSVC-32 codegen in the paths we run — with any gap a **loud stop**, not a guess |
| Verifiability | behaviour is whatever the emulator produces | uniform x86 semantics, so a single interpreter passes the *same* x86-referenced differentials the factory already runs (`scripts/verify-factory/README.md:10-18`) |
| Product identity | the product is a compatibility layer | the product is native code + services; the residual executor is a component with a budget and a shrinking surface |

**Honest counter-argument.** None of that changes the *letter* of the exclusion: an
interpreter in the APK still "executes x86 at runtime", and that sentence is what
`docs/ARCHITECTURE.md:8-9` forbids. So the real question is not technical, it is which
risk the owner prefers: the risk of shipping an interpreter (policy change, a large
un-verifiable-by-construction surface, an audit burden) versus the measured risk of (A)
alone (**3.6–12.3 years** of unattended agent time for the image under assumptions the
pricing report says are already false, `:157-158`, `:186-188`). That is why 8.1 puts (B) in
dev-time first: **it gets (B)'s answer without touching the product boundary at all**, and
keeps the policy question for the moment where real measurements make it cheap.

## 7. (e) Win32/OS service sharing, and effort per option

### 7.1 Service sharing

Today's services are hand-authored, guest-ABI-visible adapters living in `ts2_core`
(`CMakeLists.txt:10`: heap, OS error, release/storage/lazy/error-slot ABI adapters, loader
policy, resolver, DBPF/QFS/resource mount) and registered by exact VA in `GuestDispatch`.
They are executor-agnostic by construction: they take `(registers, memory, dispatch)`.

| | (A) | (B) | (C) |
|---|---|---|---|
| Service implementations needed | identical set | **identical set** (same imports, same contracts) | identical set, plus whatever the translator's own runtime expects |
| Dispatch mechanism | exact-VA registry | + range fallback for dynamic import stubs | import hooking inside the translator |
| Threading / last-error | per-thread state, explicit handoff (`docs/ARCHITECTURE.md:80-84`); last-error per contract | same, plus one interpreter context per thread, and last-error inside `CpuState` because *interpreted* code raises failures too | same, plus translator queue locking |

The asymmetry that matters: (B) makes missing services *discoverable* (it runs until the
next unimplemented import and names it) instead of *invisible* (a lift simply never
reaches it). That converts Lane A's frontier item 2 — "which imports the startup prefix
actually executes … has no inventory receipt yet" (`docs/STARTUP_CRITPATH.md:51-53`) — from
an archaeology problem into a log file. It does not implement one import fewer.

### 7.2 Effort in function-families-to-milestone terms

Milestones: **M-menu** = first real menu on Android; **M-game** = the 120-second gameplay
smoke test (`the mission brief (private record):11`). Families = the class census plus the families
the receipts force: F1 thunk, F2 leaf get/set, F3 small straight-line, F4 branchy (no calls),
F5 calls + cleanup-ABI classes, F6 indirect/virtual dispatch, F7 x87, F8 SSE, F9 C++ EH/SEH,
F10 TLS/FS/last-error, F11 large/init functions, F12 service-call boundary.

| Option | Work to M-menu | Work to M-game | Bounded? |
|---|---|---|---|
| **(A)** | F1–F4 *rigs* (F5–F12 mostly still open), then per-function verification of the whole startup closure. Function count to M-menu is **Open** and unmeasurable today (graph is SEED, `docs/STARTUP_CRITPATH.md:45-57`; static closure can't bound it, 0). At the measured 40–125 min/function plus the measured 1-in-12 factory yield on the *easiest* class, a closure of even 3,000 functions is months of campaign time and 12,000 is years. | Same curve with no asymptote; every new family re-prices. | **No** — cost is linear in discovered functions; contracts are "stops and asks" (`:250`). |
| **(B)** | Fixed components: fast guest memory (0.5–1 wk), interpreter core for F1–F5 + dynamic import stubs (1–2 wk), x87/SSE decision (1–2 wk), SEH/TLS/last-error (1–2 wk), boundary (2–4 d), ABI/reentrancy matrix (1 wk), re-baselining the differential discipline onto the interpreter (1 wk) → **Estimate 5–9 focused engineer-weeks before "does it reach a menu" is answerable**, *then* the same service/contract work as (A). | + hotness-driven promotion of measured-hot functions into (A)'s pipeline, priced per family, not per function. | **Yes**, for the execution half. The service half stays as unbounded as (A). |
| **(C)** | F1–F12 *all at once* before anything runs, plus code-cache coherence, SMC invalidation, thread-queue locking, and an answer on Android executable-memory policy for generated code (**Estimate/UNCERTAIN, verify before relying on it**: Android 10+/API 29 enforces W^X for third-party apps, which is precisely why JIT-style translators surface in Termux-like environments rather than ordinary APKs). **Estimate 1–3 engineer-years** to a baseline one would trust with the ledger's discipline. | Same, and the performance target is the translator's own. | Bounded but far larger; and it is the excluded architecture. |

### 7.3 The one number that should decide (A) vs (B) later

The honest discriminator is not "how many functions exist" but **how many distinct functions
and how many distinct services one real startup actually touches**. That is measurable and
has never been measured: statically it is unknowable (`0x8248A3` has no recorded callees and
a closure of one), and under (B) it falls out of a single run. Everything in section 8 is
organised around buying that number as cheaply as possible.

## 8. (g) Recommendation, risks, and switching thresholds

### 8.1 Recommendation

1. **Keep (A).** Do not touch `docs/ARCHITECTURE.md` today; do not re-plan Lane B
   (`abi-services`, `factory-families`) — its services are needed identically by every
   option, so nothing there is wasted either way.
2. **Run the one-day boundary PoC** (section 9) — decision-relevant for (B) and
   independently useful for (A), because it forces the fast-memory path and the shared
   `CpuState` that `docs/RECOMPILATION.md:120-121` already records as missing.
3. **Build the dev-time *pathfinder*, not the product interpreter.** Cheapest first version:
   drive the recovered code offline with the already-pinned `unicorn==2.1.4` behind our own
   `GuestMemory`/`GuestDispatch`-shaped service adapters and a fail-closed import policy,
   never linked into `ts2_core`. **Scope note (Established boundary):** this is *extended
   execution of recovered code*, and `the owner standing authorization (private record):11-13` authorises
   "**bounded** differential execution", so a long startup run needs a one-line owner
   sign-off; it touches no DRM, no authentication, no original files, and ships nothing.
   Its deliverable is the two lists Lane A needs — **the distinct functions reached (with
   indirect edges resolved dynamically) and the distinct imports/services demanded** —
   written into `docs/STARTUP_CRITPATH.md` as `confirmed` edges.
4. **Decide (A)-only vs (B)-in-product from that data**, against the thresholds in 8.3.
5. **Reject (C)**, once and for the record: excluded twice over
   (`docs/ARCHITECTURE.md:8-9`, `the mission brief (private record):15`), the only candidate
   fighting both the no-executable-guest-pages rule and Android's executable-memory rule,
   and 1–3 engineer-years just to *start answering the question* is not a trade for a
   project whose bottleneck is service contracts.

### 8.2 Risks of this recommendation

| Risk | Why it is real | Mitigation already in the plan |
|---|---|---|
| Policy drift: "dev-time pathfinder" becomes "shipped emulator" | the letter of `docs/ARCHITECTURE.md:8-9` is about the APK, and pressure to reuse is normal | hard rule: GPL-class reference runners (Unicorn's engine is GPL-2.0 upstream — confirm the pinned revision's licence; `docs/RESEARCH.md:152-157` already sets the precedent of an ignored GPL reference that is never linked or redistributed) and any pathfinder code stay out of `ts2_core` and the app target; shipping (B) needs an ADR amendment |
| Measuring with the wrong oracle | the pathfinder's own fidelity becomes an assumption | the project's standard already applies: reference states come from executing original x86 under Unicorn fresh, never from the compared side (`scripts/verify-factory/README.md:10-12`); a *third* implementation (in-house interpreter) must agree with it, see T1 below |
| (B) hides missing services behind partial progress | an interpreter happily runs until the 400th import | the pathfinder's output *is* the import list; treat "imports demanded" as the Lane B queue input, not as an error |
| Years of (A) investment judged unfair | 46 addresses, 23 rigs, the factory, ~14,900 rig lines | the promotion loop (6.1) makes (A) the *end state* of (B), not its casualty; every service, fixture, receipt and pinned pcrecomp rig stays in use |
| Unbounded dev-time runs | `the owner standing authorization (private record):39` (investigations stay "bounded by reasonable resource and execution" limits) and campaign budgets | hard wall-clock/step budgets per run, recorded, with the trace truncated not extended |
| False precision in this document's numbers | no benchmark harness exists | all perf numbers labelled Estimate; PoC's job is to replace them |

### 8.3 Evidence thresholds

Promote (B) from dev-time instrument to **shipped residual executor** only if all of:

- **T1 Interpreter trust.** The in-house interpreter reproduces the existing factory
  receipts on the same x86 reference states across ≥10,000 whole-function cases spanning
  F1–F11, with zero false acceptances, mutation controls still failing, host + AArch64
  byte-identical (`scripts/verify-factory/README.md:10-18` discipline). Any unexplained
  divergence stops the promotion.
- **T2 Startup value.** One pathfinder run yields ≥90 % of dynamically observed call edges
  resolved to concrete targets, an ordered distinct-import list, and a closure size the
  graph can state as a number instead of "unknown".
- **T3 (A) is measurably slower on the same closure.** Compare (A)'s measured factory
  throughput and yield on that exact closure against the interpreter's wall-clock to the
  same frontier. If (A) is within ~2× *and* the closure is under ~500 functions, stay with
  (A) — the extra shipped surface is not worth it.
- **T4 Performance budget survives.** A real on-device measurement (which needs the
  benchmark harness that does not exist yet) puts the interpreted residual inside budget for
  the menu path, with hot functions promoted.
- **T5 Owner amendment** to `docs/ARCHITECTURE.md:8-9` and `the mission brief (private record):15`.

Abandon (B) if: divergences in T1 concentrate in x87/SSE/SEH and cannot be closed (then the
interpreter cannot be trusted for the very families it was built for), or the pathfinder
shows the startup path is dominated by service contracts rather than function volume
(which is what the pricing report already hints at, `:18`) — in that case *neither* option
is the bottleneck and the fleet should keep spending everything on services.

## 9. Bounded one-day PoC: the native↔interpreted boundary

**Goal.** Prove that lifted-and-verified code and an interpreted guest function can execute
against **one** `GuestMemory` and **one** `CpuState`, in both directions, reentrantly, with
existing receipts still passing — or fail loudly and cheaply. **Deliberately excluded:**
game startup, the entry point, Win32 services, resources, threads, x87/SSE/SEH, the APK,
and performance claims of any kind.

### 9.1 Scope

- **New:** `native/include/ts2/guest_x86_min.hpp`, `native/src/guest_x86_min.cpp` — a
  decoder/executor over the **exact** opcode whitelist the factory already treats as
  supported (`scripts/verify-factory/factory.py:45-51`: mov/lea/add/sub/xor/and/or/cmp/test/
  push/pop/nop/inc/dec/not/neg/adc/sbb/movzx/movsx/xchg/imul/shl/shr/sar + all `setcc`),
  **plus** control flow only (`call rel32`/`call r/m32`, `ret [imm16]`, `jmp`/`jcc
  rel8|rel32` direct and indirect, `leave`). Any other mnemonic is a typed
  `UnsupportedOpcode(va, bytes)`. Coverage is deliberately *identical to the already
  verified class* — that is what makes the three-way comparison honest.
- **New:** `CpuState` (GPRs, lazy flags, x87 file + top + cw, SSE file + MXCSR, `fs_base`,
  SEH chain head, last-error, "touches FP" cache) + single-active-owner pointer; the FP
  fields exist and stay inert in the PoC.
- **Modified (behaviour-preserving):** `GuestDispatch` gains an optional non-owning
  fallback hook consulted before `throw UnresolvedGuestCall(va)`
  (`native/src/guest_dispatch.cpp:24`); with no hook the class behaves exactly as today,
  which is what keeps the existing suites meaningful. Fast-path memory = the page-state
  array of 3.1, with `checked()` semantics retained.
- **New tests/probe:** `native/tests/guest_hybrid_boundary_*`, CMake targets
  `ts2_guest_hybrid_tests` / `ts2_guest_hybrid_probe`, host + the existing AArch64 QEMU
  path (`scripts/campaign/arm64-run.sh`).

### 9.2 The three proofs

- **P1 native → interpreted.** A lifted T1 function that calls a guest VA which is *not*
  bound in `GuestDispatch` (so today it throws) instead reaches the interpreter. Use the
  T1 composed opener initializer `0x2570` as the native side and a call-free verified
  leaf as the interpreted side; the native side's expected post-state is the state its
  existing receipt already asserts (`docs/VERIFIED_LEDGER.md:51`, 64/64 each ISA).
- **P2 interpreted → native.** Interpreted code `call`s a VA bound to a lifted T1 leaf
  (`0x1A00`/`0x1A40`/`0x102D0` class, `docs/VERIFIED_LEDGER.md:49-50,52`); return value, ESP
  delta and cleanup ownership must match the leaf's recorded contract.
- **P3 nested reentrancy.** native → interpreted → native → interpreted, depth 4, asserting
  the outer frames survive (upstream's rule-2 failure mode).

**Acceptance: a three-way agreement.** Each PoC fixture runs three ways and must agree
byte-exactly on 8 GPRs + final ESP + memory delta: (i) the existing lifted native body,
(ii) the new interpreter, (iii) fresh x86 reference under Unicorn. This reuses the
project's own fixtures instead of inventing new expectations, so it cannot pass by
construction. A mutation control per fixture (perturb one interpreted instruction; the
comparison must FAIL) is mandatory, per `scripts/verify-factory/README.md:16-18`.

**Also record (numbers, not claims):** host cycles per crossing (both directions, integer
only vs forced FP sync), host cycles per interpreted instruction, on x86_64 host and
AArch64, labelled first-measurement.

### 9.3 What this PoC proves, and what it does not

**Proves:** that the guest ABI/state/memory model supports two executors over one guest
instance; that reentrancy is safe; that the fail-closed boundary can gain a fallback edge
without disturbing an existing verified adapter; first real cycle numbers for the 6.1
estimates; that the interpreter agrees with the project's own oracle on the already
verified class.

**Proves nothing about:** whether the startup path runs, which services it needs, x87/SSE/
SEH/TLS fidelity, Android packaging or policy, gameplay performance, or whether (B) is the
right end state. Only 8.3's T2–T4 answer those.

## 10. Explicit non-claims

This document makes no claim that the game, a menu, an init path or any original function
has executed on Android as a result of this analysis; that `scripts/phase1-acceptance.sh`
(exit 78) should change; that any performance figure here is measured; that the recovered
image was executed, modified or launched for this analysis (it was not — every measurement
here was a read-only query over `work/ghidra-index/`); or that the exclusions in
`docs/ARCHITECTURE.md:8-9` and `the mission brief (private record):15` are void. Phase 1 remains
uncloseable without the trusted independent validator.
