# Experiment log (evidence archive)

> Historical record of diagnostic experiments and private-fixture procedures.
> These are evidence archives, **not setup instructions** — see README.md for setup
> and AGENTS.md for contribution rules. Some entries reference owner-only
> private fixtures under ignored `work/` paths; a fresh clone lacks them
> and such commands are expected to fail there.

## Linux/AArch64 regression tests (not Android)

With the documented Zig 0.14.0 wrappers installed (see
[local toolchain setup](LOCAL_VALIDATION.md)), use a separate build tree:

```sh
. scripts/campaign/worker-env.sh
scripts/campaign/provision-qemu-aarch64.sh --verify
cmake -S . -B build/arm64 -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-musl.cmake \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build/arm64 -j4
ctest --test-dir build/arm64 --verbose
scripts/test-host.sh
```

The toolchain cross-compiles `ts2_core`, the native tests and probe executables
as static `aarch64-linux-musl` binaries. Existing CTest entries automatically
invoke `scripts/campaign/arm64-run.sh` through CMake's cross-compiling emulator
support. Each invocation has a 60-second limit and propagates the guest exit
status; missing QEMU fails with a provisioning command. `--verbose` shows each
suite's command and result. Host and Android toolchains are unchanged.

Overrides: `TS2_HOST_TOOLCHAIN` selects the absolute Zig-wrapper directory at
configure time; `TS2_HOST_TOOLS` selects the QEMU provisioning root;
`TS2_QEMU_AARCH64` selects an existing emulator at test time. This is AArch64
instruction execution under Linux user-mode emulation, not Android, hardware,
original-game startup or Phase 1 acceptance.

### Synthetic loading integration artifact

`ts2_guest_loading_smoke` constructs a public PE32 fixture in memory, maps it at
`0xA0000000`, then runs checked-memory and loader/resolver policy checks in that
same address space. Three deterministic cases cover fallback retry, second-module
selection and export failure (which must not try another module), cache reentry,
missing-provider rejection and image isolation. Its providers are authored test
responses, not Windows services. PE code bytes remain data; no entry is executed.

After building both trees above:

```sh
ctest --test-dir build/host -R '^guest_loading_smoke$' --verbose
ctest --test-dir build/arm64 -R '^guest_loading_smoke$' --verbose
mkdir -p work/loading-smoke
build/host/ts2_guest_loading_smoke > work/loading-smoke/host.txt
scripts/campaign/arm64-run.sh build/arm64/ts2_guest_loading_smoke > work/loading-smoke/arm64.txt
cmp work/loading-smoke/host.txt work/loading-smoke/arm64.txt
```

Both executions must exit 0 and output must match; this is synthetic native
loading-policy integration, not an original recompiled function, Android startup,
an import/IAT binding or a real game menu.

### Native error-slot accessor (opt-in diagnostic ABI)

`GuestErrorSlotAbi` calls an explicitly bound cdecl provider and returns its
nonzero pointer plus 16 modulo 2^32, or a caller-configured fallback address on
null. It does not dereference either destination; wrapped zero is not the null
input branch. Integer flags, full stack and volatile-provider effects are checked
against the existing independent accessor oracle. No actual thread storage,
Windows service, automatic binding, FP/SEH or game startup is supplied. Failed
nested calls are not transactional. After building both trees:

```sh
python3 -m unittest discover -s tests -p test_error_slot_abi.py -v
TS2_GUEST_ERROR_SLOT_ABI_PROBE="$PWD/build/arm64/ts2_guest_error_slot_abi_probe" \
TS2_GUEST_ERROR_SLOT_ABI_RUNNER="$PWD/scripts/campaign/arm64-run.sh" \
  python3 -m unittest discover -s tests -p test_error_slot_abi.py -v
# Optional owner-only comparison: reads the existing pinned image, no recovery.
python3 tools/check_error_slot_abi.py --private-x86
python3 tools/check_error_slot_abi.py --private-x86 \
  --native build/arm64/ts2_guest_error_slot_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

The 160 cases per ISA compare all GPRs, defined flags (AF excluded only on the
null TEST path), full 4096-byte stack and provider return/SP trace. Missing or
lying providers, wrong cleanup, corrupt caller frames and bad stacks reject.
Only the stack is mapped in this probe. This is Linux/AArch64 under QEMU, not
Android/hardware. The standalone probe injects its provider; the nested experiment
below uses the existing-slot provider/selector/hot models. The six-body reference
is unchanged.

### Nested error-slot/provider hot ABI (diagnostic only)

`ts2_guest_error_provider_hot_abi_probe` nests the unchanged accessor, existing-slot
provider, selector and hot resolver models through exact-VA dispatch on one stack.
The independent four-body frame oracle checks all caller GPRs, defined flags,
full4096 stack, both immutable data pages, ordered external frames and last-error.
A storage all-ones value becomes provider null, hence fallback ADDRESS; a nonnull
`FFFFFFF0` wraps to zero through ADD, not fallback. No destination is dereferenced.

```sh
# After both native builds; bounded worker execution for long commands.
python3 -m unittest discover -s tests -p test_error_provider_hot_abi.py -v
TS2_GUEST_ERROR_PROVIDER_HOT_ABI_PROBE=build/arm64/ts2_guest_error_provider_hot_abi_probe \
TS2_GUEST_ERROR_PROVIDER_HOT_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_error_provider_hot_abi.py -v
# Optional existing pinned private image; no recovery, lift or new binding.
python3 tools/check_error_provider_hot_abi.py --private-x86
python3 tools/check_error_provider_hot_abi.py --private-x86 \
  --native build/arm64/ts2_guest_error_provider_hot_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

Private mode compares four original x86 bodies in one frame, not four separate
results. Get/SetLastError, guard and storage remain authored endpoints. Cold
allocation/resolution and unsupported bindings reject; failures are not
transactional. No mapper/release consumer, slot store, endpoint CPU snapshots,
transient-write trace, FP/SEH, Windows service, ownership/lifecycle/races/reentry,
IAT binding or startup is established. The probe is excluded from Android;
AArch64 Linux/QEMU is not Android/hardware or gameplay evidence.

### Checked native OS-error value policy

`legacy_map_os_error` reads an explicit 45-pair little-endian guest table and
returns the first exact match before unsigned interval fallbacks. Duplicate keys,
zero and all-ones values are legal; error zero has no implicit success meaning.
The full 360-byte table must be readable, even for an early match. Null, wrapping
and uncommitted spans reject without writes. Tables may be unaligned. Callers
must provide stable memory/single ownership; no table/global/IAT binding is
installed, and no private table is included in source.

```sh
# After both builds; use bounded worker execution for long checks.
python3 -m unittest discover -s tests -p test_os_error_policy.py -v
TS2_GUEST_OS_ERROR_PROBE=build/arm64/ts2_guest_os_error_probe \
TS2_GUEST_OS_ERROR_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_os_error_policy.py -v
# Optional owner-only pinned x86 comparison; table travels only through stdin.
python3 tools/check_os_error_policy.py --private-x86
python3 tools/check_os_error_policy.py --private-x86 \
  --native build/arm64/ts2_guest_os_error_probe \
  --runner scripts/campaign/arm64-run.sh
```

Public tests cover all 45 positions, duplicates, interval/unsigned edges and
transport corruption. The native probe verifies its entire mapped table pages
are unchanged. CTest `guest_os_error` adds missing/wrapping/partial tables,
page-crossing unaligned tables, the exact 4-GiB upper boundary and memory isolation.
Private mode additionally checks the original x86 body's complete integer state
against the existing independent oracle; only its result is compared to native.
This is a value policy, **not a CPU ABI differential**, original-body lift,
errno destination write, Windows service or release-chain integration. No startup,
Android, hardware or gameplay evidence is implied by Linux/AArch64/QEMU tests.

### Opt-in OS-error mapper integer ABI

`GuestOsErrorAbi` adds the `831A7A` cdecl integer caller contract to the checked
value policy above. The table remains explicit; no runtime binding is installed.
It models caller GPRs, defined arithmetic flags and final stack, including EBP
save and path-dependent scratch words. Stack/table overlap, incomplete frames
and invalid tables reject before mutation. Stable single-owner memory is required.

```sh
# After both native builds; use bounded worker execution for long commands.
python3 -m unittest discover -s tests -p test_os_error_abi.py -v
TS2_GUEST_OS_ERROR_ABI_PROBE=build/arm64/ts2_guest_os_error_abi_probe \
TS2_GUEST_OS_ERROR_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_os_error_abi.py -v
# Optional existing owner-only pinned image, no recovery/lift:
python3 tools/check_os_error_abi.py --private-x86
python3 tools/check_os_error_abi.py --private-x86 \
  --native build/arm64/ts2_guest_os_error_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

The comparator checks all eight GPRs, defined flags and the entire 4096-byte
stack against the unchanged independent mapper oracle; optional private mode also
checks the original x86 body. Input tables travel only through child stdin, not
arguments or reports. The batched transport avoids per-token stdio synchronization
and compares every table-page byte through checked 32-bit reads, retaining the
60-second child limit and full sweep. Native checks guard both table pages;
CTest adds invalid stack/table, overlap, unaligned and exact-4-GiB-end frame
checks. No errno slot
store, release consumer, transient-write trace, FP/SEH, thread/Windows service,
startup or Android integration is established. Linux/AArch64/QEMU is not Android
or hardware evidence.

### Opt-in release/error ABI composition (diagnostic only)

`GuestReleaseAbi` models the `8461B8` integer caller frame with explicit heap,
HeapFree/GetLastError slots, mapper and accessor targets. It installs no bindings
and provides no heap service. Null context and successful release bypass error
handling; failure maps last-error, gets a destination and performs a checked
32-bit store. HeapFree is stdcall12; mapper is cdecl1; other calls have no args.
Endpoint nonvolatile/frame preservation, stable single-owner memory and no
stack/layout/table/destination aliasing are caller obligations. Failures are not
transactional: earlier heap, endpoint, stack or register effects may remain;
destination readability/writability is checked only at store time.

```sh
# After both builds; bounded worker execution for long checks.
python3 -m unittest discover -s tests -p test_release_error_abi.py -v
TS2_GUEST_RELEASE_ERROR_ABI_PROBE=build/arm64/ts2_guest_release_error_abi_probe \
TS2_GUEST_RELEASE_ERROR_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_release_error_abi.py -v
# Optional existing pinned owner-only image, no recovery or lift:
python3 tools/check_release_error_abi.py --private-x86
python3 tools/check_release_error_abi.py --private-x86 \
  --native build/arm64/ts2_guest_release_error_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

The diagnostic composes the unchanged mapper, accessor and existing-slot provider
with an authored storage-query endpoint. The unchanged four-body release/error
oracle checks caller GPRs/defined flags, full4096 stack, both error slots, ordered
external frames and last-error restoration. Private mode additionally executes
four original x86 bodies together. Every other mapped non-stack word must remain
unchanged. No actual selector/hot resolver is nested in this experiment. Cold
allocation, missing bindings, wrong cleanup, bad stacks and unmapped destination
reject. No endpoint CPU snapshots, transient-write trace, FP/SEH, heap/thread
ownership/lifecycle/races/reentry, IAT binding, startup or Android integration is
established. AArch64 Linux/QEMU is not Android/hardware/gameplay evidence.

### Native release/error/selector/hot ABI composition (diagnostic only)

`ts2_guest_release_hot_abi_probe` nests six existing ABI models without changing
or binding them: release, mapper, accessor, existing-slot provider, selector and
hot resolver. The unchanged `heap_hot_composed_probe` oracle checks caller GPRs,
defined flags, full4096 stack, both error slots, cache words, ordered endpoint
and resolver-entry frames and final last-error. Other mapped non-stack words must stay unchanged.
HeapFree, Get/SetLastError, guard and storage remain authored endpoints, not OS
services. Dynamic FLS and tail TLS include the resolver's actual nested saves and
volatile effects; decoded zero still rejects cold initialization.

```sh
# After both builds; use bounded worker execution for long checks.
python3 -m unittest discover -s tests -p test_release_hot_abi.py -v
TS2_GUEST_RELEASE_HOT_ABI_PROBE=build/arm64/ts2_guest_release_hot_abi_probe \
TS2_GUEST_RELEASE_HOT_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_release_hot_abi.py -v
# Optional existing pinned owner-only x86 bodies; no recovery or lift:
python3 tools/check_release_hot_abi.py --private-x86
python3 tools/check_release_hot_abi.py --private-x86 \
  --native build/arm64/ts2_guest_release_hot_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

The sweep covers all32 cookie counts, both storage/destination paths, endpoint
volatile clobbers and null/success bypass. Private mode also runs six original
x86 bodies in one frame. Failure is not transactional; the release model's
single-owner/stable-layout/no-alias/provider contracts remain. No endpoint CPU
snapshots, transient writes, FP/SEH, cold allocation, heap/thread lifecycle,
ownership/races/reentry, IAT binding or startup is established. The probe is
excluded from Android; Linux/AArch64/QEMU is not Android/hardware/gameplay.

### Public lifted dispatch artifact

`ts2_guest_dispatch_smoke` binds **exact VA `0xA0001000`** to one compiled,
public authored MOV/ADD/RET leaf generated by pinned pcrecomp. Its narrow
fixture-only shim uses explicit register/memory parameters, checked 32-bit guest
memory, ADD flags and cdecl return-stack adjustment. Twelve cases cover carry,
overflow, parity, auxiliary carry and high-bit addresses. Unbound neighboring
VAs reject without state changes; invalid reads reject; peer memory is isolated.
This is not a general lifter adapter or an original Sims 2 function.

```sh
# Optional regeneration audit; requires already verified pinned upstream source.
python3 tools/generate_dispatch_fixture.py --pcrecomp \
  work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e --check
# After building both trees (no upstream source required for native compilation):
ctest --test-dir build/host -R '^guest_dispatch_smoke$' --verbose
ctest --test-dir build/arm64 -R '^guest_dispatch_smoke$' --verbose
python3 -m unittest discover -s tests -p test_guest_dispatch_smoke.py -v
TS2_GUEST_DISPATCH_SMOKE="$PWD/build/arm64/ts2_guest_dispatch_smoke" \
TS2_GUEST_DISPATCH_RUNNER="$PWD/scripts/campaign/arm64-run.sh" \
  python3 -m unittest discover -s tests -p test_guest_dispatch_smoke.py -v
```

The Python test compares all eight GPRs, full EFLAGS and a stack window against
bounded Unicorn x86-32 execution and an independent arithmetic oracle. Native
checks reject any other write in the committed stack page; the x86 oracle checks
its complete page. Transport mutation tests reject partial/duplicate streams and
changed registers/flags/bytes. This observes statically recompiled synthetic code
executing AArch64 instructions under QEMU Linux, **not Android or hardware**.
No x86 emulator is linked into the executable, and no game code is included.

### Private read-only dispatch experiment (optional owner fixture)

`ts2_readonly_dispatch_bridge` is **host-test infrastructure only**, not linked
into Android. It marshals nine integer state words across a C boundary into
`GuestDispatch`, copies bounded read-only spans into `GuestMemory`, and retains
logical span checks even when several spans share a committed page. Invalid
reads latch failure; state is published only on success. Nested calls reject.
No writes, OS services, general pcrecomp ABI or rollback of legacy globals is
provided. CTest `readonly_dispatch_bridge` exercises the bridge without game data.

The existing private three-function fixture can optionally be adapted without
changing its lifted bodies or saved cases. Preparation pins the documented source
hash and exclusively creates output under ignored `work/`. Missing inputs fail;
no substitute originals are fetched/generated. After building both native trees:

```sh
. scripts/campaign/worker-env.sh
D="$PWD/work/private-readonly-NEW" # use a new directory; never publish its contents
mkdir -m 700 "$D"
python3 tools/generate_dispatch_fixture.py --pcrecomp \
  work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e --check
python3 tools/prepare_private_readonly_dispatch.py --output "$D/group.c"
for isa in host arm64; do
  opts=(); [ "$isa" = host ] || opts=(-target aarch64-linux-musl -static)
  zig-cc "${opts[@]}" -D_POSIX_C_SOURCE=200809L -std=c11 -O0 -Itools \
    -Iwork/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/runtime/recomp32 \
    -c "$D/group.c" -o "$D/$isa.o" || break
  zig-cxx "${opts[@]}" "$D/$isa.o" \
    "build/$isa/libts2_readonly_dispatch_bridge.a" "build/$isa/libts2_core.a" \
    -lm -o "$D/$isa-private" || break
  if [ "$isa" = host ]; then
    "$D/$isa-private" > "$D/$isa.txt"
  else
    scripts/campaign/arm64-run.sh "$D/$isa-private" > "$D/$isa.txt"
  fi
  python3 tools/check_private_readonly_dispatch.py \
    --reference work/interop-legacy-002/group-bundle/reference.json \
    --stdout "$D/$isa.txt" || break
done
cmp "$D/host.txt" "$D/arm64.txt"
```

Run long jobs with the documented bounded worker execution path. The comparator
pins the pre-existing 96 saved x86 states and prints counts only; this is not a
fresh x86 execution or full-game validation. Legacy globals/flag helpers and
undefined-flag normalization remain fixture-specific. No game code or states
are included in Git. AArch64 Linux/QEMU results are not Android/hardware results.

### Scoped nested-call/write bridge (public authored contract)

`ts2_scoped_dispatch_bridge` is separate diagnostic-only infrastructure, excluded
from Android. Unlike the read-only bridge, it supports explicit nested exact-VA
calls sharing one copied `GuestMemory` transaction. Each output span is an explicit
write permission; stores outside it (including same-page gaps and crossing its
end) latch failure. An ordered journal records every 32-bit store's address,
before and after values, including unchanged/overlapping stores. Limits are eight
active calls, 64 total calls and 256 stores. No automatic x86 CALL/RET/flags effects
are supplied: the authored callbacks explicitly implement their tested ABI.

```sh
# After the host and AArch64 builds above:
ctest --test-dir build/host -R '^scoped_dispatch_bridge$' --verbose
ctest --test-dir build/arm64 -R '^scoped_dispatch_bridge$' --verbose
```

The test covers ten **authored**, non-lifted cache-wrapper cases, explicit nested
cdecl stack cleanup, full integer state, final memory and ordered writes, plus
fault/budget/exception/reentry rejection and recovery. On failure no caller state,
output buffers or report is published. This is a trusted-fixture interface, **not
a sandbox**: host buffers must be valid/nonaliasing; callbacks must use the API,
return normally and have no external effects. Callback globals are not rolled back.
See `tools/scoped_dispatch_bridge.h` for the full contract. No private wrapper,
x86 differential, general lifter, OS callback or game-runtime integration is
validated by this public test; existing read-only behavior is unchanged.

### Existing private cache fixture through scoped dispatch (optional)

`tools/prepare_private_scoped_dispatch.py` adapts only the previously validated,
hash-pinned 64-case cache fixture. No recovery, PE execution or additional lift
occurs. Two explicit store sites and stack/call macros are adapted; other lifted
instructions and saved case data are retained. Nested calls go through exact-VA
`GuestDispatch`, not direct C calls. Only the selected four-byte cache and declared
stack span allow writes; the handle and other outer bytes remain read-only.
Every case also checks call counts and the complete ordered store journal against
explicit stack/cache expectations, including unchanged stores.

```sh
# After building both trees; run with the bounded worker execution path.
. scripts/campaign/worker-env.sh
D="$PWD/work/private-scoped-NEW" # new private directory, never publish
mkdir -m 700 "$D"
python3 tools/generate_dispatch_fixture.py --pcrecomp \
  work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e --check
python3 tools/prepare_private_scoped_dispatch.py --output "$D/wrapper.c"
for isa in host arm64; do
  opts=(); [ "$isa" = host ] || opts=(-target aarch64-linux-musl -static)
  zig-cc "${opts[@]}" -D_POSIX_C_SOURCE=200809L -std=c11 -O0 -Itools \
    -Iwork/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/runtime/recomp32 \
    -c "$D/wrapper.c" -o "$D/$isa.o" || break
  zig-cxx "${opts[@]}" "$D/$isa.o" \
    "build/$isa/libts2_scoped_dispatch_bridge.a" "build/$isa/libts2_core.a" \
    -lm -o "$D/$isa-private" || break
  if [ "$isa" = host ]; then
    "$D/$isa-private" > "$D/$isa.txt" || break
  else
    scripts/campaign/arm64-run.sh "$D/$isa-private" > "$D/$isa.txt" || break
  fi
  python3 tools/check_private_scoped_dispatch.py \
    --reference work/interop-legacy-002/wrapper-bundle/reference.json \
    --stdout "$D/$isa.txt" || break
done
cmp "$D/host.txt" "$D/arm64.txt"
python3 -m unittest discover -s tests -p test_private_scoped_dispatch.py -v
```

Missing private inputs fail explicitly. The comparator pins all 64 pre-existing
saved x86 states (eight registers, flags, FP transport and full memory deltas),
not a fresh x86 run. Legacy lazy flags, undefined-AF normalization, global state
and the macro ABI remain fixture-specific. Failure may modify legacy globals;
no concurrency, ownership, OS callbacks or general lifter integration is claimed.
This diagnostic-only experiment is not linked into Android and does not establish
startup, rendering, gameplay, Android execution or hardware behavior.

### Private release/error/storage composition (development only)

`tools/heap_storage_composed_probe.py` executes five existing pinned original
bodies in one bounded Unicorn x86 reference context: release, error mapping,
error-slot accessor, existing-slot provider and storage-query selector. It checks
all integer registers, defined flags, the full stack page, both error slots,
external call frames and last-error restoration against an independent oracle.
The selector's dynamic provider uses a nested frame; its TLS fallback tail-jumps
with the provider caller's frame. With non-clobbering authored APIs, the dynamic
selector leaves its target in ECX rather than the earlier mapper caller's error
value; last-error is still restored. Resolver and storage endpoints remain authored
contracts, **not** Windows services. Actual resolver `0x847E6C` is not replaced by
`0x82A212`. Lazy allocation rejects; nothing is bound into the shipped runtime.

```sh
. scripts/campaign/worker-env.sh
# Run private commands via the bounded worker execution path; logs stay in work/.
python3 tools/heap_storage_composed_probe.py
python3 -m unittest discover -s tests -p test_heap_storage_composed_probe.py -v
```

The optional private command requires the existing hash-pinned analysis image;
it does not recover or generate missing originals. Public tests use only authored
x86 fixtures. Neither command validates an actual heap, encoded resolver, FLS/TLS
ownership, ARM64 translation, Android startup, rendering or gameplay.

### Actual encoded resolver hot-cache reference (development only)

`tools/encoded_cache_probe.py` checks the actual `0x847E6C` resolver's cached
paths against an independent 32-bit rotate/XOR and full-state oracle. It does
not substitute the different `0x82A212` resolver. A decoded all-ones sentinel
returns zero; decoded zero requires unresolved cold initialization and rejects.
Cookie rotation counts, high-bit values and selected cache indices are covered.
Every integer register, defined flag, full stack page and final immutable page
is checked. Cold helpers/APIs are not implemented, executed or bound to runtime.

```sh
. scripts/campaign/worker-env.sh
# Private command: use the bounded worker path; output/logs stay under work/.
python3 tools/encoded_cache_probe.py
python3 -m unittest discover -s tests -p test_encoded_cache_probe.py -v
```

The optional `--index` argument accepts an existing private Ghidra JSON query
and cross-checks all 56 instruction boundaries/mnemonics (not operand semantics).
The image hash is pinned; missing private input fails without reconstruction.
Public tests use only authored fixtures. This is x86 development evidence, not
ARM64 translation, a Windows storage service, game startup or Android gameplay.

### Actual cold module-acquisition reference (development only)

`tools/module_acquisition_probe.py` checks resolver dependency `0x847DA1`
against an independent module-selection/publication oracle. Unlike the earlier
`0x82A2B2` helper, its error-87 fallback requires **two** nonzero prefix
comparisons before retrying a load without flags. Failed module attempts publish
all-ones and continue through the supplied index range; cached failures skip,
while the first usable module stops selection. APIs/comparisons remain authored
responses, not Windows services. No concurrent publication or ownership is tested.

```sh
. scripts/campaign/worker-env.sh
# Private command: bounded worker execution path, logs under ignored work/.
python3 tools/module_acquisition_probe.py
python3 -m unittest discover -s tests -p test_module_acquisition_probe.py -v
```

The optional `--index` accepts the existing private Ghidra query and compares
74 boundaries/mnemonics, not operand semantics. The reference checks values,
module-page publication, nonvolatile registers, caller stack, external call
arguments/frames and final immutable pages. It does **not** compare the entire
scratch stack, flags or volatile registers. Public tests use authored fixtures;
missing pinned input fails. No game code is included or bound to Android; this
is not ARM64 translation, startup, menu or gameplay evidence.

### Actual cold encoded-resolver composition (development only)

`tools/encoded_resolver_composed_probe.py` executes actual resolver `0x847E6C`,
module acquisition `0x847DA1`, and encoder `0x82F3EC` together in bounded x86
reference memory. An independent oracle checks module selection, ordered external
call frames, encoded publication and export-failure stop. Same-memory reentry
removes the candidate/name/IAT pages and checks the full hot-path integer state,
defined flags and stack against the existing independent hot-cache oracle.

```sh
. scripts/campaign/worker-env.sh
# Private command: bounded detached worker execution, logs under ignored work/.
python3 tools/encoded_resolver_composed_probe.py
python3 -m unittest discover -s tests -p test_encoded_resolver_composed_probe.py -v
```

The optional `--encoder-index` takes a cached private Ghidra query and checks
13 encoder boundaries/mnemonics, not operands. Public tests use authored x86;
missing pinned private input fails. Load/error/export APIs and both comparisons
remain authored responses. Cold checks cover nonvolatile registers, caller stack,
final immutable pages and the complete module/cache page, **not** volatile
registers, flags, full scratch stack or transient writes. Export responses exclude
all-ones, which is reserved for cache failure. No races/FreeLibrary ownership,
SEH, real storage/heap service, native translation or Android integration is proven.
The older `0x82A212`/`0x82A2B2` pair is not substituted.

### Checked native encoded-resolver policy

`legacy_resolve_encoded` in `native/src/guest_encoded_resolver.cpp` is a separate
value/cache policy for the actual `847E6C`/`847DA1`/`82F3EC` contracts above.
It does not replace the older `legacy_resolve_two` policy. Caller-supplied cookie
and function-word addresses plus an explicit materialized candidate range avoid
inferred globals/IAT bindings. Cold cache initializes to `encode(0,cookie)`.
Hot paths ignore candidates/providers; cold failures publish encoded all-ones.
Both length-seven prefix vetoes apply before an error-87 retry. Export failure
stops selection. Missing providers throw, and reserved all-ones provider responses
reject. No OS service, original-body translation, CPU ABI, races, ownership,
recursive resolution, rollback or game integration is provided.

```sh
# Build both trees as above. Run long checks via the bounded worker path.
ctest --test-dir build/host -R '^guest_encoded_resolver$' --verbose
ctest --test-dir build/arm64 -R '^guest_encoded_resolver$' --verbose
python3 -m unittest discover -s tests -p test_encoded_resolver_policy.py -v
# Optional private reference checks require the existing pinned image:
python3 tools/check_encoded_resolver_policy.py --private-x86
python3 tools/check_encoded_resolver_policy.py --private-x86 \
  --native build/arm64/ts2_guest_encoded_resolver_probe \
  --runner scripts/campaign/arm64-run.sh
```

The authored transport compares ordered API/comparison requests, result, module
words, encoded publication and same-memory hot reentry, and guards neighboring
memory. Private mode executes the existing bounded x86 composition as well as
its independent oracle; public tests require no game input. Native policy does
**not** expose x86 registers/flags/stack, so this is not a CPU-state differential.
AArch64 Linux/QEMU execution is not Android or hardware validation. The candidate
range is materialized by the caller, not parsed from game tables.

### Checked native storage-selector composition

`legacy_query_storage` in `native/src/guest_storage_selector.cpp` composes the
actual encoded-resolver policy with the value-level `0x8480BF` selection contract.
Callers supply the layout, candidate range, export name, index and explicit
`GuestStorageServices` endpoints. Nonzero resolution calls `check_target` then
`read_fls`; zero resolution calls `read_tls`. Zero/all-ones storage values are
returned unchanged. Missing endpoints throw; guard/FLS failures never trigger TLS
fallback. Resolver publication survives endpoint exceptions. Only the function
address is cached, not storage values. No guest VA is cast to a host function.

```sh
ctest --test-dir build/host -R '^guest_storage_selector$' --verbose
ctest --test-dir build/arm64 -R '^guest_storage_selector$' --verbose
python3 -m unittest discover -s tests -p test_storage_selector_policy.py -v
# Optional private references (bounded detached execution for worker long jobs):
python3 tools/check_storage_selector_policy.py --private-x86
python3 tools/check_storage_selector_policy.py --private-x86 \
  --native build/arm64/ts2_guest_storage_selector_probe \
  --runner scripts/campaign/arm64-run.sh
```

The authored transport checks result, encoded publication, module word, ordered
resolver/guard/storage requests and same-memory hot reentry. Private mode executes
the existing pinned x86 resolver composition and selector **separately**, checking
each against its independent oracle; it does not execute a composed x86 frame or
compare native CPU state. Public tests need no private game input. This is not an
IAT/table binding, original-body translation, actual Windows FLS/TLS, guard ABI,
thread storage/lifecycle/ownership, lazy allocation, SEH, races or startup. The
resolver's stable-cookie/single-caller/nonmutating-provider preconditions remain.
AArch64 Linux/QEMU is not Android or hardware validation.

### Opt-in storage-selector integer ABI model

`GuestStorageAbi::invoke` is a separate bounded model of the `8480BF` caller
contract, using checked guest stack writes and exact-VA dispatch for the resolver,
guard and FLS/TLS endpoints. Resolver cleanup is cdecl; storage cleanup is
stdcall4. The TLS fallback receives the original caller frame (tail dispatch),
while FLS receives a nested frame after guard validation. Missing endpoints,
wrong cleanup and endpoint exceptions stop without TLS fallback or rollback.
No automatic binding is installed; all layout/endpoint addresses are explicit.

```sh
# After building both trees; long checks use the bounded worker execution path.
python3 -m unittest discover -s tests -p test_storage_abi.py -v
TS2_GUEST_STORAGE_ABI_PROBE=build/arm64/ts2_guest_storage_abi_probe \
TS2_GUEST_STORAGE_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_storage_abi.py -v
python3 tools/check_storage_abi.py --private-x86
python3 tools/check_storage_abi.py --private-x86 \
  --native build/arm64/ts2_guest_storage_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

Public tests compare 256 cases against the existing independent selector oracle:
all eight caller GPRs, defined flags, entire 4 KiB stack and ordered endpoint
frames/ECX. Private mode additionally compares the existing pinned original x86
selector, not a composed resolver/selector frame. The resolver and storage APIs
remain authored endpoints. This is an authored ABI model, **not** a pcrecomp lift,
complete endpoint-register differential, Windows storage, IAT wiring, SEH,
thread/lifecycle support or startup. Endpoints must not mutate saved/caller stack
or layout and must honor the documented nonvolatile/guard contract. AArch64
Linux/QEMU is not Android/hardware/gameplay evidence.

### Opt-in encoded-resolver hot-cache integer ABI

`GuestEncodedHotAbi::invoke` models only the actual `847E6C` cached return
contract with an explicit cookie address and 64-word function-table base. It
uses checked guest memory and the existing rotate/XOR policy primitive. Decoded
zero requires cold initialization and throws **before mutation**, rather than
calling the value-level cold policy with an invented CPU ABI. Invalid index,
stack/cache overlap, missing memory and stack bounds also reject. No binding is
installed. The caller supplies a stable cookie/cache and a single execution owner.

```sh
# After both native builds; long checks use the bounded worker execution path.
ctest --test-dir build/host -R '^guest_encoded_hot_abi$' --verbose
ctest --test-dir build/arm64 -R '^guest_encoded_hot_abi$' --verbose
python3 -m unittest discover -s tests -p test_encoded_hot_abi.py -v
TS2_GUEST_ENCODED_HOT_ABI_PROBE=build/arm64/ts2_guest_encoded_hot_abi_probe \
TS2_GUEST_ENCODED_HOT_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_encoded_hot_abi.py -v
# Optional pinned owner-only original x86 hot-path comparisons:
python3 tools/check_encoded_hot_abi.py --private-x86
python3 tools/check_encoded_hot_abi.py --private-x86 \
  --native build/arm64/ts2_guest_encoded_hot_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

The public sweep checks 1,332 cases against the existing independent hot-cache
oracle: eight GPRs, defined flags, complete 4 KiB stack and both immutable data
pages. CTest additionally checks page-end hot arguments (cold name/range arguments
unmapped), lower-page saved-frame rejection and memory isolation. AF is undefined
and excluded; other unobserved CPU state is not claimed. This authored model is
**not** an original-body lift, composed resolver/selector frame, IAT binding,
cold CPU ABI, Windows service, SEH/thread lifecycle or startup. AArch64 Linux/QEMU
execution is not Android/hardware/gameplay evidence.

### Composed selector + hot resolver reference (development only)

`tools/storage_hot_composed_probe.py` runs the actual `8480BF` selector and
`847E6C` hot resolver in one bounded x86 context, with an independent composed
frame oracle. It checks every caller GPR, defined flags, all 4 KiB of stack,
immutable cookie/cache pages, and complete integer/defined-flag snapshots at
resolver entry and guard/FLS/TLS endpoints. The fallback sees the resolver's
rotation count in ECX and decoded failure sentinel in EDX; it is not equivalent
to the earlier opaque resolver endpoint. Guard and storage remain authored
contracts (preserving flags, optional storage ECX/EDX clobbers), not Windows APIs.

```sh
. scripts/campaign/worker-env.sh
python3 -m unittest discover -s tests -p test_storage_hot_composed_probe.py -v
# Optional pinned owner-only reference; long jobs use the bounded worker path:
python3 tools/storage_hot_composed_probe.py
```

Optional `--selector-index` / `--hot-index` reuse existing private Ghidra JSON
queries for boundary/mnemonic checks, not operand semantics. The private sweep
covers 3,456 cases; public tests use independently authored path-specific bodies,
not game bytes. Cold initialization, unresolved exports, wrong cleanup, changed
immutable pages and budget exhaustion reject. No cold ABI, native composition,
transient-write trace, IAT binding, storage ownership/lifecycle, SEH, race/reentry,
startup, Android or gameplay is validated. The native ABI models remain isolated.

### Native selector + hot-resolver ABI composition (diagnostic only)

`ts2_guest_storage_hot_abi_probe` composes the existing `GuestStorageAbi` and
`GuestEncodedHotAbi` models through exact-VA dispatch, without changing either
model or installing any runtime binding. Guard and storage are authored endpoints.
The shared guest stack retains nested resolver saves; the TLS tail path observes
resolver ECX/EDX rather than an opaque value-only resolver response.

```sh
# After both native builds; long jobs use the bounded worker execution path.
python3 -m unittest discover -s tests -p test_storage_hot_abi.py -v
TS2_GUEST_STORAGE_HOT_ABI_PROBE=build/arm64/ts2_guest_storage_hot_abi_probe \
TS2_GUEST_STORAGE_HOT_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_storage_hot_abi.py -v
# Optional existing pinned owner-only x86 bodies (not fetched or regenerated):
python3 tools/check_storage_hot_abi.py --private-x86
python3 tools/check_storage_hot_abi.py --private-x86 \
  --native build/arm64/ts2_guest_storage_hot_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

Each native sweep compares 3,456 cases against the existing independent composed
oracle: caller GPRs/defined flags, full stack and both immutable data pages, and
complete integer/defined-flag snapshots at resolver/guard/FLS/TLS entry. Private
mode also compares the two actual original x86 bodies in one reference context.
Public tests reject cold resolution, unresolved targets, missing bindings, wrong
cleanup, endpoint exceptions and invalid stacks, and mutate observed components
and transport. Decoded zero still throws: no cold CPU ABI is inferred from the
value-level policy. Failure is not transactional; selector frame writes may
remain. No original-body lift, transient-write trace, FP/SIMD/SEH, Windows storage,
lifecycle/ownership/races/reentry, IAT binding or startup is established. This
probe is excluded from Android; Linux/AArch64/QEMU is not Android or hardware.

### Existing-slot provider + selector + hot-resolver reference

`tools/provider_hot_composed_probe.py` executes the three actual pinned original
bodies (`84601E`, `8480BF`, `847E6C`) together in bounded development-only x86
memory. Its independent oracle checks all caller GPRs, defined flags, full 4 KiB
scratch stack, both immutable data pages, ordered external call frames and
last-error restoration. The index global shares the cookie page and is included
in the whole-page expectation. Nested resolver saves survive below the later
SetLastError frame. TLS retains count/sentinel ECX/EDX unless authored APIs clobber
them; dynamic FLS retains target/target. All-ones storage maps to a null result.

```sh
. scripts/campaign/worker-env.sh
python3 -m unittest discover -s tests -p test_provider_hot_composed_probe.py -v
# Optional existing pinned owner-only reference; bounded worker execution path:
python3 tools/provider_hot_composed_probe.py \
  --provider-index work/phase1-run3-045/provider.json
```

The index option reuses the private persistent Ghidra result (67 provider
boundaries/mnemonics, not operands). Public tests use independently authored,
path-specific fixtures, not game bytes. Cold allocation, all-ones index,
decoded-zero resolver, unknown target, wrong cleanup and budgets reject. Get/Set,
guard and storage remain authored contracts, not Windows services. This checks
caller integer state and endpoint frames, **not** complete endpoint CPU snapshots,
transient writes, native provider translation, FP/SIMD/SEH, thread storage
ownership/lifecycle, startup or Android gameplay. Existing native models and
Android wiring are unchanged; no new IAT binding or original-body lift occurs.

### Native existing-slot provider ABI composition (diagnostic only)

`GuestExistingProviderAbi::invoke` models the existing-slot `84601E` integer
caller contract with explicit index/Get/Set slots and exact-VA selector dispatch.
`ts2_guest_provider_hot_abi_probe` composes it with the unchanged selector and
hot resolver models. Get/SetLastError, guard and storage are authored endpoints,
not Windows services. All-ones storage maps to null; all-ones index, null storage
and decoded-zero resolver throw rather than inventing a cold allocation ABI.
No binding is installed. Failures can leave stack/register/endpoint effects;
last-error restoration is guaranteed only for successful calls.

```sh
# Build both native trees above; long checks use the bounded worker path.
python3 -m unittest discover -s tests -p test_provider_hot_abi.py -v
TS2_GUEST_PROVIDER_HOT_ABI_PROBE=build/arm64/ts2_guest_provider_hot_abi_probe \
TS2_GUEST_PROVIDER_HOT_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_provider_hot_abi.py -v
# Optional existing pinned original x86 bodies, not fetched or regenerated:
python3 tools/check_provider_hot_abi.py --private-x86
python3 tools/check_provider_hot_abi.py --private-x86 \
  --native build/arm64/ts2_guest_provider_hot_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

Each sweep compares 6,912 cases against the existing independent three-body
oracle: caller GPRs/defined flags, full4096 stack, both immutable4096 data pages,
ordered endpoint arguments/return-RVAs/SP and final last-error. Private mode also
compares the three original x86 bodies in one frame. Endpoint CPU snapshots,
transient writes, FP/SIMD/SEH, thread storage/lifecycle/ownership/races/reentry,
original-body lifting, IAT binding and startup are not established. The probe
is excluded from Android. AArch64 Linux/QEMU is not Android or hardware evidence.

### Opt-in lazy-provider integer ABI (diagnostic only)

`GuestLazyProviderAbi` separately models the `84601E` NULL-storage/invalid-index
slow frame. The existing-slot model is unchanged and still rejects cold paths.
Explicit setter, object allocator (`849A00`, NOT index allocation), initializer
and release targets dispatch through checked guest memory. All-ones index skips
query but still attempts a sentinel write. Allocation/publication failure clears
storage before release; success publishes before initialization and releases
NULL, not the new object. Newly allocated all-ones is not normalized to null.
Endpoints remain authored responses, not actual storage/heap/Windows services.

```sh
# After both native builds; bounded worker execution for long checks.
python3 -m unittest discover -s tests -p test_lazy_provider_abi.py -v
TS2_GUEST_LAZY_PROVIDER_ABI_PROBE=build/arm64/ts2_guest_lazy_provider_abi_probe \
TS2_GUEST_LAZY_PROVIDER_ABI_RUNNER=scripts/campaign/arm64-run.sh \
  python3 -m unittest discover -s tests -p test_lazy_provider_abi.py -v
# Optional existing owner-only pinned image, no recovery or lift:
python3 tools/check_lazy_provider_abi.py --private-x86
python3 tools/check_lazy_provider_abi.py --private-x86 \
  --native build/arm64/ts2_guest_lazy_provider_abi_probe \
  --runner scripts/campaign/arm64-run.sh
```

The unchanged slow-path oracle checks all GPRs, flags under its `0xCC5` mask
(AF excluded), full4096 stack, ordered endpoint arguments/return-RVAs/SP and
final last-error for648 cases.
The probe guards its entire non-stack layout page; no object/locale pointer is
dereferenced. Private mode also checks the original x86 provider in one frame;
selector/setter/allocator/init/release remain injected endpoints. Thirty-six bytes
of readable scratch below SP plus the return word are required. Stable layout,
single-owner/no-alias memory and endpoint nonvolatile/flag/frame preservation
are caller obligations. Nonzero existing storage rejects after query. Failures
are not transactional and need not restore last-error. No endpoint CPU snapshots,
transient writes, FP/SEH, actual services, lifecycle/ownership/races/reentry,
IAT binding, original-body lift, startup or Android/gameplay is established.
The diagnostic probe is excluded from Android; AArch64 Linux/QEMU is not hardware.

### Release/error path with actual hot resolver (development only)

`tools/heap_hot_composed_probe.py` extends the older five-body reference without
changing it: release, error mapper, error-slot accessor, existing-slot provider,
selector and actual hot resolver execute in one bounded private x86 context.
The independent oracle checks caller GPRs/defined flags, all4096 stack bytes,
both writable error slots, ordered external frames and final last-error. Every
other byte of every mapped non-stack page must remain unchanged, including the
cookie/cache pages that also contain heap/index/fallback globals. Resolver saves
at SP-64/-68/-72 survive the later SetLastError frame. TLS exposes resolver
count/sentinel ECX/EDX unless authored APIs clobber them, not opaque-query scratch.

```sh
. scripts/campaign/worker-env.sh
python3 -m unittest discover -s tests -p test_heap_hot_composed_probe.py -v
# Optional pinned owner-only x86 reference; use the bounded worker path:
python3 tools/heap_hot_composed_probe.py
```

Public tests use authored path-specific bodies, not original bytes. HeapFree,
Get/SetLastError, guard and storage are authored endpoints, not Windows services.
Null context and successful release bypass storage; failure writes the mapped
error to PTD+16 or the fallback slot. Cold allocation/resolution, unknown targets,
wrong cleanup, changed immutable neighbors and execution budgets reject. No
native translation/comparison, endpoint CPU snapshots, transient-write trace,
FP/SEH, heap/thread ownership/lifecycle/races/reentry, IAT binding, startup,
Android or gameplay is established. Existing native models remain unchanged.

## Android build

Install a **full JDK 17+**, Android SDK command-line tools and these exact components:

```sh
sdkmanager 'platforms;android-35' 'build-tools;35.0.0' \
  'ndk;27.2.12479018' 'cmake;3.31.6' 'platform-tools'
export ANDROID_HOME=/path/to/android-sdk
export JAVA_HOME=/path/to/jdk-17
scripts/build-android.sh --no-daemon
```

Gradle wrapper 8.13 and AGP 8.9.1 are pinned; the wrapper verifies its distribution
SHA-256. First build requires network access and SDK license acceptance through
the standard SDK tools. The app targets/compiles API 35, supports API 26+, and
packages only `arm64-v8a`. No game data or upstream recompiler is needed for this APK.
Optional `android/local.properties` can specify `sdk.dir=/path/to/android-sdk`.

Output: `android/app/build/outputs/apk/debug/app-debug.apk` (ignored by Git).

```sh
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n org.ts2native.diagnostic/.MainActivity
adb logcat -s TS2Native
```

These are device test instructions, not commands claimed to have succeeded here.
Run the [M1 checklist](ROADMAP.md) on the Thor or another actual ARM64 device.
The app uses a native software diagnostic surface; Vulkan game rendering, native
audio/video and the game OS runtime are not yet implemented.

## Supply and inspect your installation

On Steam use **Properties → Installed Files → Browse**, then copy/archive the game
installation folder. Do not include credentials, Steam Guard codes or original
saves. Extract your own files to ignored `game-files/` or point at another location:

```sh
python tools/analyze_install.py --install '/path/to/game' --output work/install.json
# Or set TS2_INSTALL and omit --install.
```

Reports never enable execution. Outputs must be new paths in `work/` and cannot
be written inside the selected installation. Symlinked scan entries are skipped.
The Android Game files tile opens a document-tree picker and scans the selected
tree; it does not yet copy assets or make them usable by game code.

For a ZIP upload, preview and stage only the analysis binaries first:

```sh
python tools/archive_intake.py '/path/to/game.zip' --report work/archive-preview.json
python tools/archive_intake.py '/path/to/game.zip' --extract-binaries game-files/analysis-001
python tools/analyze_install.py --install game-files/analysis-001 --include-dlls \
  --output work/binaries-001.json
```

This leaves the original archive and resource payloads untouched. See
[ARCHIVE_INTAKE.md](ARCHIVE_INTAKE.md) for limits, CRC/hash semantics and partial
extraction handling. Named/ordinal/delay imports include guest IAT addresses; TLS
callback lists are bounded and never executed.

After the host build, inspect a local package with the native reader:

```sh
build/host/ts2_dbpf_probe '/path/to/example.package'
# Optional TYPE GROUP INSTANCE arguments write one decoded payload to stdout.
# Keep any redirected proprietary payload inside ignored work/.
```

Read [RESOURCES.md](RESOURCES.md) for format limits, independent decoder
verification and the Android package-probe device checklist.

## Recompilation experiment

```sh
UPSTREAM=$(python tools/fetch_pcrecomp.py)
RECOMP_CC="$PWD/scripts/cc-with-libm.sh" python "$UPSTREAM/tools/lift/difftest.py"
python tools/recomp_probe.py --pcrecomp "$UPSTREAM" \
  --ndk "$ANDROID_HOME/ndk/27.2.12479018"
```

All dependency downloads/generated results remain under ignored `work/`. The
public leaf probe retains a narrow, verified stack-only memory contract and must
match the exact executable hash. The private original object-field helper used a
separate reviewed fixture; that gate was not relaxed. Read [RECOMPILATION.md](RECOMPILATION.md)
before using it. A full function catalog or game initialization is not implemented.
