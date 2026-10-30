# Architecture decision ADR-001 — 2026-10-21

Status: provisional Windows x86 static recompilation path; not a claim of game execution.

## Intent and first slice

Preserve the original PC simulation, resources, saves, and mod semantics in a native
ARM64 Android application with controller actions. No Wine, Box86, Winlator, runtime
x86 interpreter, or full system emulator is part of the product. Users supply their
own legitimate installation. Console Sims 2 is a different game and is out of scope.

This pass implements a diagnostic platform and a bounded lift experiment, not an
entire game port. Supplied game inputs remain ignored and local. The Legacy target
analysis is in [TARGET_LEGACY.md](TARGET_LEGACY.md); no game execution is claimed.

## Options and decision

| Path | Evidence and benefit | Cost / decision |
|---|---|---|
| A: Windows x86 → C | pcrecomp publishes lifters, differential tests, vtable/RTTI recovery. NFSU2 publishes an ARM64 Android memory/runtime and D3D9 bridge. Preserves the Windows PC code path and eventual UC scope. | Selected provisionally. Requires a version-specific function catalog, address translation, Win32/COM ABI adapters, SEH/TLS, and extensive validation. Existing 32-bit pointer runtimes cannot simply be compiled as ARM64. |
| B: Mac PPC → C | Linked author reports resource loading and menu on Apple Silicon. PPC endian/ABI and OpenGL paths could avoid D3D. | No publicly reusable Sims 2 source located in the inspected links/profile/search. Cannot base a build on unpublished code. Mac expansion coverage also differs from Windows UC. Revisit if source and license become available. |
| C: engine rewrite | OpenTS2 has resource loaders and basic neighborhood rendering; Las Marionetas documents PC ABI and engine interfaces. | Neither demonstrates independent full gameplay parity. Reimplementing the simulation is a larger preservation risk. Use as format/reference material subject to licenses. |

Selection is reversible until a bounded original function and import callback pass
host and ARM64 differential checks. No custom full recompiler or wholesale lift is
authorized by this technical decision. First use the existing pinned lifter.

## Supplied-target decision gate

Steam Legacy 1.18.0.187 confirms x86, D3D9 and high unsigned guest addresses, but
its SteamStub 3.x signatures and high-entropy code section establish a protected
input. The pinned tool's header-copy matcher does not support this loader.
The user approved a scoped interoperability experiment. Isolated metadata/code
recovery and one original helper's 64-case host comparison succeeded; ARM64
compilation passed but execution remains unverified. Retain path A; see
INTEROP_EXPERIMENT.md. Broader work requires further scope approval.
Other legitimately obtained releases remain alternatives. Do not lift wrapper
bytes as game progress or silently switch to a full rewrite.
The native DBPF/QFS reader is a host-verified resource slice with an Android
single-package diagnostic path (build only), not game initialization.

## Boundaries

```
Android Activity / SAF / IME / input / lifecycle
                     ↓
portable C++ action system / diagnostics / guest memory
                     ↓ (future, not connected today)
compiled game functions ↔ guest dispatch + OS services
                     ↔ D3D9 COM marshal → DXVK Native → Vulkan
                     ↔ audio/video services → AAudio / codec backend
                     ↔ virtual assets (read only) + separate save overlay
```

The Android M1 shell uses the platform Activity and JNI directly. Native C++ draws
a software diagnostic surface through ANativeWindow; Java supplies accessible text,
Storage Access Framework, device events, and the IME. This keeps the portable core
dependency-free and makes platform failures observable before graphics translation.
It is not the future game renderer. SDL3 remains a candidate for portable windowing,
audio and input, but adding a second event loop is unnecessary for this slice.

The current main/UI thread owns JNI input, state updates and drawing. Rendering
stops on pause/surface loss; input resets on focus loss and controller removal.
Future simulation and graphics threads must use explicit message queues, never
Java callbacks into a running guest while holding the guest-machine lock.

## 32-bit execution contract

Guest pointers are uint32_t values, never truncated host pointers. Guest memory is
a reserved 4 GiB data space on 64-bit hosts with host-page-size-aware commits and
checked ranges. Guest code pages are data and never receive executable permission.
The first implementation only exposes checked little-endian reads/writes; it is
not yet an upstream lifter memory adapter.

Indirect calls dispatch a guest VA through a registered function table and abort
with VA/register/stack diagnostics when unresolved. C++ vtables remain 32-bit guest
data. Host D3D objects use handle tables and guest-width COM vtables, with explicit
argument/result marshalling. A host 64-bit vtable is never copied into guest memory.

Each guest thread needs integer/x87/SSE/flags state, its own stack, FS/TEB, TLS,
last-error and callback context. Static TLS directory callbacks run before entry.
MSVC thiscall/stdcall/cdecl and stack cleanup must be preserved. SEH and C++ unwind
operate on guest records, not ARM C++ exceptions. x87 precision and undefined flags
require explicit policies and reference tests; instruction coverage is insufficient.

## Service replacements (planned)

| Guest interface | Native destination / unresolved work |
|---|---|
| Files, Win32 paths, registry install keys | virtual mount table with case-insensitive indexed lookups; read-only original assets and isolated writable save root |
| Threads, events, critical sections, atomics, timers | POSIX/C++ primitives and monotonic clock; preserve guest ordering, handles and timer units |
| User32 window/messages, cursor, DirectInput | application lifecycle + action adapter; focus-based UI requires verified game UI hooks later |
| D3D9 and COM | DXVK Native candidate; guest-width COM bridge, Android WSI, capability probing, device/surface loss and shader-cache handling needed |
| DirectSound / Miles / other sound middleware | determine actual imports first; AAudio/Oboe mixer adapter, not arbitrary success stubs |
| Bink / other video | inspect actual version/ABI and select licensed/native decoder; skip-video policy must be explicit |
| CRT, allocation, locale, exceptions | guest ABI compatible implementation; never expose host FILE*, pointers or va_list |

The table is an investigation plan, not an observed Sims 2 import census. Dynamic
LoadLibrary/GetProcAddress and delay imports must also be traced.

## Graphics decision gate

DXVK Native is a translation library without Wine, but is not a drop-in x86 DLL for
ARM64. The inspected NFSU2 adapter pins native-1.9.2b and adds ARM intrinsics, WSI,
guest COM and compressed texture fallback. Modern upstream DXVK Native exposes
SDL2/SDL3/GLFW WSI. Choose/pin a backend only after the target's D3D9 usage and
actual device Vulkan extensions, BC texture support and limits are measured.
AYN Thor Max is a validation target, not a performance claim. Test 16 KiB pages,
recreation, TV focus, thermals, and handheld controller axis layouts on hardware.

## Data and distribution

SAF retains a read grant; it does not promise a filesystem path. This pass scans a
selected tree and streams candidate executables for fingerprints, without copying
or executing them. A later importer must stage to app-private files atomically,
check free space and hashes, preserve relative paths, and support interrupted imports.
Saves live separately; originals must never be modified. Unknown executable hashes
are report-only and must not start game code. There is no automatic unpacking in
the importer or runtime. One explicitly approved private recovery/leaf experiment
is documented separately; new protected inputs need their own authorization and
validation. No recovered code is distributed with this foundation.

Generated C, raw bytes, memory dumps and analysis artifacts stay in ignored local
work directories. Shipping a user-specific compiled game/APK raises distribution
questions independent of the open-source runtime; this foundation includes no such
output. Native build caches and APKs must also be ignored.

## First-pass implementation sequence

1. Record source revisions, licensing and uncertainty; establish this decision.
2. Write portable controller/guest-memory tests; implement those small interfaces.
3. Add bounded PE/DBPF inspection, discovery and unknown-version reporting tests.
4. Add an ARM64 Gradle/CMake JNI shell, diagnostic renderer, hotplug, SAF and IME.
5. Run host tests, sanitizers, APK build/lint if SDK provisioning succeeds.
6. Run pinned pcrecomp on synthetic functions against an x86 reference; prepare a
   hash-pinned original-function probe, but do not claim original execution without input.
7. Review boundaries and record exact verification and remaining milestone gates.
