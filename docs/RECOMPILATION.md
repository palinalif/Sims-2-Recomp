# Binary analysis and recompilation

## Current evidence

The supplied Steam **Legacy Collection** is now analyzed: version 1.18.0.187,
x86 PE32, image base `0xA0000000`, 438 imports including D3D9. See
[TARGET_LEGACY.md](TARGET_LEGACY.md) for its exact hash, evidence and limits.
SteamStub 3.x entry and loader-signature matches identify the protection family.
The pinned parser's header-copy pattern does not support this particular loader.
The user approved the scoped experiment. Private metadata/code recovery and
64/64 host comparisons for one original helper succeeded; generated C compiled
for ARM64 without executing there. See [INTEROP_EXPERIMENT.md](INTEROP_EXPERIMENT.md).
No modified game image was launched and no broader development has begun.
`config/versions.json` recognizes the fingerprint with execution disabled and
`recompilation_ready=false`; the leaf tool rejects it before disassembly.
That fingerprint is still the wrapped original. The approved private image and
dedicated one-function fixture do not enable general execution in this registry.
Do not copy base-game/UC addresses or function catalogs into this edition.

Completed experiment: the pinned upstream pcrecomp `lift32` generated C for an
authored x86 leaf that reads two stack arguments, adds them, writes stack scratch
and returns. Five inputs include unsigned overflow and signed-boundary values.
Host-compiled C matched Unicorn for GPRs, defined arithmetic flags, stack changes
and memory writes. The same C cross-compiles into an Android ARM64 shared ELF.
**It has not run on ARM64 and is not Sims 2 code.** There is no game initialization,
game-rendered frame, Win32 runtime, or D3D translation connected to this application.

The separate upstream suite passed 372 cases. See [VERIFICATION.md](VERIFICATION.md)
for commands, environmental failures and practical limits.

## What to supply

- A legally obtained installed PC game directory, including its `TSBin` executable(s),
  DLLs and the `TSData` resource trees for the chosen edition/expansions.
- The supplied Steam build is fingerprinted. Another edition needs separate
  inspection and a compatible, unprotected code input. Other Steam account data,
  credentials, Steam Guard codes and saves are unnecessary for first analysis.
- Ideally include a note of edition, storefront, language, installed DLC and patch
  version. These are claims to cross-check against executable metadata.
- Keep original saves outside this workspace. Later use **copies** of Documents /
  EA Games / The Sims 2 (or the edition's corresponding user directory), with a
  separate backup before any save compatibility testing.

Do not supply pirated executables or redistribute recovered binaries. Protected
code recovery requires the user's explicit approval and applicable legal grounds;
the current scripts do not automatically unpack inputs. Document unsupported
wrappers and validate recovered code before any lifting.

## Read-only inspection

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r tools/requirements.txt
python tools/analyze_install.py --install '/path/to/installation' --output work/install.json
# Or use TS2_INSTALL=/path/to/installation and omit --install.
python tools/analyze_install.py --exe '/path/to/TSBin/Sims2.exe'
python tools/analyze_install.py --package '/path/to/example.package'
# Include middleware/engine DLL metadata, subject to count/byte limits:
python tools/analyze_install.py --install '/path/to/installation' --include-dlls
```

Executable reports include SHA-256, PE machine/optional-header magic, image base,
entry RVA, sections/entropy, version strings, large-address-awareness, direct and
delay imports with guest IAT addresses, bounded TLS callback arrays and parser warnings. The parser does not
unpack, load or execute the image. Directory scans skip symlinks and stop after
50,000 entries. Candidate names are case-insensitive `Sims2*.exe`; pass `--exe` for
other filenames. Candidate EXEs over 256 MiB are rejected. DBPF inspection only
checks header/index metadata and bounds. The native `ts2_dbpf_probe` separately
indexes DBPF 1.0/1.1 with index 7.0/7.1/7.2 and decodes the observed QFS variant.
Two compressed resources match an independent host decoder byte-for-byte; an
uncompressed PNG matches an independent index slice. See [RESOURCES.md](RESOURCES.md)
for bounds, unsupported variants and the Android single-package probe (build only).

For a large installation ZIP, [ARCHIVE_INTAKE.md](ARCHIVE_INTAKE.md) documents a
read-only preview and EXE/DLL-only staging path. Full resources need not be expanded
for the first binary analysis. All staged binaries remain ignored proprietary inputs.

Recognition of a hash is **not** permission to run it. Execution support remains
false even for future recognized versions until a specific runtime/catalog passes
its acceptance tests. Reports may contain local paths; keep them in ignored `work/`.

Android's Game files tile retains a read-only SAF tree grant and fingerprints up
to 64 candidate EXEs, with a 1 GiB total hashing budget. It writes only a private
diagnostic report. It counts packages, but does not import/copy an installation or
load game resources through that tree scan. A separate single-package document
picker invokes native decoding with strict input/output caps; it is not a full
installation importer. Providers may reject large/slow trees; those failures are
reported. A retained URI is not a native filesystem path.

## Target questions: do not infer answers from a filename

| Question | Evidence needed / next investigation |
|---|---|
| Executable/CPU/build/hash | Legacy 1.18.0.187 fingerprint recorded; protected-code blocker remains. Other editions require separate inspection. Reject XBE/DOL/console executables and mismatched CPU paths. |
| Rendering/shaders | Direct3DCreate9 confirmed. Inspect dynamic loader call sites. Identify shader bytecode, actual device caps and render-state usage in this build. |
| Audio/video/input | DirectSound ordinal 1, WINMM, VfW/AVI and VP6 observed. USER32/IMM32 input imports observed. Dynamic dependencies and runtime behavior remain unverified. |
| Resource loading | DBPF packages and QFS/RefPack codecs are documented in OpenTS2 source. Recover index versions, resource keys, expansion precedence and lazy-load behavior from this install. |
| Saves | Neighborhood/lot/Sim packages and user-directory references must be verified. Preserve IDs, resource ordering, serialization and custom content. Full save compatibility is untested. |
| Timing/threading | Trace monotonic/wall clock imports, sleeps, waits and thread entrypoints. Measure simulation ticks on an owned reference; never substitute render delta for game time. |
| Expansions | Enumerate all executable/resource roots, latest-engine selection, registry/install keys, file precedence and neighborhood migration logic. UC and Legacy are not interchangeable catalogs. |
| Mods | Packages/BHAV/SimAntics and GZCOM/native hooks require separate compatibility policies. Package mods may survive preserved semantics; x86 injected DLL mods cannot run as native ARM64 libraries. |

## Reproduce the bounded experiment

```sh
UPSTREAM=$(python tools/fetch_pcrecomp.py)
RECOMP_CC="$PWD/scripts/cc-with-libm.sh" python "$UPSTREAM/tools/lift/difftest.py"
python tools/recomp_probe.py --pcrecomp "$UPSTREAM" --ndk "$ANDROID_HOME/ndk/27.2.12479018"
```

The archive and four code/header inputs are SHA-256 pinned in
`config/dependencies.lock.json`. Upstream stays in ignored `work/deps/` with its
license. No patches are applied. The `-lm` workaround is a separate script.

`work/probe/result.json` records host/cross-compiler commands, reference and
differences. `leaf.c` and binaries are deliberately untracked. The experiment
reuses upstream's output protocol while capturing returned flags after the lifted
`ret`. It does not use the explicit-CPU lifter whose default pointers require a
32-bit host. Generated memory accesses still use upstream macros, not the checked
GuestMemory class; integrating those interfaces is a separate prerequisite.

## Smallest next original-code experiment

1. Inspect the supplied executable and identify an **unprotected**, manually
   reviewed, straight-line integer leaf with no imports/TLS/global state. Confirm
   entry/end and memory operands using a disassembler. Do not auto-sweep functions.
2. Extract only that bounded range, requiring its exact executable hash:

   ```sh
   python tools/probe_function.py --exe '/path/to/game.exe' --sha256 ACTUAL_SHA256 \
     --rva 0xACTUAL_RVA --size ACTUAL_SIZE --out work/original-leaf.json
   ```

3. `recomp_probe.py --probe work/original-leaf.json --exe '/path/to/game.exe'`
   rechecks the executable hash, range and bytes. Execution permits only plain
   `ret`, no other control flow/stack-pointer writes, and memory operands confined
   to stack offsets 4..15 with no segment/index register. Those three slots contain
   two arguments and scratch. **Use it only if that leaf has the matching reviewed
   memory/ABI contract.** Otherwise implement a dedicated checked fixture first.
   Compilation/execution have time limits. Compare
   a reference result, stack, callee-saved registers, defined flags and all writes.
4. Cross-compile, then execute on an actual ARM64 target and compare the same
   vectors. Follow with a small indirect call and a guest→host→guest callback.

The extraction tool restricts the first probe to 4 KiB, executable raw section
bounds and a limited instruction family ending in `ret`. This is not a proof of
safe or complete function recovery; review remains necessary. C generation without
a correct fixture is not an execution milestone.

## Before game startup

Need a closed function catalog (entry/exports/relocations/RTTI/vtables/address-taken
callbacks/jump tables), guest memory mapping and relocations, fail-closed dispatch,
import wrappers, guest allocators/CRT, TLS/TEB and exceptions, loader initialization,
thread ordering, path/registry data and rendering/audio service coverage. Packed
instructions or unsupported APIs must fail explicitly. Preserve unknown-call
traces locally and never return arbitrary success values to make startup advance.
