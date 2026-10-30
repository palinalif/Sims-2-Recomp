# The Sims 2 — Native Android Recompilation

**New code, old behaviour, proof by execution.**

A clean-room, from-the-executable-up reimplementation of the original PC
The Sims 2 engine in modern C++, built to run **natively on ARM64 Android**.
No emulation, no runtime x86 translation (Box86/Wine-class approaches are
explicitly out of scope), no original machine code in the result.

> ⚠️ **Honest status:** this is a long-horizon engineering project, not a
> playable game yet. 46 functions have survived full verification out of
> ~43,700 in the target binary. What exists today is the *machinery* — build
> system, differential-verification harness, and the process that makes every
> verified function provably correct — plus a diagnostic Android app that
> exercises parts of it on real devices.

## How it works

We do **not** translate x86 machine code to ARM64, and we do not recover the
original source code (it's gone). For each function:

1. **Hypothesise** — study the x86 binary (Ghidra as a discovery index;
   decompiler pseudocode is treated strictly as hypothesis).
2. **Re-implement** — write fresh, readable, idiomatic C++ expressing the
   observed *behaviour*.
3. **Prove** — execute the original function and the new implementation on
   real hardware (x86 reference vs ARM64 build) across many inputs. Outputs
   must match byte-for-byte. Only functions with receipts count.

Verification tiers (see [`docs/VERIFICATION.md`](docs/VERIFICATION.md)):
**T1** = full dual-ISA differential proof · **T3** = path-bounded/partial.
Everything ever proven lives in [`docs/VERIFIED_LEDGER.md`](docs/VERIFIED_LEDGER.md).

Correct-but-illegible is a failure state: the code aims to stay *readable*
beyond parity with the original, so the engine remains moddable. The full
contributor rules — including the claim system that keeps contributors from
colliding — are in [`AGENTS.md`](AGENTS.md). Read it before contributing.

## Setting up

### Path A — "Send this to an agent"

Give a capable coding agent this repository URL and the following prompt:

> Clone this repository and set my machine up to contribute. Read `README.md`
> and `AGENTS.md` completely first. Then: run `scripts/doctor.sh` and report
> what's missing; install the missing prerequisites (see README "Prerequisites"
> and "Pinned components"); create a Python venv and install
> `tools/requirements.txt`; run `scripts/test-host.sh` until it passes;
> optionally run `scripts/build-android.sh --no-daemon` if an Android SDK is
> configured. Commit nothing. Do **not** attempt to obtain, download,
> reconstruct, or "recover" the original game binaries or content — supplying
> those is the project owner's private step and is not needed for setup or for
> the vast majority of contributions.

Everything the agent needs is in this README and `AGENTS.md`. If
`scripts/test-host.sh` passes, the machine is useful to the project.

### Prerequisites

Any Linux/macOS box (Windows via WSL2); a plain x86_64 machine is enough to
start — contributions need **no GPU, no device, and no game files**.

- Git, Python 3.10+, CMake 3.31+, Ninja, a C++20 compiler
- Python deps: `python3 -m venv .venv && . .venv/bin/activate && pip install -r tools/requirements.txt`
- For the Android app only: a full **JDK 17+** (JRE insufficient; JDK 25 is
  unsupported by the pinned Gradle), Android SDK command-line tools,
  **NDK 27.2.12479018**, **platforms;android-35**, **build-tools;35.0.0**,
  SDK **cmake;3.31.6**
- Optional extras: an ARM64 Android device/emulator for on-device validation,
  and Zig 0.14.0 wrappers for the AArch64-under-QEMU regression lane
  (`docs/LOCAL_VALIDATION.md`)

### First build

```sh
git clone <this-repo-url> sims2-native && cd sims2-native
scripts/doctor.sh          # inventory of what you have / lack
scripts/test-host.sh       # cmake + ctest + python unit tests — the main gate
```

With sanitizers (CI runs this too):

```sh
cmake -S . -B build/sanitized -DTS2_SANITERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/sanitized --parallel
TS2_ASAN_WORKARROW= ctest --test-dir build/sanitized --output-on-failure
```

(Where ptrace blocks LeakSanitizer: `ASAN_OPTIONS=detect_leaks=0 ctest ...`.)

### Android app

```sh
sdkmanager 'platforms;android-35' 'build-tools;35.0.0' \
  'ndk;27.2.12479018' 'cmake;3.31.6' 'platform-tools'
export ANDROID_HOME=/path/to/android-sdk JAVA_HOME=/path/to/jdk-17
scripts/build-android.sh --no-daemon     # gradle assembleDebug + lint
```

Gradle wrapper 8.13 and AGP 8.9.1 are pinned; `android/local.properties`
(`sdk.dir=...`) is an acceptable alternative to `ANDROID_HOME`. Output:
`android/app/build/outputs/apk/debug/app-debug.apk` — a **diagnostic** app,
not the game. CI runs the same build on every PR
([`.github/workflows/build.yml`](.github/workflows/build.yml)).

### Pinned components, offline

For hermetic setups, `tools/install_android_ndk.py` and
`tools/install_android_sdk_package.py` install the exact pinned NDK r27c /
Platform 35 / build-tools / SDK-cmake from archives you download, verifying
Google's published size/SHA-1 plus locally measured SHA-256 before writing.
`scripts/android-env-probe.sh --sdk <path>` emits a JSON inventory of what an
SDK directory contains versus what this repo pins. Details in each tool's
`--help`.

### The original game binaries (project owners only)

Function-level reimplementation requires a locally supplied copy of the
*Steam Legacy Collection* build (`Sims2SP9.exe`) from your own legitimately
acquired installation. **No game binaries, DLLs, packages, saves, or assets
belong in this repository or any PR — a PR containing game content will be
closed.** See `docs/TARGET_LEGACY.md` for target facts and `AGENTS.md` for the
hard rules. Harness, tooling, build-system, and test contributions never need
game files at all.

## Contributing

1. Read [`AGENTS.md`](AGENTS.md) end to end — it defines the claim system
   (`docs/CLAIMS.md`) that keeps two contributors off the same function.
2. Pick an unclaimed function (skip everything in
   `docs/VERIFIED_LEDGER.md`), open a draft PR to claim it, branch
   `recomp/<rva>-<name>`, implement, and attach differential evidence.
3. Keep code readable: semantic names (with receipts in comments), idiomatic
   C++ over transliterated assembly, compiler-quirk adapters clearly labelled.

Good first reads: [`docs/RECOMPILATION.md`](docs/RECOMPILATION.md) (a
function's journey from binary to verified), `docs/VERIFICATION.md` (what
counts as proof), `scripts/recomp/README.md` (the harness),
`docs/ARCHITECTURE.md` (service boundaries), `docs/ROADMAP.md` (M0–M9 and the
current next tasks).

The deep-dive experiment records (ABI models, probe compositions, private
fixture instructions) moved to
[`docs/EXPERIMENT_LOG.md`](docs/EXPERIMENT_LOG.md) — they are evidence
archives, not setup docs.

## Ground rules

- **Clean room.** Behaviour is derived from executed observable inputs,
  disassembly, and differential evidence — never from leaked or otherwise
  unauthorised source code.
- **No game content in git.** Ever, in any form.
- **No emulation shortcuts in shipped code.** The deliverable is native ARM64.
- **Receipts or it didn't happen.** Claims without differential evidence are
  filed as hypotheses, not progress.
- **Readability is a feature.** Ship legible or don't ship.

## Licence

MIT (see `LICENSE`) for this repository's original code. `patches/pcrecomp/`
retains its upstream MIT notice; the pinned Gradle wrapper notices are under
`third_party/gradle/`. None of this grants any rights to EA's game, its
binaries, content, or trademarks — you supply your own legitimately acquired
copy. The Sims 2 and related trademarks belong to their respective owners.
