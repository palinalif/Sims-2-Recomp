# Local ARM64 and object-query validation — 2026-10-21

This follow-up was run on the owner's Windows machine from a fresh clone. Private
inputs, recovered code, generated C, binaries, full reference states and raw device
output remain under Git-ignored `work/`. No game executable was launched or changed.

## First original function on physical ARM64

The owner-provided `android-arm64-probe.zip` was extracted into ignored
`work/android-arm64-probe/`. Its local preflight reported `bundle_valid: true`,
64 cases and `arm64_executed: false`. Exactly one authorized USB device was visible
to ADB: a Samsung SM-S931B reporting AArch64, `arm64-v8a`, Android 16/API 36,
4 KiB pages and no known emulator properties. Device properties are self-reported.

`python work/android-arm64-probe/run_probe.py --serial <device serial>` returned
exit status 0. The saved private `result.json` reports `arm64_executed: true`,
`execution_attempted: true`, remote exit 0, `hardware_gate_passed: true`,
`matched: 64`, `cases: 64`, no differences and no error. Its on-device binary
SHA-256 matched the bundle: `040625a63d1102e2edc46671cae9f2e52c9d66897b1212ec0c6cca54ed439231`.
The local result directory is
`work/android-arm64-probe/results-003da7074e37403abe9489d009a73330/`,
with `result.json`, 14,680 bytes of stdout and empty stderr. The runner removed
its temporary directory under `/data/local/tmp` after execution. This validates
the first 19-byte helper on this device, not APK launch or game behavior.

## Second original function on the Windows host

The unchanged Steam Legacy executable SHA-256 was rechecked as
`24041f834e979cc088714713c3207540ff9093f51ff126450a4f7989432156b6`.
The pinned pcrecomp archive passed its lockfile hash checks; the isolated
SteamStub patch was applied only to a private copy. Metadata inspection matched
the previously reviewed 0xF0-byte header, app ID, image base, zero flags, code
range and original entry. The private recovered analysis image reproduced SHA-256
`63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985`.
Only the declared raw code range differs from the original. The original PE was
rehashed after recovery and remained unchanged.

One second function was selected at RVA `0x1250`, preferred VA `0xA0001250`.
Its reviewed 27-byte range has SHA-256
`3d3b467ac94d779b05c24d2c928485b8b7522941d19830c8c8a76b9440bbdea8`.
Alignment/padding and a direct call at RVA `0x1AB79C` support its boundary.
It reads a caller-supplied object pointer from the stack and fields `+0x18`,
`+0x1C` and `+0x100`. If the last field is zero it returns `0xFFFFFFFF`;
otherwise it returns `field_18 - field_1C + field_100` modulo 2^32. It has a
conditional branch, arithmetic and two returns, with no import, callback,
global read, allocation or memory write. Its symbol and gameplay role are unknown.

The private `work/interop-legacy-002/second_probe.py` pins the image/function
hashes, checks instruction boundaries and constructs three basic blocks for
unmodified upstream pcrecomp. It uses a single generated C function across
64 deterministic cases: 32 with the zero branch and 32 with the nonzero branch,
including arithmetic boundaries and fixed-seed random inputs. Unicorn x86-32
matched an independent arithmetic/register/flag/memory oracle in all 64 cases.
The generated C compiled and ran on Windows with Zig 0.14.0; its official archive
SHA-256 was verified against Zig's published release metadata. Its outputs
matched Unicorn in **64/64** cases for all eight GPRs, defined flags, return-stack
adjustment and the complete tracked memory difference. The logic instruction's
undefined AF is excluded only on the zero branch. The private report is
`work/interop-legacy-002/second-result.json` and records zero differences.

At this earlier stage the second function had **not** run on ARM64. The fixture assumes a valid,
readable 32-bit guest object of at least 0x104 bytes, a valid cdecl stack and a
single bounded execution. It does not test invalid pointers, exceptions, floating
point, calls, threads, OS services, indirect dispatch, game initialization or a
game-rendered frame. The candidate's meaning remains unproven.

## Approved read-only object-query group

The owner approved the bounded group milestone. Static x86 analysis found a
direct caller at RVA `0x1ABD40` that passes the same pointer from `[esi+0x34]`
to all three functions. Two nearby wrappers also pass that object pointer to
the functions at `0x1250` and `0x1270`. These are related read-only queries,
although their symbols and gameplay meanings remain unknown.

| RVA | Reviewed bytes and SHA-256 | Observed result |
|---|---|---|
| `0x1240` | 11; `f424662e1b90f5d99c02937ed041695bb3b23bd27734ca6d17af75d9a31e89b1` | Return object `+0xFC`. |
| `0x1250` | 27; `3d3b467ac94d779b05c24d2c928485b8b7522941d19830c8c8a76b9440bbdea8` | If `+0x100` is zero, return `0xFFFFFFFF`; otherwise return `+0x18 - +0x1C + +0x100` modulo 2^32. |
| `0x1270` | 30; `8e1d492836b41265c7704a3244edfd4108eb351d78905d2658865510e926f85b` | If `+0x104` or `+0x100` is zero, return zero; otherwise return `+0x104 - +0x100` modulo 2^32. |

The private `work/interop-legacy-002/group_probe.py` verifies those hashes
against the pinned analysis image and exact decoded basic-block boundaries.
It lifts only these three functions with unmodified pinned pcrecomp. Test inputs
use high-bit 32-bit guest addresses, a declared 0x108-byte object span and an
8-byte stack span. The authored `tools/guest_query_guard.h` checks each 32-bit
read for overflow and membership in a committed span before touching host
memory. It dispatches only the three reviewed VAs; an unknown VA exits with a
distinct error. Four authored C-fixture tests passed for valid reads, missing
memory, address wraparound and unresolved dispatch.

The same generated C was reused for 96 deterministic cases: 16 at `0x1240`,
32 at `0x1250` and 48 at `0x1270`. Every branch outcome and arithmetic edge was
covered. Unicorn x86-32 matched independent result, register, defined-flag,
stack and no-write oracles in **96/96** cases. The Windows generated executable
matched every full saved x86 state exactly in **96/96** cases. Undefined AF was
excluded only on the logical zero-return branches; the saved reference and
generated output both clear that bit for strict transport comparison.
The final generated C SHA-256 is
`c7502ad58ae1a887b06673a5ca44a1ce15e741e2746dcc8560da9174b8e60591`.

Google's official NDK r27c Windows archive (version `27.2.12479018`) matched
the [Android NDK project's published SHA-1](https://github.com/android/ndk/wiki/Home/b35b56c5c58c37771c404832c565f0ca4ee5aaab)
`ac5f7762764b1f15341094e148ad4f847d050c38`; its locally computed SHA-256 was
`27e49f11e0cee5800983d8af8f4acd5bf09987aa6f790d4439dda9f3643d2494`.
Its API 26 AArch64 compiler built the same generated C as a PIE using
`/system/bin/linker64`, with all four LOAD segments aligned to 16,384 bytes.
Bundle preflight accepted all hashes and 96 reference states while reporting
`arm64_executed: false`.

After the owner reconnected the phone, the strict USB-ADB runner verified one
authorized physical AArch64 Android device, pushed the hash-checked executable,
and ran it in a fresh `/data/local/tmp` directory. The saved private report at
`work/interop-legacy-002/group-bundle/results-03597cf7f40747e2adfd03bb1543f7a3/result.json`
records `arm64_executed: true`, remote exit 0, **96/96** exact matches, zero
differences, empty stderr and no cleanup error. The on-device binary SHA-256
matched the bundle: `89cae18a79c26f71a3964cb829d8eed3cf18fe377ac3a1e75932c3e17572f5b8`.
Device properties are self-reported; this run used 4 KiB pages and does not
prove behavior on a 16 KiB page device.

The original executable and analysis image were rehashed unchanged, and Git
ignore excludes all private code, inputs, generated C, binaries and raw states.
This validates a bounded read-only call group. It does not establish invalid
game-pointer behavior, callbacks, imports, threads, exceptions, game startup,
rendering or a playable Android port.

## Cache-wrapper host and ARM64 validation — 2026-10-21

The two outer-object wrappers at RVAs `0x1AB770` and `0x1AB78C` were selected
from the caller map. Each reads the handle at outer `+0x34`; with a null handle
it returns its existing cache (`+0x90` or `+0x8C`), and with a live handle it
calls the previously validated leaf at `0x1270` or `0x1250`, stores the result
in that cache, and returns it. The 28-byte wrapper ranges have SHA-256 values
`e11e51869f78e658b083e86c7278158569686d54f76bd2c3384439d0acc9c0f7`
and `ebc580d3ee42e7ff6682975daae665b68431f6fdaa5544f57db1e4b6a9d1cf62`.
The unchanged analysis image has SHA-256
`63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985`.

Private `work/interop-legacy-002/wrapper_probe.py` runs 64 deterministic cases:
16 null-handle and 16 live-handle cases for each wrapper. The cases cover
retained/refreshed caches, both guarded branches in each leaf, arithmetic
edges and random values at high-bit guest addresses. An independent oracle
checked result, cache and handle state, eight GPRs, CF/PF/ZF/SF/DF/OF and
absence of unexpected outer/handle writes against Unicorn x86-32 in **64/64**
cases.
Deliberately corrupting a cache result made that oracle reject a case.
The unmodified pinned pcrecomp lifter then generated C for exactly the two
wrappers and their two already validated leaves. A checked guest-memory
window rejects other addresses. Windows execution matched all saved x86
registers, defined flags, stack effects and byte-level guest-memory changes
in **64/64** cases. The same generated C has SHA-256
`8f2528e6fabe017d13c25fac6e01c44356125b6eab85b71cd01f9b62909eec56`.
Undefined AF on logical-result branches was cleared on both sides for strict
transport comparison; the strict host bundle comparison also passed **64/64**.

NDK 27.2.12479018 compiled that source into an API 26 AArch64 PIE with
`/system/bin/linker64` and four 16 KiB-aligned LOAD segments. Bundle preflight
accepted all hashes and reference states with `arm64_executed: false`.
After the owner connected the phone, the strict USB runner verified the device
and on-device binary SHA-256
`3f5c36bb34fb1e3e3619790cbc7bb217100289a5e0bfd59ec5861d49cd3d5d52`,
then observed remote exit 0 and **64/64 exact state matches**, zero differences,
empty stderr and no cleanup error. The private result is under ignored
`work/interop-legacy-002/wrapper-bundle/results-ad1bcc650fbc4953b51ccdc76054a0fc/`.
The phone reported 4 KiB pages. This validates only the bounded wrappers and
leaves; the creator, callback setup, release, mutation, jump table and full
game runtime remain unvalidated. No game initialization or rendered frame was
attempted.

## Local diagnostic APK build — 2026-10-21

The owner's Windows checkout built `assembleDebug` and `lintDebug` with JDK
17.0.20.1+1, Android platform/build tools 35, CMake 3.31.6 and NDK r27c
(`27.2.12479018`). Gradle reported `BUILD SUCCESSFUL`; lint reported zero
errors and one expected ChromeOS ABI warning because this diagnostic target
intentionally packages ARM64 only. The final debug APK SHA-256 is
`84e0463d22e8b48480fd1201301af1ae0d48b6bc271c05054eebc77160c152df`.
`zipalign -c -P 16 4` and `apksigner verify --verbose` passed. The APK contains
`lib/arm64-v8a/libts2_android.so` and `lib/arm64-v8a/libc++_shared.so`;
the native bridge has three 16 KiB-aligned LOAD segments and declares the
C++ library as a dependency. This does not prove 16 KiB device behavior.

The first local native link exposed a Windows path/toolchain issue: CMake's
shortened `CLANG_~1.EXE` path combined with NDK `-no-canonical-prefixes`
omitted the driver's implicit C++ runtime link. An otherwise identical manual
link using the full `clang++.exe` name succeeded. The app now selects the
NDK's shared C++ runtime and links it explicitly; the APK packages the runtime.

## Diagnostic APK phone pass — 2026-10-21

The final APK was installed with `adb install -r` and cold-launched on an
authorized physical Samsung SM-S931B, Android 16/API 36, `arm64-v8a`, Adreno,
with 4 KiB pages. `System.loadLibrary` succeeded, the activity resumed, and
the native surface was acquired. A final 1080×2340 screenshot shows all six
tiles, focus highlight, status and bars. The first device screenshot exposed
a status-bar overlap on Android 16; window-inset padding corrected it in the
final APK. The final screenshot is in ignored
`work/android-diagnostic-validation/final-apk-screen.png`.

| Check | Observed result |
|---|---|
| Simulated D-pad and Enter | Focus moved from tile 2 to 3; Enter toggled Navigation Mode, with `actions` and `mode_changed` native logs. |
| Modal controls | D-pad/Enter opened the sensitivity and mappings dialogs; Back dismissed them and reset input. |
| Text and IME | ADB text `Test123` appeared in the field. The first build required a tap to show the keyboard; setting the dialog soft-input mode made it appear immediately after Enter in the final APK. |
| SAF cancel | Game files opened Android DocumentsUI's folder picker; Back returned to the diagnostic app. No file was selected or read. |
| Lifecycle | Home/resume and picker backgrounding produced `pause`, `input_reset`, `surface_released`, `resume` and `surface_acquired` logs; the process survived. |
| Touch | Tapping Reset input selected tile 6, logged an action/reset and showed the “Input released” toast. |

The final APK passed `zipalign -c -P 16 4` and `apksigner verify` (v2 scheme).
`aapt dump permissions` listed no requested permissions. The filtered logs
are saved privately in ignored `work/android-diagnostic-validation/`; the
observed app process had no `FATAL EXCEPTION`, `AndroidRuntime` or fatal-signal
markers during these checks. ADB-injected keys are **not** evidence of a
physical controller. Hardware pad hotplug/axes and key+hat duplicates, Android
TV/tablet, rotation and sustained runs remain untested. No installation or
package resource was selected, so M2 Android resource validation remains open.

## Resource probe host preflight — 2026-10-21

The Java bounded stream test passed 9 checks. A new authored CLI regression
showed that Windows text-mode stdout changed each decoded LF byte to CRLF; it
failed before the fix and passed after the probe switched stdout to binary mode.
The rebuilt host probe then decoded the owner's three small local samples with
the expected sizes and exact SHA-256 hashes: lighting 8,238 bytes
(`1b2151eefac283d9d02ee4a477d9691efbd2ebdd7b39edd01bf94b6230dc0a46`),
FaceInfo 2,716 bytes
(`c77b50651c3061a0dfbd3e9f5d97c35347bfb8aa6c288f4841372bb04e880920`),
and WantTuning 11,905 bytes
(`a8aa3798ebc3812b10cb0195f07693dd3fcd6e1b22d93767b4dd8d4cdae3e82d`).
No payload was written outside ignored `work/` or added to Git.

The offline `assembleDebug lintDebug` build succeeded with the pinned local SDK,
JDK and Gradle cache. The new APK SHA-256 is
`3f4ecc255468e14955229895a1e00db1f4d690cefe6abbd6a8055a003aabaeb0`.
`zipalign -c -P 16 4` and `apksigner verify --verbose` passed; the APK contains
`lib/arm64-v8a/libts2_android.so` and `lib/arm64-v8a/libc++_shared.so`.

The broad Python host suite ran 42 tests and was not green on this Windows host:
four guest-query fixture builds failed with Zig's `Unexpected` error, two tests
could not create a symlink/hardlink with the current Windows privileges, and the
SteamStub patch fixture could not find a `patch` executable. The new probe test
passed. These failures are separate from the resource probe preflight and remain
visible for cross-platform test maintenance.

The M2 package picker and JNI report still require a physical Android run. The
next device bundle is installation of this APK, selecting the three small
legitimate packages through SAF, comparing private report hashes, and checking
PNG preview, failure recovery and lifecycle logs. No new ADB run is claimed here.
The device has 4 KiB pages; 16 KiB hardware behavior remains untested. M1 is
therefore partially validated, not fully accepted.

## No-root host toolchain bootstrap and full baseline — 2026-10-22

`scripts/test-host.sh` had never run on this machine: no `cmake`, `ninja`, `make`
or any C/C++ compiler, no `ps`/`pgrep`/`pkill`, and the pinned Python analysis
deps were absent. A self-contained toolchain was installed under the ignored
`.local-tools/` tree without root, and the documented baseline now runs.

Bootstrap (all no-root, all under `.local-tools/`):

```sh
cd "<parent of sims2-native>"
.local-tools/python/bin/python3 -m venv .local-tools/toolchain
.local-tools/toolchain/bin/python -m pip install cmake ninja 'ziglang==0.14.0'
# wrapper scripts in .local-tools/toolchain/bin:
#   zig-cc, zig-cxx, zig-ar, zig-ranlib  -> python -m ziglang cc | c++ | ar | ranlib
#   cc, clang, gcc                       -> zig cc   (names tests look up)
#   c++, clang++, g++                    -> zig c++
```

Versions actually used: cmake 4.4.4, Ninja 1.13.2, **Zig 0.14.0** (the version
this repository already expects — see `work/deps/zig-windows-x86_64-0.14.0/` in
`tests/test_guest_query_guard.py`). Zig 0.17.0 was tried first and is *not*
suitable: `GuestQueryGuardTests` pins `ZIG_LOCAL_CACHE_DIR` inside its own
temporary directory, and under 0.17 files are still landing there when
`TemporaryDirectory.cleanup()` runs, so `tearDownClass` failed with
`OSError: [Errno 39] Directory not empty` on every run. Under 0.14.0 the same
four tests pass. The generator must be Ninja — there is no `make` for "Unix
Makefiles" to find, and configure fails with `CMAKE_MAKE_PROGRAM is not set`.
Linking also needs the archiver, or the build dies at `CMAKE_AR-NOTFOUND`:

```sh
TC=../.local-tools/toolchain/bin
cmake -G Ninja -S . -B build/host -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER="$TC/zig-cc" -DCMAKE_CXX_COMPILER="$TC/zig-cxx" \
  -DCMAKE_MAKE_PROGRAM="$TC/ninja" \
  -DCMAKE_AR="$TC/zig-ar" -DCMAKE_RANLIB="$TC/zig-ranlib"
```

Python dependencies at the repository's own pins in `tools/requirements.txt`
(pefile 2024.8.26, capstone 5.0.6, unicorn 2.1.4) plus cryptography 50.0.0 from
`tools/interop-requirements.txt`.

GNU patch, which `test_steamstub_patch` shells out to, is absent from this
container and unreachable without root (`apt-get download patch` →
`E: Unable to locate package patch`, and `/var/lib/apt/lists` is not writable so
the index cannot be refreshed). The genuine Debian package was fetched over
verified TLS from the official mirror and unpacked with `dpkg-deb -x` into the
toolchain `bin` — no root, no reimplementation:

```sh
# https://deb.debian.org/debian/pool/main/p/patch/patch_2.8-2_amd64.deb
# sha256 80c46a0085b33acc74bf451fddb6a70cb43d4ebcc4a873aec04d8d0a63ffc630  (134328 bytes)
dpkg-deb -x patch_2.8-2_amd64.deb extracted   # -> extracted/usr/bin/patch  (GNU patch 2.8)
```

`scripts/campaign/worker-env.sh` appends that same `bin` directory to `PATH`, so
worker sessions inherit patch, the compiler and the pinned Python deps.

Result of `./scripts/test-host.sh`:

- CTest: 4/4 passed — `core`, `dbpf`, `resource_mount`, `qfs`.
- `unittest`: **54 tests, `OK`, no skips** (`test-host.sh` exit 0). Before this
  bootstrap the suite could not even import: 29 tests with 3 import errors and
  two classes skipped or erroring at `setUpClass`.
- The four `GuestQueryGuardTests` (uncommitted read, unregistered function,
  wraparound read, valid high-bit object/stack reads) now actually compile and
  run, because that suite looks for `cc`/`clang`/`gcc` and its own skip message
  names "verified local Zig".
- The seven `SteamStubPatchTests` (headers/entry/wrapper/overlay recovery, and
  so on) now run instead of skipping, which is what pulled GNU patch into scope.

This closes the *host* environment gap only. It says nothing about Android, and
the fail-closed acceptance gate still refuses: `scripts/phase1-acceptance.sh`
exits 78 without `TS2_TRUSTED_PHASE1_VALIDATOR`.

Two traps worth recording:

- Append the toolchain directory to `PATH`, never prepend it. The venv ships its
  own `bin/python3`, which shadows the vendored interpreter that has pefile, and
  the analysis tests then fail with `ModuleNotFoundError: No module named
  'pefile'` despite the package being installed.
- Zig is a clang frontend, not the MSVC toolchain used by CI and not the Android
  NDK. This evidence says the host suite compiles and passes under clang on Linux
  x86_64; it does not replace the Windows host or ARM64 device evidence above.
