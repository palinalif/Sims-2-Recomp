# Verification record — 2026-10-21

> **Policy update (2026-11-04):** platform ports (Android ARM64 first) are
> deferred to a separate follow-on project. Effective immediately, the
> verification ladder is **x86 reference vs host differential only** — the
> AArch64/physical-device execution arms are retired from the gates, and no
> tier requires a device. T1 = full differential proof against the recorded
> x86 reference behaviour (emulated execution counts). Historical receipts
> below are kept as-recorded, including the device runs already performed;
> nothing already earned is demoted.

Repository: `/workspace/sims2-native`, branch `work/native-foundation`.
Initial foundation checks ran before game files arrived; later sections record
the supplied Legacy analysis and resource work. A final local follow-up records
one physical ARM64 function probe. This is not a running Sims 2 port.

## Environment and reproducible commands

Linux x86-64, GCC 14.2.0, Python 3.12, CMake 3.31.6. Android SDK API 35,
build-tools 35.0.0, NDK 27.2.12479018 (r27c), SDK CMake 3.31.6, Gradle 8.13,
AGP 8.9.1. A full Temurin JDK 17.0.20.1+1 was installed locally after discovering
that the preinstalled Java 21 was a JRE without `javac`.

The temporary tool installation is `/workspace/.tools/` and is not part of this
repository. Set equivalent paths for your machine; the ordinary commands are in
README.md. These are the actual host commands, with workspace-local tools:

```sh
PATH=/workspace/.tools/jdk/jdk-17.0.20.1+1/bin:/workspace/.tools/python/cmake/data/bin:/workspace/.tools/python/bin:$PATH \
PYTHONPATH=/workspace/.tools/python scripts/test-host.sh

/workspace/.tools/python/cmake/data/bin/cmake -S . -B build/sanitized \
  -DTS2_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
/workspace/.tools/python/cmake/data/bin/cmake --build build/sanitized --parallel
ASAN_OPTIONS=detect_leaks=0 /workspace/.tools/python/cmake/data/bin/ctest \
  --test-dir build/sanitized --output-on-failure
```

Results: CTest **1/1 passed**, containing **36 checks**; Python unittest **9/9
passed**; AddressSanitizer + UndefinedBehaviorSanitizer CTest **1/1 passed**.
LeakSanitizer initially failed because the sandbox runs under ptrace; leak
detection was disabled for the successful sanitizer run. This is not a clean
LeakSanitizer result.

Checks cover input deadzones/timing/remapping/edge retention, negative mappings,
mixed pointer/focus navigation, renderer stride bounds, high guest addresses,
unaligned little-endian memory, uncommitted/null/wraparound rejection, malformed
PEs, exact hashes, symlink-free bounded discovery, DBPF index versions/bounds,
non-clobbering report paths, source-bound probe records and unsafe-leaf rejection.

## Android build

The actual wrapper-based build command in this managed environment was:

```sh
JAVA_HOME=/workspace/.tools/jdk/jdk-17.0.20.1+1 \
JAVA_TOOL_OPTIONS='-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts -Dhttps.proxyHost=proxy -Dhttps.proxyPort=8080 -Dhttp.proxyHost=proxy -Dhttp.proxyPort=8080' \
ANDROID_USER_HOME=/workspace/.tools/android-user \
ANDROID_HOME=/workspace/.tools/android-sdk \
GRADLE_USER_HOME=/workspace/.tools/gradle-user \
scripts/build-android.sh -Duser.home=/workspace/.tools/java-user --no-daemon
```

Result: **BUILD SUCCESSFUL**, assembleDebug + lintDebug, 47 tasks. Lint reports
**0 errors, 1 warning**: ChromeOS x86_64 ABI support is absent because this target
deliberately packages ARM64 only. No lint errors were suppressed.

APK: `android/app/build/outputs/apk/debug/app-debug.apk`, 376,609 bytes.
SHA-256 for this local debug artifact:
`9ba2cf910ff2f53fd4a35eb397256d30beb09347f460c830d0b15f0701758b7c`.
Debug signing keys and ZIP metadata mean another build need not have this hash.

Packaging checks performed:

```sh
/workspace/.tools/android-sdk/build-tools/35.0.0/apksigner verify --verbose \
  android/app/build/outputs/apk/debug/app-debug.apk
/workspace/.tools/android-sdk/build-tools/35.0.0/zipalign -c -P 16 4 \
  android/app/build/outputs/apk/debug/app-debug.apk
readelf -Ws build/validation/libts2_android.so
```

Signature verification passed (v2). ZIP alignment passed. APK inspection found
only `lib/arm64-v8a/libts2_android.so`; ELF e_machine=183 (AArch64), all three LOAD
segment alignments=16,384. All eight Java native method symbols are exported.
This verifies packaging and linkage, **not Android execution or 16 KiB device behavior**.

Build setup failures investigated and resolved: missing SDK/cache permissions
(set a writable ANDROID_USER_HOME), JRE without compiler (install full JDK),
downloaded JDK lacking the session proxy CA (use the existing system trust store),
Gradle wrapper proxy not receiving Gradle-only arguments (pass JVM proxy options),
and an incorrect CMake source-root ascent. Lint caught missing TV metadata and a
SAF permission constant; both were corrected, along with backup/accessibility
declarations. Gradle reports deprecated features for Gradle 9; this project pins 8.13.

ADB device enumeration was attempted but the installed adb tried to create an
unwritable default `~/.android` directory and aborted. No device launch, controller,
IME, SAF provider, touch, TV, suspend/resume or surface-recreation behavior is claimed.
Use the device acceptance checklist in ROADMAP.md before marking M1 complete.

## Recompilation experiment

```sh
PYTHONPATH=/workspace/.tools/python python3 tools/fetch_pcrecomp.py
PYTHONPATH=/workspace/.tools/python RECOMP_CC="$PWD/scripts/cc-with-libm.sh" \
  python3 work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/tools/lift/difftest.py
PYTHONPATH=/workspace/.tools/python python3 tools/recomp_probe.py \
  --pcrecomp work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e \
  --ndk /workspace/.tools/android-sdk/ndk/27.2.12479018
```

Fetch archive hash and reviewed input hashes verified. Upstream suite: **372/372
match**, zero known divergences, zero failures. The reference is Unicorn x86-32.
Upstream prints two `FIXED` notes for former known divergences; both now match.
Without `cc-with-libm.sh`, the upstream suite failed Linux linking on libm symbols;
the separate wrapper adds `-lm`, with no upstream source patches.

Our authored leaf: **5/5 reference cases match**, including GPRs, defined flags,
stack return adjustment and memory writes. Cross-compilation produced an Android
API 26 AArch64 shared ELF with 16 KiB LOAD alignment. `arm64_compiled=true`,
`arm64_executed=false`, `game_initialized=false` in ignored `work/probe/result.json`.
No original Sims 2 code was extracted, translated or executed.

## Review and artifact discipline

A separate read-only reviewer identified five defects. Regression tests exposed
them before the corresponding fixes: output clobbering, unsafe leaf memory access,
lost between-frame button taps, pointer/D-pad arbitration, and negative mappings.
All fixes pass the current suites. A follow-up source check corrected DBPF index
minor 1 to the 20-byte layout (minor 2 uses 24-byte entries).

The original-probe execution gate now rechecks source SHA/range/bytes and rejects
non-stack memory, segment/index registers, stack-pointer writes, control flow and
non-plain returns. It has finite compile/run timeouts. Only the documented fixed
fixture is supported; this is not a general safe game-function executor.

Git ignore checks confirmed exclusion of game-files/, work/, generated/, build
outputs, APKs, native binaries and local SDK configuration. The sole intended
tracked binary is the Gradle wrapper JAR (SHA-256
`81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f`),
with its Apache license/notices retained. CI configuration was added but has not
run on GitHub; local scripts/builds above are the evidence for this pass.

Decisions retained: native Android APIs for the diagnostic shell; POSIX guest
data memory for Linux/Android; Windows static recompilation provisional; keep
working branch local. Game renderer/audio/video/OS services and original-code
initialization remain unimplemented. Hardware execution and game compatibility
remain blocked on suitable inputs and test devices, not marked complete.

## Follow-up while the Legacy Collection upload is pending

Added ZIP preview and opt-in EXE/DLL-only staging (`tools/archive_intake.py`) plus
DLL census, import IAT metadata and TLS callback enumeration in the PE analyzer.
This changed host tooling only; the diagnostic APK and its first-pass hash above
are unchanged. No actual game files were available during this follow-up.

The current host command is the same `scripts/test-host.sh` invocation above.
Result: **CTest 1/1 passed (36 native checks), Python unittest 29/29 passed**.
New tests use authored ZIP/PE fixtures for default read-only behavior, CRC corruption,
path traversal and directory aliases, symlinks/special files, encrypted flags,
space/data/path-complexity budgets, exclusive staging destinations, named/ordinal/
delay imports, PE32/PE32+ TLS pointers, truncation and malformed-file byte budgets.

A separate reviewer identified three follow-up defects. Regression cases failed
before fixes and passed after them: implicit parent-directory spelling aliases,
unbounded deep-path indexing, and rejection of TLS table raw bytes when the PE
section's VirtualSize is zero/small. Path indexing now uses a bounded component
tree; callbacks use independently checked raw backing and pointer width.

An end-to-end smoke check built an authored fixture ZIP containing two PEs and a
1 MiB synthetic package, ran all three documented intake/analyzer CLI stages,
and confirmed two binary reports, expected TLS callbacks, no extracted package,
and an unchanged archive SHA-256. Preview reported `crc_verified=false`; the
staging manifest recorded per-binary CRC verification and SHA-256. This exercises
the actual CLI with synthetic inputs; it does not establish Legacy compatibility.

See [ARCHIVE_INTAKE.md](ARCHIVE_INTAKE.md) for commands, default limits, and the
distinction between metadata preview, payload checks and game execution.

## Supplied Steam Legacy target and native DBPF slice — 2026-10-21

The owner-supplied archive (10.45 GB, sparse local working set) was validated
structurally: selected ZIP members passed CRC — six EXE/DLLs and nine
resource/configuration samples from a cached 25.6 MB working set. The sparse local
ZIP is incomplete; no whole-archive checksum or all-entry CRC claim is made. Full
inputs/reports remain ignored.
See [TARGET_LEGACY.md](TARGET_LEGACY.md) for factual target metadata and the
protected-executable blocker. No unpacking, decryption or original-code execution.

The new native DBPF reader supports DBPF 1.0/1.1, index 7.0/7.1/7.2, resource-key
lookup, bounded borrowed payload spans and compression DIR metadata. Decoded reads
of compressed entries fail explicitly. It does not decode QFS, render assets or
connect resources to Android SAF yet. An independent source reviewer found no
Important defects and separately compiled the authored DBPF tests with UBSan:
30 checks passed.

Commands run from the repository:

```sh
PATH=/workspace/.tools/python/cmake/data/bin:$PATH \
  PYTHONPATH=/workspace/.tools/python scripts/test-host.sh
cmake --build build/sanitized --parallel
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build/sanitized --output-on-failure
```

Results: **CTest 2/2 passed (36 core + 30 DBPF checks); Python 30/30 passed**.
ASan/UBSan CTest 2/2 passed, with LeakSanitizer disabled for the documented ptrace
limitation. The protected-build guard test first failed for the missing catalog
argument, then passed after implementation. The actual Legacy executable probe
at entry RVA `0x011e1310`, size 4, exact registered SHA-256 exited 2 with the
documented protection blocker; no leaf output file was created.

Three supplied packages were indexed using `build/host/ts2_dbpf_probe PACKAGE`.
For the lighting package, this command returned the selected uncompressed bytes:

```sh
build/host/ts2_dbpf_probe \
  game-files/legacy-steam-resource-samples-001/EP9/TSData/Res/Lighting/lighting.package \
  0x856ddbac 0x8ba01057 0x6fb59732
```

A separate Python check read the index offset with `struct.unpack_from('<I', b, 40)`,
then resource offset/size from `index + 12`, and compared that slice with the native
stdout. **8,238 bytes matched exactly**, SHA-256
`1b2151eefac283d9d02ee4a477d9691efbd2ebdd7b39edd01bf94b6230dc0a46`.
FaceInfo's compressed resource returned nonzero with the explicit QFS/RefPack
unsupported message and empty stdout. Proprietary payloads are not committed.

Android was rebuilt using the JDK/SDK/proxy environment documented above and
`scripts/build-android.sh -Duser.home=/workspace/.tools/java-user --no-daemon`.
**assembleDebug + lintDebug succeeded** (47 tasks, 3 executed, 44 up to date).
The new DBPF object is an AArch64 relocatable object in the NDK core archive;
unused reader code is not wired into the APK's UI. Current debug APK SHA-256:
`9ba2cf910ff2f53fd4a35eb397256d30beb09347f460c830d0b15f0701758b7c`.
No device launch or game execution was performed. M1 hardware acceptance and
M2 decompression/mount/Android integration remain open.

## QFS decoding and Android package diagnostic — 2026-10-21

Implemented the observed TS2 QFS framing, owned `Dbpf::decode_resource()` output,
portable first-resource probe and Android single-document picker/worker/JNI path.
The UI reports SHA-256 and optionally previews a bounded PNG. Tree scanning remains
separate and is not a complete installation importer. No original game code ran.

Fresh verification after the final framing fix:

```sh
PATH=/workspace/.tools/python/cmake/data/bin:$PATH \
  PYTHONPATH=/workspace/.tools/python scripts/test-host.sh
JAVA_HOME=/workspace/.tools/jdk/jdk-17.0.20.1+1 scripts/test-package-stream.sh
/workspace/.tools/python/cmake/data/bin/cmake --build build/sanitized --parallel
ASAN_OPTIONS=detect_leaks=0 /workspace/.tools/python/cmake/data/bin/ctest \
  --test-dir build/sanitized --output-on-failure
```

Results: **CTest 3/3 passed; 36 core + 41 DBPF/probe + 6,684 QFS assertions**;
Python unittest **30/30 passed**; Java bounded stream **9/9 passed**;
ASan/UBSan CTest **3/3 passed**, LeakSanitizer disabled for the same ptrace limit.
QFS assertions include a single-byte mutation sweep, not thousands of independent
real-world packages. Authored tests cover all command classes, maximum distances/
lengths, overlapping copies, trailers, truncation, output/history bounds, size
disagreement, unsupported flags and budgets. Java tests exercise short/zero reads,
EOF, overflow, provider exceptions and cooperative interruption.

The new decoder first failed the literal test with its unimplemented stub, then
passed after implementation. Review exposed ambiguous framing: data may resemble
both a raw header and a valid size-prefixed header. Raw and prefixed collision
regressions failed before the final fix. The decoder now validates complete
framing with at most two bounded attempts. A separate reviewer rechecked both
the final fix and queued Android result delivery, with no remaining Critical or
Important findings. This does not substitute for Android runtime tests.

The independent reference source was fetched over HTTPS from the pinned raw URL
in `config/dependencies.lock.json`; 7,135 bytes, required SHA-256 verified. It was
compiled for host verification only. The reproducible comparison command was:

```sh
python3 tools/verify_qfs_reference.py \
  --reference-source work/qfs-reference/refpack.c \
  --package game-files/legacy-steam-resource-samples-001/Base/TSData/Res/Catalog/Skins/FaceInfo.package \
  --package game-files/legacy-steam-resource-samples-001/Base/TSData/Res/Wants/WantTuning.package \
  --package game-files/legacy-steam-resource-samples-001/EP9/TSData/Res/Lighting/lighting.package
```

All three complete payloads matched. FaceInfo: **2,716 decoded bytes**;
WantTuning: **11,905 decoded bytes**; lighting: **8,238 uncompressed bytes**,
PNG header dimensions **64 × 64**. Hashes are in TARGET_LEGACY.md; no payloads are
tracked. Native and independent C implementations run on this x86-64 host;
this is not ARM64 runtime validation.

Rebuilt using the exact Android environment above and
`scripts/build-android.sh -Duser.home=/workspace/.tools/java-user --no-daemon`.
**assembleDebug + lintDebug succeeded** (47 tasks, 16 executed, 31 up to date),
0 lint errors and the existing intentional ARM64-only ChromeOS warning.
`zipalign -c -P 16 4` and `apksigner verify` passed on the final debug APK.
SHA-256: `e499c810c9ab07f9ef23b90e8058f7a4ec7f5128fecba765267a29236ef0fd7c`.

Tried `adb devices -l` with writable ANDROID_USER_HOME and ANDROID_SDK_HOME;
this adb still tried `/home/agent/.android` and aborted on the read-only directory.
No successful device enumeration, install, launch, JNI execution, SAF provider,
controller or PNG-preview device result is claimed. Follow RESOURCES.md and the
M1 checklist on real hardware. CI now includes the Java stream tests, but CI itself
has not run remotely. Expansion overlays, a complete asset mount, saves and game
execution remain unimplemented; the supplied protected-code blocker is unchanged.

## Read-only SteamStub diagnosis after scope clarification — 2026-10-21

The user clarified that legitimate interoperability research is allowed and
explicitly required approval before unpacking. Updated current architecture,
target notes and registry wording accordingly. Static recompilation remains the
selected path; no engine rewrite or automatic protection recovery was introduced.

Fresh `pefile` inspection and SHA-256 reproduced Legacy 1.18.0.187, x86 PE32,
image base `0xA0000000`, entry RVA `0x011E1310`, 438 direct imports and the unchanged
input fingerprint in PROTECTION_DIAGNOSIS.md. A read-only Python check parsed
SteamStub signature constants from the pinned tool's AST, compared original entry
bytes, and inspected plaintext loader instructions with Capstone. It did not
import/call `unwrap()`, XOR/decode the protected header, decrypt code or write an
executable. Raw report/disassembly stay ignored under `work/`.

Observed: exact 21-byte `V3_PROLOGUE` match, no 2.x prologue match; plaintext
`0xC0DEC0DF` comparison at preferred VA `0xA11E149D`; loader copies `0xF0` header
bytes using different instructions from the supported parser pattern. `V3_COPY`
does not match the first `0x100` entry bytes (nor the checked `0x200` bytes).
Thus the current source would reject at its header-copy check, before decoding.
This is source/pattern evidence, not an attempted unpack or proof of decryption
support. Exact wrapper minor version and payload cryptography remain unverified.

Ran the upstream tool only on its built-in fixtures:

```sh
PYTHONPATH=/workspace/.tools/python python3 \
  work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/tools/drm/steamstub.py --selftest
PYTHONPATH=/workspace/.tools/python python3 tools/fetch_pcrecomp.py
PYTHONPATH=/workspace/.tools/python python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Results: **steamstub selftest: ok**; dependency archive/source verification passed
with `tools/drm/steamstub.py` now SHA-256 pinned; Python **30/30 passed**. No Android
or native application code changed, so the APK was not rebuilt for this diagnosis.
No proprietary input/output, raw dump or protected key/header was committed.

Primary-source follow-up inspected upstream file history (no later SteamStub
change returned after the known 3.x-support commit), Las Marionetas' pinned UC
requirement, Aspyr's public Mac Store expansion coverage and 17 USC 1201(f).
No other game executable was acquired. EU directive retrieval returned an empty
body, so it is not used to assert a particular local legal exception.
The procedure, limitations, alternative releases and explicit approval gate are
recorded in [PROTECTION_DIAGNOSIS.md](PROTECTION_DIAGNOSIS.md).

## Approved private recovery and one original function — 2026-10-21

The user approved the scoped experiment, requiring unchanged originals, private
ignored analysis copies, metadata-first validation, one function only, no Steam
authentication bypass or modified-game launch, and no broader development.
See [INTEROP_EXPERIMENT.md](INTEROP_EXPERIMENT.md) for complete results and limits.

Created `work/interop-legacy-001/` mode 0700 and an exclusive mode-0600 input copy.
Original and copy SHA-256 matched the recorded `24041f...2156b6` fingerprint.
Pristine pinned upstream was verified before copying its SteamStub source; the
dependency directory was never patched. Only the separate source copy received
the patch now under `patches/pcrecomp/`, with upstream license retained.

Authored metadata/recovery tests initially failed for missing APIs. After adding
the patch they passed. Independent review found missing raw overlap validation;
new header/.bind alias fixtures failed before the fix and passed after it. The
reviewer rechecked the fix with no remaining Important/Critical findings. Seven
patch tests now cover metadata-only operation, raw backing/field/App-ID errors,
cipher corruption, exact output preservation, header/section/certificate overlaps
and the existing automatic copy pattern. No test opens a game file. Optional
source/cryptography absence is reported as a skip, never silently fetched.

The private metadata-only call validated a 0xF0-byte header, signature/base/App ID,
flags zero, bounded code and original entry. Recovery was a later explicit call.
The existing AES-256-CBC scheme passed padding/length checks without cipher changes.
The resulting mode-0600 image SHA-256 is
`63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985`.
It differs only within raw `.text` code bytes; the PE entry still points at the
wrapper. Headers/imports/wrapper/other sections/overlay are unchanged. Existing
image-signature validity is not preserved. No PE was launched.

Private commands actually run:

```sh
PYTHONPATH=/workspace/.tools/python python3 work/interop-legacy-001/recover_analysis.py
PYTHONPATH=/workspace/.tools/python python3 work/interop-legacy-001/probe_one_original.py
PYTHONPATH=/workspace/.tools/python python3 -m unittest discover -s tests -p test_steamstub_patch.py -v
PYTHONPATH=/workspace/.tools/python python3 work/interop-legacy-001/pcrecomp/tools/drm/steamstub.py --selftest
PYTHONPATH=/workspace/.tools/python python3 tools/fetch_pcrecomp.py
```

The first metadata script attempt stopped before parsing because it incorrectly
expected the App ID to appear in VDF contents. The supplied VDF filename supplies
that expected identifier; it then matched decoded metadata. No code recovery
occurred on that failed precheck. No actual protected-header, cipher or original
function comparison mismatch was encountered.

Selected exactly one 19-byte original object-field helper at RVA 0x1070, with a
recovered caller at RVA 0x1AB6C7. The private harness pins image/function hashes and
checks the exact reviewed operands, without relaxing the existing public leaf
contract. One upstream-generated function is reused across 64 input/state cases.
**64/64 native host vs Unicorn comparisons passed**, plus 64/64 independent
expected-state checks: eight GPRs, modeled defined flags, return-stack adjustment
and complete guest-window memory differences. Guest pointers have their high bit
set; test inputs include uint32 boundaries and fixed-seed random values. Unicorn
write hooks constrain stores to the two reviewed object fields. This is bounded
original-code execution in an x86 reference, not launching the game.

The same generated C compiled with NDK 27.2.12479018 into a standalone AArch64
shared ELF, e_machine=183, four LOAD segments aligned to 16384. It was not loaded
or executed on ARM64; no Android application/integration code was changed and the
APK was not rebuilt. Upstream lifter source remained unchanged.

Final audit rehashed the original and both PE copies, verified private modes and
ARM64 ELF properties, and recorded private harness/patch hashes. Proprietary C,
original bytes, decoded headers/keys, recovered image and binaries remain ignored.
The completed experiment authorizes no broader runtime or additional function
work. Real ARM64 execution and full game feasibility remain unverified beyond
this original-code proof.

Final whole-project check:
`PATH=/workspace/.tools/python/cmake/data/bin:$PATH PYTHONPATH=/workspace/.tools/python scripts/test-host.sh`
passed **CTest 3/3 and Python 37/37**, with all seven optional patch tests actually
executed locally. `git diff --check` passed. Ignore checks explicitly exclude both
PE copies, generated leaf C, host executable and ARM64 library. No APK rebuild,
remote CI run, physical x86/ARM64 execution or game-launch result is claimed.

## Local ADB handoff preparation (2026-10-21)

The exact same generated C was revalidated: 64/64 host-vs-x86 comparisons and
independent expected-state checks, with original and recovered image hashes still
pinned. Saved complete x86 states for local Android comparison; the new strict
parser also matched all 64 recorded host cases. NDK 27.2 built an AArch64 PIE
executable (API 26, Android linker64, four 16384-aligned LOAD segments). Bundle
preflight passed, explicitly reporting `arm64_executed: false`.

`PATH=/workspace/.tools/python/cmake/data/bin:$PATH PYTHONPATH=/workspace/.tools/python scripts/test-host.sh`
passed CTest **3/3** and Python **44/44**, including seven new authored-fixture
parser/device/comparison/USB-selection/failure-cleanup tests. Mocked ADB tests do not
exercise hardware. No APK rebuild, Android execution, second function lift or
game launch occurred. The cloud has no USB exposure/configured ADB endpoint; a
network-enabled localhost:5037 check returned connection refused. Owner-local
instructions and the remaining hardware gate are in [ANDROID_PROBE.md](ANDROID_PROBE.md).

## Owner-local device and second-function follow-up (2026-10-21)

On Windows, ADB listed one authorized physical ARM64 device. The first original
function's private bundle passed preflight and then executed on the device:
`hardware_gate_passed: true`, remote exit 0, **64/64** matches, no differences,
matching on-device/bundle binary SHA-256 and empty stderr. Raw output and the
private report remain ignored under `work/android-arm64-probe/`.

The local original executable rehashed to its recorded SHA-256; metadata-first
inspection matched the reviewed SteamStub fields, and the separately recovered
analysis image reproduced its recorded SHA-256. A second 27-byte original
function at RVA `0x1250` was hash-pinned and lifted with unmodified upstream
pcrecomp. An independent arithmetic/state oracle matched Unicorn x86-32 in
64/64 cases; generated C compiled and ran on Windows and matched Unicorn in
**64/64** cases, covering both branches, eight GPRs, defined flags, stack and
complete tracked memory changes. The logic operation's undefined AF was
excluded only on that branch. It had not run on ARM64 at that stage; the later
approved group result is recorded below.

The local Python patch-test command could not start because GNU `patch` is not
installed on this Windows host. The isolated patch was instead checked and
applied with `git apply`, and the actual metadata/image hashes were verified.
This is not a claim that the seven synthetic patch tests were rerun locally;
their earlier cloud result remains recorded above. Full private methods, paths,
scope and limitations are in [LOCAL_VALIDATION.md](LOCAL_VALIDATION.md).

## Approved read-only object-query group (owner-local, 2026-10-21)

Static decoding identified a caller that passes the same object pointer to
the original functions at RVAs `0x1240`, `0x1250` and `0x1270`. All three byte
ranges were pinned to the unchanged analysis-image hash. The generated C uses
checked 32-bit high-address object/stack reads and a three-entry exact-VA
registry. Four authored C-fixture tests passed after first failing for the
missing guard implementation: valid reads, uncommitted read, wraparound read,
and unknown dispatch.

The private `group_probe.py` ran 96 cases through Unicorn x86-32 and independent
result/register/defined-flag/stack/no-write oracles. Host generated C matched
the complete saved states **96/96 exactly**. The same source compiled with
hash-verified NDK 27.2.12479018 into an API 26 AArch64 PIE with four 16 KiB
aligned LOAD segments. Bundle preflight passed with `arm64_executed: false`.
After phone reconnection, strict USB-ADB execution returned exit 0 and **96/96**
exact state matches, zero differences, an on-device hash match, empty stderr
and no cleanup error. Private report and raw output are under ignored
`work/interop-legacy-002/group-bundle/results-03597cf7f40747e2adfd03bb1543f7a3/`.
The original executable and analysis image rehashed unchanged; Git ignores the
private fixture, C, binaries, bundle, raw states and device output.

The local full Python run completed 41 individual tests with three environment
errors: two existing symlink tests require Windows symbolic-link privilege
(`WinError 1314`), and the optional SteamStub patch test needs GNU `patch`,
which is absent. The remaining individual tests, including all four new guard
tests and seven ADB-runner tests, passed. Those three tests are not claimed as
passing locally. No CTest/Gradle build or APK/device application launch was
performed in this follow-up. See [LOCAL_VALIDATION.md](LOCAL_VALIDATION.md)
for function contracts, result hashes and limits.

## Cache-wrapper follow-up (owner-local, 2026-10-21)

The two 28-byte cache wrappers at RVAs `0x1AB770` and `0x1AB78C` were
hash-pinned to the same analysis image. Unicorn x86-32 matched an independent
cache/register/status-flag oracle in **64/64** cases; an altered cache value
was rejected. Generated C from unmodified pinned pcrecomp matched all saved
registers, defined flags, stack effects and guest-memory changes in **64/64**
Windows host cases. The generated source SHA-256 is
`8f2528e6fabe017d13c25fac6e01c44356125b6eab85b71cd01f9b62909eec56`.
The strict transport comparison also matched all 64 host states exactly.

NDK r27c compiled the same C into an AArch64 PIE with four 16 KiB aligned
LOAD segments. Preflight passed without claiming execution. After the owner
connected the phone, the USB runner recorded remote exit 0, **64/64** exact
matches, matching on-device binary hash, empty stderr and no cleanup error.
The ignored result is under
`work/interop-legacy-002/wrapper-bundle/results-ad1bcc650fbc4953b51ccdc76054a0fc/`.
The device reported 4 KiB pages. The full handle lifetime, callbacks,
game startup and rendering remain unverified. See
[LOCAL_VALIDATION.md](LOCAL_VALIDATION.md).
