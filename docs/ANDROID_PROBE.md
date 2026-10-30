# Private Android ARM64 original-function probe

Status: **physical ARM64 execution passed 64/64 cases** on the owner's Windows
connected device on 2026-10-21. Those historical device passes remain standalone
CLI tests; no JNI/Android execution has been measured for the optional Campaign F
build-side integration below. The conditional second original-function lift
also passed 64/64 initial host reference cases. In the later approved
three-function read-only group, it and two neighboring queries passed 96/96
host and physical ARM64 comparisons. See [LOCAL_VALIDATION.md](LOCAL_VALIDATION.md).
The instructions below document the original bundle and remain useful for
repeating the first probe.

The earlier cloud workspace exposed neither `/dev/bus/usb` nor
`/sys/bus/usb/devices` and had no configured ADB endpoint. The owner's local
Windows checkout can access the phone by USB; no public ADB listener or remote
network setup is needed.

## Campaign F: opt-in diagnostic JNI differential (build-side, not gameplay)

The default APK still contains **no private original-game code**. The optional
Debug build stages the already-verified `0x9550` lift and its 64 saved x86
input/post-state cases in ignored `work/`. It replaces only CLI I/O, retains
the generated body verbatim, and invokes it through the existing production
`GuestMemory` / exact-VA `GuestDispatch` slice. The named JNI entry is
`MainActivity.nativeLeafDifferential`; without private staging it returns
`available:false`, never a synthetic pass. This is a fixture boundary, not a
startup/game binding. No new lift, x86 oracle, flags/FP/PC or transient-write
coverage is implied. Eight GPRs and six complete pages are compared.

Private preparation/build (use a **new** output directory; requires the existing
owner-only `work/recomp-bench/leaf-d1` fixture and pinned NDK/SDK):

```sh
. scripts/campaign/worker-env.sh
python3 scripts/recomp/prepare_android_leaf.py prepare --output work/jni-leaf-NEW
# Use a compatible JDK, e.g. the locally provisioned JDK21, not JDK25.
export JAVA_HOME="$(cd .. && pwd)/.local-tools/jdk21"
export ANDROID_HOME=/workspace/.local-tools/android-sdk
export TS2_PRIVATE_LEAF_DIR="$PWD/work/jni-leaf-NEW"
scripts/build-android.sh --no-daemon
python3 scripts/recomp/prepare_android_leaf.py bundle \
  --prepared work/jni-leaf-NEW \
  --apk android/app/build/outputs/apk/debug/app-debug.apk \
  --output work/jni-device-NEW
python3 work/jni-device-NEW/run_probe.py  # local hash preflight only; no ADB
unset TS2_PRIVATE_LEAF_DIR
scripts/build-android.sh --no-daemon     # restore the game-code-free default APK
```

**Never distribute/upload this private APK or bundle.** Transfer the whole bundle
privately to the owner machine (Python 3.11+ and USB ADB required). Its manifest
hashes bind the APK and copied runner, not a cryptographic attestation or a trusted
gameplay validator. One explicit owner command installs/updates the diagnostic app,
verifies the installed APK hash, launches the nonce-bound worker-thread JNI check,
and saves private logs/results:

```sh
python run_probe.py --run  # optionally --adb PATH --serial SERIAL
```

This updates the existing `org.ts2native.diagnostic` app, requires a compatible
signing identity, leaves it installed, and starts the diagnostic UI. It does not
clear app data, access game files/saves, change ADB transport or root the device.
Exactly one authorized physical USB ARM64 API26+ device is required; emulator
identities reject for this hardware-only batch. There is no ADB polling from the
build host. Device properties are self-reported. Matching fresh nonce, exact
64/64 result, installed APK hash and successful device commands are required;
partial/malformed/mismatching/duplicate completion is failure. No completion in
60 seconds is a failure. `results-*/result.json` always keeps
`phase1_complete:false`; preflight and APK assembly keep `android_executed:false`.
This runner is **not** the independently controlled Phase 1 acceptance validator.

## Local execution

Obtain the owner-only `android-arm64-probe.zip` from this workspace and extract it
locally. Keep it private: it contains a compiled original-function test and must
remain outside public repositories. It contains no PE, recovered image, generated
C, game assets, Steam credentials or decoded protection metadata.

Install Python 3.10+ and Android SDK Platform Tools. Connect an unlocked physical
Android ARM64 device running API 26+ via USB debugging and accept its authorization
prompt. In a terminal in the extracted directory:

```sh
adb devices -l
python run_probe.py
```

On Windows, `py run_probe.py` is also suitable; on macOS/Linux use `python3` if
needed. An ADB installation outside PATH can be selected with
`--adb "PATH/TO/adb"`. Connect exactly one USB device; wireless transports are
excluded using ADB's `-d` selector for every device command. Optional
`--serial DEVICE_SERIAL` additionally checks its identity. No root or APK
installation is required.

The runner checks architecture/ABI/API level and rejects known emulator
properties. These are self-reported device properties, not hardware attestation.
It verifies bundle hashes, pushes only the native test into a fresh mode-700
UUID directory beneath `/data/local/tmp`, verifies its on-device SHA-256, executes
it and removes that directory. It does not read or write game files or saves.

Each run writes a new `results-<uuid>/` containing `result.json`, and raw stdout
and stderr when the process returns. Send back `result.json`; include stdout for
a mismatch. Device serial/fingerprint may be redacted. Exit status 0 and
`hardware_gate_passed: true` require all 64 cases to match. A missing, malformed,
partial or differing result is not a pass. `--preflight` checks only the local
bundle and explicitly reports `arm64_executed: false`.

## Exact scope and reproduction

This reuses the existing function at RVA 0x1070 and identical generated C
(SHA-256 `97ddb073fa5a67eeab389443819ecf34de0b51396c3ed5c6ee23cae9ff153184`).
No new original function has been selected or lifted. The private harness was
extended solely to save all x86 reference states. Rerunning its bounded experiment
again passed 64/64 x86-vs-host comparisons and independent expected-state checks;
the original executable hash remained unchanged. See [the prior
experiment](INTEROP_EXPERIMENT.md) for the reviewed operand contract and hashes.

Private commands from the repository root in this workspace:

```sh
PYTHONPATH=/workspace/.tools/python python3 work/interop-legacy-001/probe_one_original.py
/workspace/.tools/android-sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang \
  -std=c11 -O0 -fPIE -pie \
  -I work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/runtime/recomp32 \
  work/interop-legacy-001/original-leaf/leaf.c -lm \
  -Wl,-z,max-page-size=16384 \
  -o work/interop-legacy-001/original-leaf/leaf-arm64
python3 tools/android_probe.py --bundle work/interop-legacy-001/android-arm64-probe --preflight
```

The private harness/generated input are deliberately absent from Git. Public
tests exercise the generic parser, state comparison and runner failure behavior
using authored fixtures, without game files or hardware:

```sh
python3 -m unittest discover -s tests -p test_android_probe.py -v
```

The native executable is ELF64 little-endian, AArch64 machine 183, PIE type 3,
interpreter `/system/bin/linker64`; all four LOAD alignments are 16384. Its
manifest binds binary/reference hashes to the original/function/generated-source
hashes. The strict comparison checks eight GPRs, modeled EFLAGS, stack adjustment
and the full tracked memory delta for every case. Floating point, branching,
callbacks, imports, threading, exceptions and game initialization remain untested.
The x86 reference is bounded Unicorn execution plus an independent state oracle,
not a physical x86 run or proof of full-game compatibility.

The hardware pass and exactly one second bounded function with branching and
arithmetic are now recorded in LOCAL_VALIDATION.md. That file proposes the next
subsystem milestone for owner review. No broader lifting or Android runtime
development is authorized by this probe preparation.
