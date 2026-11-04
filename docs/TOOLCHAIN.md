# Toolchain manifest — pinned tools and versions

One-stop reference for humans and setup agents: every tool this project uses,
its pinned/current version, what it's for, and where the pin is enforced.
If anything here disagrees with the enforcing file, the enforcing file wins —
and please fix this page.

## Build (Android app — frozen, see scope note in README)

| Tool | Version | Enforced by |
|---|---|---|
| Android NDK | `27.2.12479018` (r27c) | `android/` Gradle config; `tools/install_android_ndk.py` installs the exact pinned version |
| Android platform | `platforms;android-35` | `android/build.gradle` (`compileSdk`) |
| Android build-tools | `35.0.0` | SDK install list in README |
| Gradle | wrapper **8.13** | `android/gradle/wrapper/gradle-wrapper.properties` (`distributionUrl`) |
| Android Gradle Plugin | **8.9.1** | `android/` build config |
| JDK | **17** (a full JDK, not a JRE; JDK 25 unsupported by the pinned Gradle) | README; Gradle toolchain check |
| SDK CMake | `cmake;3.31.6` | SDK package list in README |

Hermetic alternative: `tools/install_android_ndk.py` and
`tools/install_android_sdk_package.py` fetch the exact pinned versions without
Android Studio.

## Host-side validation & cross-compilation (Linux/macOS; Windows via WSL2)

| Tool | Version | Notes |
|---|---|---|
| Zig | **0.14.0** | Deliberate. 0.17.0 is *not* suitable: its delayed local-cache writes break `GuestQueryGuardTests` teardown (`OSError 39` on every run). Receipts: `docs/LOCAL_VALIDATION.md`. Wrappers: `zig-cc/-cxx/-ar/-ranlib` → `python -m ziglang cc|c++|ar|ranlib`. |
| CMake | 3.31+ (4.4.4 used in the referenced runs) | Must be paired with Ninja; `Unix Makefiles` fails (no `make` to find). |
| Ninja | 1.13.2 (used) | Required generator — configure fails with `CMAKE_MAKE_PROGRAM is not set` otherwise. |
| Python | 3.10+ (3.13 used) | `python3 -m venv .venv && pip install -r tools/requirements.txt` |
| C++20 compiler | any modern | For host tests not routed through the Zig wrappers. |

Cross toolchain file: `cmake/toolchains/aarch64-linux-musl.cmake`
(zig-cc/zig-cxx/zig-ar/zig-ranlib, target `aarch64-linux-musl`).
Environment prelude for campaign scripts: `scripts/campaign/worker-env.sh`.

## Static analysis

| Tool | Version | Notes |
|---|---|---|
| Ghidra | **12.2** | Persistent headless project for the pinned analysis image; see `docs/GHIDRA_WORKFLOW.md`. Query interface: `scripts/ghidra-query.sh` (envelope carries image SHA-256 and Ghidra version). Install from the official NSA release source into an isolated, versioned tools directory; do not touch system JDKs. |
| Ghidra's JDK | 25 (isolated, repo-sibling `../.local-tools/jdk25`) | Ghidra-only; separate from the JDK 17 used by Gradle. |

Decompiled pseudocode from any version of any decompiler is hypothesis, never
evidence (see `docs/VERIFICATION.md`).

## Original-game compiler (the *subject*, not our tools)

For completeness, so the two are never confused: the analysed original binary
was produced by a MSVC-v143-era toolchain (linker 14.40 confirmed; compiler
19.40 leading hypothesis; static UCRT, SDK 22621). See
"Build-toolchain forensics" in `docs/TARGET_LEGACY.md`. That is the build of
the *subject* under reversion; it is not what you install to work here.

## Environment quirks worth knowing

- Gradle needs `JAVA_HOME` exported to a full JDK 17 — not inherited from a
  shell default pointing at Ghidra's JDK 25 (see `docs/VERIFICATION.md`
  troubleshooting).
- No `make` is assumed anywhere; Ninja is the only supported non-IDE generator.
- Zig wrappers are plain `python -m ziglang` invocations behind wrapper
  scripts (`zig-cc` etc.), so the pip `ziglang` package at the pinned version
  is sufficient — no system-wide Zig install needed.
