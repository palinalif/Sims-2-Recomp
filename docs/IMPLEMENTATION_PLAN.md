# First implementation plan

Goal: reviewable M0 foundation and M1 diagnostic application; original game
initialization remains gated on a legitimate executable and validated lifter ABI.
Spec: ARCHITECTURE.md. Execute inline as requested; no publication or proprietary data.

## Tasks and verification

- [x] Portable input: `native/include/ts2/input.hpp`, `native/src/input.cpp`,
  `tests/core_tests.cpp`. `Input::update(Pad,float)` returns action edges, analog
  camera/zoom and normalized cursor; `reset()` releases state. Test radial
  deadzones, NaN/clamping, frame-rate independence, hotplug reset, remapping,
  focus repeat, and long-pause dt cap. Native focus grid consumes these actions.
- [x] Checked guest memory: `guest_memory.hpp/.cpp`. Test little-endian unaligned
  access, high guest addresses, overflow/null/uncommitted ranges and host-page
  alignment. This is a data foundation, not a CPU execution engine.
- [x] Discovery: `tools/analyze_install.py`, `tests/test_analysis.py`,
  `config/versions.json`. Use pinned pefile; inspect PE metadata/imports/delay
  imports/TLS/sections/hashes/version info; DBPF header/index metadata; bounded
  symlink-free user-configured install scan. Test malformed/truncated files,
  unknown hashes, case-insensitive names, exact hash pinning for leaf probes,
  DBPF bounds, and scan limits. No original file writes.
- [x] Android implementation/build (hardware gate open): Gradle 8.13 / AGP 8.9.1 / NDK 27.2.12479018 / CMake 3.31.6,
  API 35 compile/target, min API 26, ARM64 only. JNI Activity draws the shared
  diagnostic renderer, reports structured logs, handles controller hotplug,
  touch/mouse, lifecycle and IME. Read-only SAF tree scan runs on a worker.
  Verify APK build/lint and an on-device acceptance checklist separately.
- [x] Recompilation probe: pinned pcrecomp + capstone + Unicorn. Generate only
  synthetic C first, compare registers/defined flags/memory with x86 reference,
  then compile a selected synthetic case for ARM64 if NDK is available. Prepare
  a bounded SHA-256 gated original leaf function experiment. No wholesale lift.
- [x] Final verification: host CTest + Python unittest, sanitizers, APK/lint when
  possible, dependency/license review, privacy/ignored-artifact audit. Record
  exact commands/results and retain all unverified hardware gates.

Most important review cases: unexpected SAF provider failures; controller removal
while a button is down; guest wraparound at 0xffffffff; unknown/packed game builds;
pause/resume causing stuck input or cursor jumps. No successful stubs for missing
game services. Android hardware launch cannot be inferred from APK compilation.

## Resource follow-up approved after Legacy intake

- [x] Decode the observed QFS framing with size/history/output bounds and authored
  command, mutation and ambiguous-framing regressions.
- [x] Compare the two compressed resources with a pinned independent host decoder;
  preserve the earlier uncompressed payload comparison and ignored inputs.
- [x] Connect a bounded single-package document picker to native probing, SHA-256
  reporting and PNG preview; build/lint the ARM64 app and test the Java stream reader.
- [x] Recheck public Mac publication and older-executable provenance without
  downloading unverified replacement game binaries. Record the unresolved blocker.
- [ ] Run the new probe and existing M1 checklist on real Android hardware.
- [ ] Determine expansion overlay precedence and implement a complete asset mount.

## Approved local interoperability experiment (complete; broader work paused)

- [x] Preserve/hash the original and create private, ignored mode-0600 analysis copy.
- [x] Keep pinned pcrecomp pristine; implement separate metadata/recovery APIs in
  an isolated patch with authored fixtures and retained MIT notice.
- [x] Validate metadata first, then recover only code bytes while preserving PE
  headers, entry, wrapper, imports and overlay. Do not launch a modified PE.
- [x] Review exactly one original helper and caller; compare generated native C
  with bounded x86 reference/oracle in 64 cases and cross-compile for ARM64.
- [x] Recheck original hash/private outputs, independent review, source pins,
  seven patch fixtures and full 3 CTest / 37 Python suite. Record limits in
  INTEROP_EXPERIMENT.md. No broader engine/Android development in this pass.
- [ ] Execute the same probe on actual ARM64 hardware (not available here).
