# Milestones and acceptance

No game milestones are inferred from generated C, an APK or diagnostic graphics.

| Milestone | Acceptance gate | Current status |
|---|---|---|
| M0 | Reproducible repo, source/licensing review, provisional decision, explicit target/version evidence or documented missing input | Foundation implemented; Steam Legacy fingerprint/import/resource analysis recorded. Historical protected-code blocker resolved for the authorized pinned analysis image; runtime correctness and scope boundaries remain (see the engineering handoff (private record)) |
| M1 | ARM64 APK builds **and launches on Android**; native diagnostics draw; input/hotplug/lifecycle logs pass device checklist | APK built, launched and drew six tiles on a physical ARM64 phone; simulated input, dialogs, IME, SAF cancel and Home/resume passed. Physical gamepad, TV/tablet, rotation and 16 KiB device gates remain open; see LOCAL_VALIDATION.md |
| M2 | Discover edition-specific resources, validate hashes/DBPF indexes, load a selected resource and compare payload; read-only originals and isolated writable root | Partial: three payloads byte-matched, QFS decoder verified; caller-ordered read-only mount host-tested; Android package probe builds; device validation, actual expansion precedence and full installation import open |
| M3 | Bounded original functions and callbacks match reference, then game initialization runs in portable runtime with unresolved calls failing visibly | First helper matched 64/64 on physical ARM64; three-function read-only query group matched 96/96 and two cache wrappers matched 64/64 host and physical ARM64 states; callbacks/runtime/startup remain open |
| M4 | Original game render call path produces a verified frame through native graphics backend | Not started |
| M5 | Main menu renders, selects and cancels using controller alone, including text and modal UI | Not started |
| M6 | Neighborhood loads with correct content/objects and navigation; compare reference screenshots/state | Not started |
| M7 | Lot loading and basic live simulation, camera, Sim selection/actions and pause/speed | Not started |
| M8 | Stable copied-save round trips; audio/video; controller-only live/build/buy/text flow; lifecycle and sustained runs | Not started |
| M9 | Per-expansion executable/resource compatibility, CC/package mods, measured performance/thermals and regression matrix | Not started |

## M1 device acceptance checklist (partially executed)

- Install APK on an ARM64 device with Android 8+; verify launch and native library
  load logs. Test Android TV launcher and a tablet as separate configurations.
- See six tiles, cursor, focus highlight, camera/rotation/zoom bars and readable
  status at handheld and TV viewing distances, with system insets/rotation.
- Use Select to switch modes; navigate all tiles using D-pad/A/B. Exercise mapping
  and sensitivity dialogs, text IME, cancellation and default reset without touch.
- Test USB/Bluetooth/hardware gamepad addition/removal while holding buttons and
  axes. Reconnect or switch devices; no stale actions. Test D-pad key+hat duplicates.
- Background/resume, lock/unlock, lose focus, show IME, destroy/recreate surface and
  rotate. No stuck input, stale ANativeWindow use or large cursor jump.
- Select a legitimate installation via SAF; deny/cancel/revoke access; test cloud
  and local providers, unknown/truncated EXEs and scan budget/error reporting.
- Test touch and mouse; verify no storage-wide permission or original file writes.
- Capture `adb logcat -s TS2Native`, device model, OS, GPU and controller descriptor
  alongside pass/fail results. Test a 16 KiB page device; ELF alignment alone is not
  evidence of correct lifecycle or memory behavior there.

## Next three tasks

The completed narrow experiments have not begun broader engine or Android
runtime integration. The remaining work needs separately bounded validation.

1. Trace the original Legacy resource-loader selection path or run the unmodified
   game with isolated user data to establish actual precedence. The installation
   hashes, OpenTS2 reference behavior and the original executable's directory
   registration method are recorded in RESOURCE_PRECEDENCE.md; none proves the
   supplied executable's package winner. Then connect the host-tested
   caller-ordered mount to a bounded installation inventory before broad import.
2. The approved read-only object-query group passed its bounded host and
   physical ARM64 checks. Two simple cache wrappers subsequently passed
   64/64 host and physical ARM64 state comparisons. The caller, cache,
   creator, teardown and callback setup are mapped in OBJECT_QUERY_CALLER.md.
   Establish complete ownership and indirect-call contracts before proposing
   a portable runtime slice.
3. Complete the remaining M1 hardware/gamepad and form-factor gates. Select a
   legitimate installation or package through SAF for the RESOURCES.md device
   checklist, then compare native-decoded hashes and PNG preview with host results.
