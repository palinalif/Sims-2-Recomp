# Research — inspected 2026-10-21

These findings distinguish inspected source from author claims. No referenced game
was run here. Exact inspected revisions and GitHub API license metadata are in
[source-revisions.json](source-revisions.json). Links below are primary sources;
branch contents can change, so use those revision IDs when reproducing findings.

## pcrecomp

[Repository](https://github.com/sp00nznet/pcrecomp/tree/c0cbd3e3653010782b17e8a87b58953608ea411c), MIT.
Inspected README, `tools/lift/lift32.py`, `lift32_cpu.py`, `difftest.py`,
`runtime/recomp32/recomp_types.h`, `runtime/recomp32_cpu/cpu.h`, Win32 HLE README.

- Has recursive function recovery, PE/import/delay-import analysis, MSVC RTTI and
  vtable seed tools, x86-32 global-register and explicit-CPU lifters, and differential
  tests. Prefer these before writing another lifter.
- `recomp32` supports memory-base rebasing. `recomp32_cpu/cpu.h` at this revision
  explicitly assumes real 32-bit host pointers in its default memory helpers.
  Neither interface constitutes a finished Sims 2 ARM64 runtime.
- `native32` forwards to Windows on a 32-bit host. `win32hle` implements selected
  Win32 services over POSIX/SDL2, with DirectDraw/DirectSound/GDI. No complete Sims 2
  D3D9 runtime was established by this inspection. Source availability is useful;
  coverage and API correctness must be measured per target.
- C++ indirect dispatch and flags across calls need catalog/runtime cooperation.
  Unknown indirect calls must fail visibly. TLS, SEH, x87 precision and threading
  are correctness problems beyond instruction enumeration.
- Runtime graphics/audio depend on host adapters; this project does not embed the
  upstream HLE or its SDL2/FFmpeg dependencies in the diagnostic APK.
- The initial protection diagnosis ran only the SteamStub tool's built-in fixture
  self-test. After explicit approval, a separate local metadata/analysis-image
  extension recovered the owned build's code, and one original leaf passed host
  reference checks. The upstream lifter was unchanged. See INTEROP_EXPERIMENT.md.

Local verification: 372/372 upstream differential cases matched the Unicorn x86
reference, with zero known divergences and zero failures. The upstream test's
wording says “hardware”; the actual reference is Unicorn, not physical x86.
Initial Linux linkage failed because its compiler command omitted `-lm`.
`scripts/cc-with-libm.sh` supplies that flag without modifying upstream.

## nfsu2-recompiled

[Repository](https://github.com/codepdbh/nfsu2-recompiled/tree/ba99da0b127dc6e98202e4f856dcd0913b695b47).
README declares MIT for authored tooling/adapters; GitHub API did not identify a
root license at this revision. Treat file notices and dependency licenses separately;
do not infer that every vendored header is MIT. No implementation code copied here.

Inspected Android CMake/runtime files, `guest_memory.h`, `gamepad_input.h`,
`guest_input.inc`, `ports/dxvk_android/README.md` and patch list.

- Public Gradle/NDK application and runtime source exist. The author reports native
  ARM64 races, menu/controller input, AAudio, surface recovery and DXVK Vulkan.
  Those gameplay/performance claims were not independently reproduced here.
- Guest memory reserves a 4 GiB data address space on 64-bit hosts; a separate
  32-bit guest COM bridge marshals D3D9 objects into host DXVK. Guest code bytes are
  not executed by ARM. This is a relevant architecture precedent, not a turnkey
  Sims 2 runtime.
- The adapter pins Joshua-Ashton/dxvk-native `native-1.9.2b`, commit
  `c8dc91fabd00cac11d697ccf07426e798393cd40`. Android work includes WSI,
  ARM intrinsics, optional BC textures/DXT fallback and generated Vulkan shaders.
  Its README lists incomplete compressed-copy, volume and other D3D9 paths.
- Input exposes a DirectInput joystick and also falls back to scan codes in
  menus/racing. Reuse concepts, not racing mappings; Sims 2 needs a separate
  semantic action layer and verified UI focus hooks.
- The project describes pcrecomp patches for SIMD, strict indirect calls,
  instrumentation, backward-branch yields, thread-local state and signed flags.
  Do not apply all patches blindly to the newer upstream pin used here.
- Resource paths, executable offsets, game middleware and synchronization are
  NFS-specific. Adoption requires a small compatibility experiment and licensing
  review, not copying its entire runtime and substituting another EXE.

## Las Marionetas

[Repository](https://github.com/OmniBlade/LasMarionetas/tree/b1f378c92dca777b31cc8dfe0cebe3f8f6c345c7).
README: GPL-2.0-or-later with a closed-source original-binary linking exception;
verify the exception and file headers before reuse.

- A bottom-up **PC Sims 2** rewrite, with the original binary supplying missing
  functions. README requires Ultimate Edition and Windows for current use; its
  standalone build has very limited functionality. It is not a complete portable
  replacement engine.
- CMake selects injectable DLLs only for MSVC x86 because vtable layout must match
  the game. Source exposes GZCOM/framework interfaces, POSIX synchronization work
  and a `d3d9.dll` proxy in `src/hookproxy/proxydll.cpp`.
- Useful for naming/interfaces and reverse-engineering context. Building its
  existing hybrid model for ARM64 would still require translating every missing
  original function and replacing host APIs. No evidence of a ready Android
  renderer/audio/controller pipeline was found in the inspected entry points.

## OpenTS2

[Repository](https://github.com/LazyDuchess/OpenTS2/tree/bdabb07f4689ed91803a3d86dcbc8870b8832878), MPL-2.0.
Inspected README, Unity ProjectVersion, content/DBPF, cameras and audio source paths.

- A **PC Sims 2** reimplementation in C#/Unity, pinned editor 2020.3.32f1 in this
  snapshot. README states a basic menu/neighborhood chooser, preview and basic
  neighborhood view. Source contains more format/audio/experimental work; that
  does not demonstrate complete simulation, saves, expansions or mod parity.
- Native Android output through Unity/IL2CPP is plausible; it would be an engine
  rewrite, not preservation by running original compiled simulation code. Full
  gameplay is a much larger commitment than porting the currently shown views.
- Valuable DBPF/QFS and content-loading references. Unity audio/rendering dependencies
  and camera use of mouse input are different from the desired C++ action runtime.
  MPL file-level obligations and third-party notices must be retained if copied.

## Reported Mac PowerPC recompilation

[Linked Reddit post](https://www.reddit.com/r/decomps/comments/1x1tlll/the_sims_2_recompiled_native_android_port_is_the/),
by u/BelmanteGu, links [the author’s YouTube channel](https://www.youtube.com/@belmante).
The fetched page states that about 111,000 functions were translated, the game
loads resources and renders intro/menu on Apple Silicon, and **input, audio, videos
and Android are not working**. Those are author reports; no binary/source test was
possible here. The page's relative timestamps are not a reliable absolute date.

Publication checks performed:

1. Read the supplied post and its visible links. No Sims 2 source repository or
   license was linked in the fetched post text.
2. Queried `https://api.github.com/users/BelmanteGu/repos?per_page=100`. The response
   listed seven public repositories, none a Sims 2 PPC project.
3. Queried GitHub repository search for `sims 2 recompiled`, `sims powerpc`,
   `user:BelmanteGu sims`, `sims2 recomp`, and `sims2 mac recompile`.
   No reusable Mac PPC Sims 2 implementation was identified by these checks.
4. Reddit's direct JSON endpoint returned HTTP 403. Web search follow-ups returned
   tool errors. Those limits prevent a claim of exhaustive search or proof that
   the code is unpublished everywhere.

Conclusion: **no publicly reusable Sims 2 Mac source located**, not “the author has
no source.” Do not speculate about its implementation details or assume access.
Revisit if the author publishes source/tooling with suitable rights. A PPC path
would need big-endian memory/ABI, Carbon/Mach-O and OpenGL services, codec/audio/input
replacement, and verification of expansion coverage; Apple Silicon success alone
does not establish Android feasibility or Windows UC compatibility.

Follow-up during the QFS slice: repeated GitHub repository searches for
`sims2 recompiled` and `user:BelmanteGu`. The former returned the excluded Xbox
project; the latter returned the same seven public repositories with no Sims 2
project. This still does not establish publication status everywhere.

## Older executable provenance follow-up

At the user's suggestion, queried Archive.org's public metadata search for
`title:(The Sims 2 Ultimate Collection) AND mediatype:software`, requesting only
identifier/title/creator/license fields. It reported six matches; returned results
included game-labelled uploads, a link-only item, a fix and Graphics Rules Maker.
Search matches are not six verified copies of the game. No game executable or
archive from those listings was downloaded. Uploader-supplied labels/licenses do
not establish authorized distribution or an unmodified/unprotected executable.
No suitable code input was verified by this check. An independently supplied older
installation still needs its own hash, protection inspection and compatibility
analysis; Legacy assets are not assumed interchangeable with that engine.

## QFS verification reference

The portable bounded decoder was checked against QuickBMS
[`src/compression/refpack.c`](https://github.com/LittleBigBug/QuickBMS/blob/5315ffe664b88dc09ae783ad17d9dfd252b1c927/src/compression/refpack.c),
revision `5315ffe664b88dc09ae783ad17d9dfd252b1c927`. Repository root license is GPL v2;
individual source headers/notices also apply. The independent source/library
remain ignored, used only in an explicit host comparison; no QuickBMS code is
linked into or redistributed with the application. Source hash is pinned in the
dependency lock; verification compiles that exact C file without patches.

Format cross-checks also used OpenTS2/DBPFSharp's QfsCompression source at the
already recorded revision. That file identifies Nicholas Hayes and an MIT SPDX
license with additional zlib notices for adapted portions. No compressor or Unity
runtime is embedded. See RESOURCES.md and VERIFICATION.md for the supported
framing, test cases and exact real-resource byte comparisons.

## Console-game exclusion

Search found [abilliontokens/sims2-recomp](https://github.com/abilliontokens/sims2-recomp),
whose repository description explicitly targets the **original Xbox USA XBE** using
XboxXBERecomp. This is the substantially different console Sims 2 and is excluded.
GameCube/PPC console recompilers likewise do not supply the PC simulation or formats
merely because the title and CPU family resemble those in the Mac report.

## D3D9 → Vulkan

[DXVK Native upstream](https://github.com/doitsujin/dxvk/tree/d713ef8748a1eee3e90d4b6d5dc2e80f5be4b519),
zlib core with additional notices in included headers/dependencies.
README explicitly describes native ports without Wine and SDL3/SDL2/GLFW WSI.
This makes it a plausible rendering backend, not a complete OS runtime.

Major risks: guest/host pointer width, full COM ABI surface, shader model/caps,
texture formats and compression, Android WSI/lifecycle, driver extensions/limits,
shader cache and thermal performance. Modern and legacy DXVK versions have
different Vulkan requirements; do not promise a version or GPU compatibility until
the target renderer and actual device capability report are measured.

## Effort and selection

| Approach | Full PC parity route | ARM64 feasibility | Principal effort / risk |
|---|---|---|---|
| Windows static recompilation | Keep original simulation, content paths and ABI semantics | Plausible; a related game publishes ARM64 runtime source | Large: control-flow recovery, guest services, D3D COM, exceptions, timing and middleware |
| Public Mac PPC reuse | Could keep PC-family simulation but expansion scope needs checking | Reported ARM64 Mac menu; Android unverified | Unavailable input code/license today; endian and platform APIs remain |
| OpenTS2 extension | Reimplement every missing simulation/UI/save behavior | Unity can target Android; current project build not tested | Very large preservation/compatibility risk despite useful resource work |
| Las Marionetas extension | Fill original-binary-dependent gaps | Requires full missing-code translation on ARM64 | Windows x86 ABI coupling plus incomplete standalone engine |

Choose A provisionally, with a bounded proof before major investment. See
[ARCHITECTURE.md](ARCHITECTURE.md). No claim of a short path to playable Sims 2.
