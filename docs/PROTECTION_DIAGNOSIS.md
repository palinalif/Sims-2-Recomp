# Owned Steam executable: read-only protection diagnosis — 2026-10-21

This records the diagnosis **before approval**. The user subsequently approved the
scoped local experiment. Recovery and one-function validation succeeded; see
[INTEROP_EXPERIMENT.md](INTEROP_EXPERIMENT.md) for current results and limits.

**Recommendation: retain Windows static recompilation. Investigate a targeted
extension of the existing SteamStub parser; do not switch to an engine rewrite.**
The user clarified that legitimate interoperability research is in scope, but
unpacking requires separate approval. No protected header/code was decoded, game
process launched, memory dumped, or replacement executable downloaded in this pass.

## Identity and concrete observations

User-supplied `EP9/TSBin/Sims2EP9.exe`: version **1.18.0.187**, Windows **x86 PE32**
(machine `0x14c`, optional-header magic `0x10b`), 18,662,696 bytes, preferred image
base `0xA0000000`, large-address-aware. SHA-256, freshly recomputed and unchanged:

`24041f834e979cc088714713c3207540ff9093f51ff126450a4f7989432156b6`

| Section | RVA | Raw size | Entropy, bits/byte |
|---|---|---|---|
| `.text` | `0x1000` | `0xD98800` | 7.999986 |
| `.rdata` | `0xD9A000` | `0x250A00` | 5.692031 |
| `.data` | `0xFEB000` | `0xDE400` | 4.794596 |
| `LBMPEG_D` | `0x110B000` | `0x400` | 6.572457 |
| `.rsrc` | `0x110C000` | `0x3000` | 5.266223 |
| `.reloc` | `0x110F000` | `0xD1600` | 6.449329 |
| `.bind` | `0x11E1000` | `0x2D7D0` | 7.976127 |

Entry RVA **`0x011E1310`**, preferred VA **`0xA11E1310`**, file offset
`0x0119C710`, lies in executable `.bind`, not `.text`.

The first **21 entry bytes exactly match** `V3_PROLOGUE` in the pinned
[pcrecomp SteamStub source](https://github.com/sp00nznet/pcrecomp/blob/c0cbd3e3653010782b17e8a87b58953608ea411c/tools/drm/steamstub.py#L203).
Its instruction sequence is `call $+5`, register saves, retrieval of the saved
return address and subtraction of five to recover its own address. The plain
loader also compares a header field against **`0xC0DEC0DF`** at preferred VA
`0xA11E149D`, matching the tool's SteamStub 3.x header-signature check.
The visible loader copies **`0xF0` bytes from entry-minus-`0xF0`** into a local
buffer. This is observed instruction behavior, not a decoded protected header.

**Diagnosis: SteamStub 3.x-family wrapper identified with high confidence.** An
exact minor variant, protected-header field layout, flags and particular code
encryption parameters remain unconfirmed until an approved decoding experiment.
No plain SteamStub/steamdrm.dll/SecuROM/SafeDisc/UPX marker strings were found in
the checks performed; absence is not evidence that no additional protection exists.

There are 438 direct imports across 17 DLLs, including `d3d9!Direct3DCreate9` and
eight `steam_api.dll` functions: RunCallbacks, RegisterCallback, UnregisterCallback,
Shutdown, GetHSteamUser, SteamInternal_ContextInit, FindOrCreateUserInterface and
SteamInternal_SteamAPI_Init (SteamAPI names abbreviated here). Full names remain
in the ignored read-only report.

Steam API imports establish **ordinary Steam integration**, not encryption. The
separate evidence for a protected code image is the exact wrapper-entry signature,
header-magic check, `.bind` entry, visible header-copy loader and essentially
uniform `.text` bytes. AES-256-CBC is the supported upstream 3.x scheme, but its
applicability to this precise payload has not been verified by decrypting it.

## Does the existing tool support this binary?

The pinned tool's SHA-256 is
`6a3724044bdb471454646d8504d53fe60f6aad45a07dc1d841e7bacaff0433f7`.
Source inspection and raw-byte pattern comparison show:

- The 2.x entry signature does not match; the 3.x signature does.
- `unwrap_v3()` requires `V3_COPY`: a `push immediate; lea eax,[ebx+disp]; push eax`
  byte pattern in the first `0x100` entry bytes. That pattern is absent, including
  in the larger `0x200`-byte check. This binary uses local-variable assignments,
  `sub ecx,0xF0` and a byte-copy loop instead.
- Therefore the unmodified tool would stop at **“3.x stub does not copy its header
  the known way”**, before header decoding. This conclusion follows from source
  branches and byte matching; `unwrap()` was not called on the supplied executable.
- Upstream `--selftest` passed using its built-in fixtures only. It does not test
  Sims 2. Upstream file history identifies prior 3.x validation on Shadows of the
  Empire/Rogue Squadron; it supplies no evidence of Sims 2 compatibility.

A focused locator extension is plausible. Correct header offsets, code range,
original entry point and decryption still need validation; signature recognition
alone is not a successful unpack. Keep any upstream patch separate and tested.

## Are original game functions available now?

Imports, resources, relocations, readable data/engine strings and the plain wrapper
are available for static inspection. Main `.text` does not presently provide
reliably recovered original function bodies. Random-looking x86 bytes can still
disassemble; that would not establish valid game code. No original gameplay leaf
was recovered or executed. The visible wrapper and readable JPEG middleware are
not substitutes for original simulation code.

## Proposed experiment — requires approval

1. Preserve and rehash the original; work only on a private ignored copy. Review a
   separate parser extension against the visible loader and authored test fixtures.
2. Decode only the wrapper metadata first. Validate signature, preferred image
   base, field/range bounds, flags and original entry point. Stop on mismatches.
3. Only if those checks justify it, recover the indicated code bytes using the
   verified wrapper scheme into a separate **analysis-only** image. Reparse it,
   inspect startup/control flow and relocation targets, and record input/output
   hashes. Do not launch it or label it a working no-Steam executable.
4. Select one original import-free integer leaf, build a reviewed fixture, lift
   with the existing pinned recompiler, and compare registers/flags/memory against
   a suitable x86 reference. Then compare on actual ARM64. Only proceed to a wider
   function catalog and guest-to-host callback after that gate passes.

The current file has 10,584 trailing bytes occupying the PE security directory;
the tool's “drop .bind at EOF” condition would not apply unchanged. Image edits
invalidate the existing image signature; no signature trust validation is claimed.
Recovered code does not solve function recovery, TLS/SEH, vtables, Win32/D3D9,
Steam service portability or redistribution/licensing. No authentication-service
bypass is part of this proposed experiment. No proprietary input/output is committed.

Ownership is relevant but not blanket authorization to circumvent protection.
Interoperability exceptions have conditions: for example,
[17 USC 1201(f)](https://www.law.cornell.edu/uscode/text/17/1201) concerns necessary,
previously unavailable interoperability analysis of an independently created
program and requires non-infringing conduct. Whether this project qualifies
depends on jurisdiction, facts and applicable terms; do not assume an exemption.
Local analysis, distributing tools, distributing recovered code and shipping a
derived application are distinct questions. Obtain appropriate legal advice before
the approved experiment if that applicability is uncertain. No legal permission
is inferred merely from the fact that the tool can perform the operation.

## Other legitimately obtained releases

| Input | Recompilation tradeoff |
|---|---|
| Supplied Steam Legacy | Best immediate candidate: owned input, exact fingerprint and matching asset samples already available. Existing wrapper tool needs a targeted extension/validation. |
| Existing EA/Origin Ultimate Collection installation | Relevant PC x86 alternative and the version family targeted by Las Marionetas. Inspect the actual owned executable/hash/protection first; no unprotected build is verified here, and Legacy assets cannot automatically be paired with it. |
| Owned original base-game/expansion discs | Potentially useful for the requested base-game milestone. Protection and patch levels must be inspected independently; older releases are not inherently unprotected and do not supply the final expansion engine automatically. |
| Legitimate EA-store Legacy installation, if available to the user | Worth comparing an actual supplied binary; a different storefront does not prove a different or unprotected code image. No such input is available here. |
| Aspyr Mac Super Collection | Legitimate currently listed PC-family alternative, but a different platform/API/ABI target with only six expansions and three stuff packs. Store listing does not identify the supplied executable's ISA or protection; it is not evidence of access to the reported old PPC recompilation. |

References: [Las Marionetas' pinned README](https://github.com/OmniBlade/LasMarionetas/blob/b1f378c92dca777b31cc8dfe0cebe3f8f6c345c7/README.md),
[Aspyr's Mac App Store listing](https://apps.apple.com/us/app/the-sims-2-super-collection/id883782620).
Neither supplies a verified replacement Windows executable. No pirated executable
was sought or downloaded. **Next action: request approval for the scoped local
metadata/code-recovery experiment above, keeping static recompilation as path A.**
