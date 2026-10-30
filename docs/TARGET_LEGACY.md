# Steam Legacy Collection target analysis — 2026-10-21

The user-provided installation is readable. Its assets are useful for the native
resource work. After explicit approval, private metadata/code recovery succeeded
and one original 19-byte helper passed 64/64 host reference cases. Its generated C
compiled for ARM64 but has not executed there. The original is unchanged and no
modified PE was launched. See [INTEROP_EXPERIMENT.md](INTEROP_EXPERIMENT.md).
See [PROTECTION_DIAGNOSIS.md](PROTECTION_DIAGNOSIS.md) for the subsequent exact
SteamStub 3.x signature findings and recommended static-recompilation experiment.

## Acquisition and provenance

The target binary is the Steam Legacy Collection build of The Sims 2
(Sims2SP9.exe, 2004/2009-era `ReleaseSRT` metadata). It was supplied privately by
the project owner from a legitimately acquired installation. The binary analysed
throughout this repository is the owner-supplied executable plus a derived,
locally-produced analysis image (SteamStub wrapper removed from the code range for
static analysis; see `PROTECTION_DIAGNOSIS.md` and `patches/pcrecomp/`).

Details of the private transfer are intentionally not documented here and are not
part of this repository. No game binaries, archives, or resources are contained in
or redistributed by this repository.

## Executable fingerprint

| Property | Observed value |
|---|---|
| Relative path | `EP9/TSBin/Sims2EP9.exe` |
| SHA-256 | `24041f834e979cc088714713c3207540ff9093f51ff126450a4f7989432156b6` |
| Bytes | 18,662,696 |
| Format | Windows PE32, x86, large-address-aware |
| File/Product version | 1.18.0.187 |
| Description | The Sims 2 Legacy |
| Product name | The Sims 2 EP9 |
| Original filename metadata | Sims2SP9.exe |
| Build metadata | 2025-04-07-1003, ReleaseSRT |
| Preferred image base | `0xA0000000` |
| Entry RVA / preferred VA | `0x011E1310` / `0xA11E1310` |
| Entry section | `.bind` |
| TLS | Directory present, eight raw TLS bytes, callback table begins with null |
| Direct imports | 438 across 17 DLLs; no delay imports reported |

The high image base makes unsigned 32-bit guest address handling a practical
requirement. Host pointers, signed guest addresses and low-address assumptions
would be incorrect even before considering ARM64 ABI differences.

The `.text` raw size is 14,256,128 bytes and its Shannon entropy rounds to 8.000
bits/byte; executable `.bind` entropy is 7.976. Together with the `.bind` entry and
Steam interfaces these strongly indicate executable protection, consistent with a
Steam wrapper. The follow-up now also identifies an exact SteamStub 3.x entry
signature and loader magic check, but not a precise minor variant. Disassembling those
original wrapped bytes as ordinary game functions would be unreliable. At initial
intake no unpacking was performed; the later approved experiment recovered the
code using an isolated patch without process dumping or modified-PE execution.
The fingerprint registry still describes the wrapped original, which the public
leaf probe rejects before decoding. Recognition never enables game execution.

## OS and middleware surface

| Evidence | Implication / remaining work |
|---|---|
| `d3d9.dll!Direct3DCreate9` | D3D9 confirmed; DXVK Native remains a candidate, not an integrated backend. Actual shaders, render states and device capabilities remain unmeasured. |
| `DSOUND.dll` ordinal 1; WINMM 12 imports | DirectSound and multimedia timing/file interfaces present. Mixer behavior, stream formats and threading remain unknown. |
| MSVFW32 and AVIFIL32, eight imports each; `vp6vfw.dll` On2 VP6 6.0.6.4 | VfW/AVI and VP6 dependency evidence; no native decoder selected or playback verified. |
| `ijl15.dll`, Intel JPEG 1.51.12.44 | x86 image middleware; translating it would not establish execution of Sims simulation code. |
| USER32 85, GDI32 13, IMM32 8 | Window/message, cursor/key, graphics and text-input adaptation required. No direct DirectInput/XInput imports observed. |
| KERNEL32 213 | File/memory, QPC/timing, threads, synchronization, TLS, exception and dynamic-loading services. Imports do not establish simulation tick cadence or thread ordering. |
| ADVAPI32 25; SHELL32 4; VERSION 3 | Registry/security, paths and version services require native equivalents with guest-width handles. |
| ole32 9; OLEAUT32 3 | COM/automation semantics require investigation and marshaling. |
| WS2_32 27; WININET 10 | Network APIs present; required offline behavior is not established. |
| steam_api.dll 8 | Steam initialization, callbacks, interfaces and shutdown are part of this build's boundary. No replacement or authentication bypass implemented. |

Dynamic `LoadLibrary`/`GetProcAddress` imports mean the direct census cannot exclude
other middleware. C++ vtables/indirect calls, SEH, callbacks and per-thread TLS are
still unresolved runtime work; instruction translation alone cannot start the game.

## First native resource slice

Three CRC-verified package samples were parsed by the new portable C++ `Dbpf`
reader and independently checked against Python little-endian index reads:

| Package | DBPF / index | Result |
|---|---|---|
| `EP9/TSData/Res/Lighting/lighting.package` | 1.1 / 7.1 | One uncompressed resource, 8,238 bytes, native output byte-for-byte matches the independently sliced payload. |
| `Base/TSData/Res/Catalog/Skins/FaceInfo.package` | 1.0 / 7.0 | Two entries including DIR; 635 compressed bytes decode to 2,716 bytes, independently byte-matched. |
| `Base/TSData/Res/Wants/WantTuning.package` | 1.1 / 7.1 | Two entries including DIR; 2,668 compressed bytes decode to 11,905 bytes, independently byte-matched. |

Lighting resource key: type `0x856ddbac`, group `0x8ba01057`, instance `0x6fb59732`.
Payload SHA-256:
`1b2151eefac283d9d02ee4a477d9691efbd2ebdd7b39edd01bf94b6230dc0a46`.
The native reader validates bounds, versions, duplicate keys and compression DIR
references. The QFS decoder now reads both compressed samples with exact-size
and back-reference checks. Their decoded SHA-256 values are:

- FaceInfo: `c77b50651c3061a0dfbd3e9f5d97c35347bfb8aa6c288f4841372bb04e880920`
- WantTuning: `a8aa3798ebc3812b10cb0195f07693dd3fcd6e1b22d93767b4dd8d4cdae3e82d`

Lighting contains a 64 × 64 PNG. Android now builds a read-only single-package
SAF → native decode → hash/report/PNG-preview path, but it has not run on a device.
No game renderer or Android installation mount exists. See [RESOURCES.md](RESOURCES.md)
for exact format limits and the device checklist.

Small configuration samples confirm package/DB segment organization and references
to sound Misc, Sfx, Voice, Build, Buy, CAS, Neighborhood and Splash packages. This
does not establish runtime overlay ordering, save serialization, audio behavior or
mod compatibility. Installed neighborhood templates are not user saves.

## Decision and next evidence

Retain the provisional Windows static-recompilation architecture and portable
asset work. This particular executable cannot currently provide the first original
leaf without protected-code recovery. The approved scoped experiment has now
completed successfully using a reviewed-size metadata API in an isolated patch.
This removes original-code access as a blocker for the exact supplied build.
One helper is verified, not simulation or startup. M3 initialization and ARM64
execution remain unverified; broader work is paused pending further scope approval.
No switch to a complete engine rewrite is proposed.
