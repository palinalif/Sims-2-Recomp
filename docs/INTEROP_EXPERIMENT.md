# Scoped original-code experiment — 2026-10-21

Later owner-local results: the first function passed 64/64 cases on physical
ARM64, and one second branching/arithmetic function passed 64/64 host reference
cases. See [LOCAL_VALIDATION.md](LOCAL_VALIDATION.md). The record below describes
the earlier experiment at the time it was run.

**Result: approved private code recovery succeeded; one original function was
lifted to C and matched an x86 reference in 64/64 cases. The generated C compiled
for ARM64, but has not executed on ARM64.** Static recompilation is now supported
by a small original-code proof, not merely the earlier synthetic experiment.
There is no game initialization or playable application.

## Scope and preservation

The user explicitly approved the experiment in PROTECTION_DIAGNOSIS.md, with
metadata validation before recovery, unchanged originals, private ignored outputs,
one function only, no Steam authentication bypass, no modified-game launch, no
redistribution and no broader engine or Android integration. This pass stayed
inside that scope. No other executable was downloaded and no Steam process/account
was used. Legal applicability remains subject to the conditions in the approval.

Original `EP9/TSBin/Sims2EP9.exe`, Legacy 1.18.0.187, x86 PE32, SHA-256:
`24041f834e979cc088714713c3207540ff9093f51ff126450a4f7989432156b6`.
The original and its private working copy retained this hash at the final audit.
The private `work/interop-legacy-001/` directory is mode 0700; original/analysis
PE copies are mode 0600, not executable. Source and generated proprietary code,
decoded bytes, harness, binaries and detailed results remain Git-ignored there.

## Parser extension and metadata gate

The pinned pcrecomp dependency was left unchanged. A separately copied tool received
[the isolated patch](../patches/pcrecomp/0001-steamstub-analysis-metadata.patch).
It adds metadata-only inspection and a separate analysis recovery API. The existing
CLI/unwrap behavior remains unchanged. For this loader, the caller supplies the
**reviewed 0xF0-byte size**, observed in plaintext loader instructions; the patch
does not claim automatic recognition of that instruction layout.

The decoded metadata passed these checks **before** code recovery:

| Field | Observed / validated |
|---|---|
| SteamStub signature | `0xC0DEC0DF` |
| Image base | `0xA0000000`, matches PE |
| App ID | `3314070`, matches supplied installation VDF filename |
| Flags | Zero; no set flag bits or special variant handling assumed |
| Header preferred VA / size | `0xA11E1220` / `0xF0`, entirely backed by `.bind` |
| Code preferred VA | `0xA0001000`, `.text` start |
| Code bytes | `0xD98800` = 14,256,128, nonzero, AES-block-aligned and raw-backed |
| Original entry preferred VA / RVA | `0xA08248A3` / `0x008248A3`, inside the code range |

The code range includes raw padding beyond the section's declared virtual length;
this is accepted as file-backed encryption input, while the original entry must
remain inside the virtual section. No code offset/key guessing or brute-force
search was used. Metadata keys/IV bytes were not printed or committed.

Independent source review found a missing raw-range non-overlap check in the new
inspector. Authored overlapping-header/wrapper fixtures failed before the fix and
passed after it. The final patch rejects code overlaps with PE headers, other
sections and certificate data; this installation passes those checks. The review
recheck reported no remaining Important/Critical findings. This was a parser
validation defect in synthetic fixtures, not an assumption failure on the owned
binary, and no original file was changed.

## Code recovery

The existing upstream **AES-256-CBC** implementation recovered the declared code
range and passed its padding/exact-length checks. No changes to the cipher were
needed. The resulting analysis image has SHA-256:

`63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985`

Only that raw code range differs. Every PE header, entry-point field, Steam import,
wrapper byte, other section and the 10,584-byte certificate overlay is unchanged.
The file still points at the wrapper; it is **not a launchable compatibility
product**. Its old image signature is invalidated by changed code; preserving
certificate bytes does not preserve signature validity.

`.text` entropy fell from 7.999986 to 6.658805 bits/byte. The recovered original
entry decodes as coherent startup control flow; the reviewed function and caller
also decode coherently. These are stronger checks than entropy alone. No Windows
PE, original or modified, was launched. No Steam validation/ownership checks were
patched out or replaced. The only executed original bytes were the selected
19-byte leaf inside the bounded x86 reference fixture.

## Exactly one original function

Selected preferred VA **`0xA0001070`**, RVA **`0x1070`**, **19 bytes**; leaf SHA-256:
`3a32b6526f23eadf353f95e8d33392d8a303ecae4496a354cff28118759cb27a`.
A recovered direct caller at RVA `0x1AB6C7` references it. The function reads an
object pointer and two 32-bit stack arguments, stores those values at object
offsets `+0x28` and `+0x2C`, then returns with cdecl caller cleanup. It has no
imports, branches, TLS access, allocation, callback execution or global data reads.
Its symbol and gameplay role are unknown. This is a real original helper, not a
simulation or controller-hook milestone.

The private probe verifies the analysis-image/function hashes and the exact
manually reviewed operand contract before execution. It does not relax the
project's existing general stack-only leaf gate. A single upstream-generated
function is shared by all cases; the upstream lifter was **not modified**.

Verification used 32 boundary/deterministic-random value pairs in two initial
arithmetic-flag states, with aligned object pointers and guest code/stack/data
addresses above `0x80000000`. Unicorn maps a bounded 256 KiB guest window and
limits execution to the selected function; write hooks permit only the two object
fields. Every case is checked against both the original x86 execution and a
separate expected-state oracle.

**64/64 cases matched** for all eight integer registers, modeled defined flags,
return-stack adjustment and complete window memory differences. Object canaries,
callee-saved registers and stack bytes are checked. This does not test indirect
dispatch, complex instructions, exceptions, threading or arbitrary memory access.

The same generated C cross-compiled with NDK r27c into an Android API 26 AArch64
shared ELF (machine 183); all four LOAD alignments are 16,384 bytes. This is a
standalone compile check, **not Android integration or execution**. No ARM64 device
was available for this experiment; no ARM64 execution result is claimed.

## Reproduction and evidence

Independent patch tests use authored data only:

```sh
pip install -r tools/interop-requirements.txt
python tools/fetch_pcrecomp.py
python -m unittest discover -s tests -p test_steamstub_patch.py -v
```

Seven tests pass: metadata-only operation, valid recovery/preservation, malformed
metadata, wrong App ID, truncated backing, incorrect sizes, bad ciphertext,
overlapping headers/sections/certificate data and the existing copy pattern.
The separately patched upstream tool's `--selftest` also passes. Tests skip
explicitly if the optional dependency/source is unavailable; they never unpack
game inputs. Whole-repository verification is recorded in VERIFICATION.md.

The approved private run used:

```sh
PYTHONPATH=/workspace/.tools/python python3 work/interop-legacy-001/recover_analysis.py
PYTHONPATH=/workspace/.tools/python python3 work/interop-legacy-001/probe_one_original.py
```

These scripts and their detailed compiler commands/results are private analysis
artifacts, not portable public game-code fixtures. Recovery output is exclusive:
rerunning recovery will not overwrite the existing analysis image. Final audit
records their hashes, original preservation, patch hash and ARM64 ELF checks.
No proprietary code is embedded in this document or the patch tests.

## What failed, and what remains

- The unmodified upstream copy-pattern detector does not handle this loader.
  The reviewed-size metadata API addresses this case; a general semantic locator
  has not been implemented or claimed.
- One synthetic raw-overlap regression exposed a new checker bug; fixed and
  independently re-reviewed. No unresolved discrepancy appeared in the actual
  metadata/code/one-function comparison.
- ARM64 **execution** is still unverified. A small MOV-only helper cannot establish
  broad x86/SIMD correctness or game compatibility.
- Function catalogs, callbacks/vtables, 32-bit ABI marshalling, SEH/TLS, Win32/Steam
  services, D3D9 translation and game initialization remain unimplemented.

**Assessment:** original-code access is no longer the blocker for this exact
owned build. Native ARM64 static recompilation looks technically feasible, with
limited evidence for one function and substantial runtime work still ahead.
The scoped experiment is complete. No broader engine/Android development or
additional function execution has begun. Next useful evidence is execution of
this same probe on real ARM64; expanding into another function/callback/runtime
requires the user's further scope approval.
