# Resource precedence investigation — 2026-10-21

## What the supplied Legacy installation shows

The local Steam Legacy Collection has Base, EP1–EP9, SP1, SP2 and SP4–SP7
product roots. It contains 16 `TSData/Res/Wants/WantTuning.package` files: one in
Base, one in each EP, and one in each present SP. `EP9`'s copy is 9,211 bytes and
has SHA-256 `ac339abcb87d2fd371d564594e29c577ba4392d84c4045a6ebd36ab6519d51d9`.
Four SP copies (SP1, SP2, SP4, SP5) are byte-identical to EP3's copy, with
SHA-256 `e80e98074f4afea35bab519512d8e966e5bed5c95e386173ecad7ede1d324577`.
SP6 and SP7 are byte-identical to EP4's copy, with SHA-256
`6e36ec6afa0f41c3d9ed4fff6153c6c34b5da315a5946fd4264691ef26383e87`.
These are read-only file hashes; no package bytes are tracked here.
An index-only scan of these 16 bounded files found one non-DIR resource in
each, always with key `(type=0x00000000, group=0xcda53b6f,
instance=0x2d7ee26b)`. Thus every copy is a direct duplicate-key candidate.
This still does not identify the winner in the original game's lookup.

The same installation contains `EP9/TSData/Res/Objects/objects.package`
(114,288,720 bytes) and `EP9/TSData/Res/Overrides/Overrides.package`
(4,809,832 bytes). Base and multiple other products have their own
`objects.package`. Names, sizes, and duplicate file hashes show candidate
overlaps, not which packages the original executable opens or which resource
wins when keys collide.

Text configuration under `Base/TSData/Res/Config` and `EP9/TSData/Res/Config`
contains no package priority manifest in the inspected `.txt`, `.xml`, `.sgr`,
and `.cheat` files. `EP9/.../LogSettings.cheat` has a `Resources` log filter and
`SimResource` reporters; enabling or interpreting them would need a separate,
controlled run of the original game.

## OpenTS2 reference behavior

[OpenTS2's `Filesystem.cs`](https://github.com/LazyDuchess/OpenTS2/blob/bdabb07f4689ed91803a3d86dcbc8870b8832878/Assets/Scripts/OpenTS2/Files/Filesystem.cs)
iterates products for several resource directories. For GlobalLots,
LotTemplates, Materials, Objects, ObjectScripts, and Wants, it replaces the
directory's package list when a later product has that directory. Its
`GetLatestFilePath` also searches products in reverse order.

[OpenTS2's `ContentManager.cs`](https://github.com/LazyDuchess/OpenTS2/blob/bdabb07f4689ed91803a3d86dcbc8870b8832878/Assets/Scripts/OpenTS2/Content/ContentManager.cs)
places newly added resources at the top of its map, so later additions win a
matching key. [Its `ContentLoading.cs`](https://github.com/LazyDuchess/OpenTS2/blob/bdabb07f4689ed91803a3d86dcbc8870b8832878/Assets/Scripts/OpenTS2/Content/ContentLoading.cs)
then adds user packages and downloads after game packages. This is the behavior
of an independent open-source implementation, not a trace of the supplied
Legacy executable. In particular, its "latest directory" selection is different
from mounting every same-named package and resolving every duplicate key.

## Bounded original-executable directory evidence

A read-only static pass over the same pinned Legacy analysis image used for
[OBJECT_QUERY_CALLER.md](OBJECT_QUERY_CALLER.md) located directory strings and
their direct references. The routine beginning at RVA `0xCA8710` repeatedly
passes a directory name, two numeric identifiers and two further arguments to
the same virtual method at vtable `+0x0C`. The constructor around `0xC261AC`
sets the relevant subobject's vtable to `0xE98510`; slot `+0x0C` resolves to
`0xCA7230`.
That method copies the path, branches on its fourth argument between two
registry structures at object `+4` and `+0x0C`, and inserts or updates a
record. The helper at `0xCA9B00` copies the fifth argument into that record's
`+0x28` field. It is a directory/key registration operation, not a direct package
read or duplicate-key lookup.

Within the registration routine, `Objects/` at `0xCA91EE`, `Overrides/` at
`0xCA9207`, and `Wants/` at `0xCA92BB` pass fourth argument zero and fifth
argument `0x20000` (the constant returned by `0xB39360`). `Downloads/` also
appears in the table at `0xCA8D93`, with fourth argument zero and fifth
argument `-1`. Earlier code references the `TSData` string at `0xCA7748`,
`0xCA7823` and `0xCA82D5`, and the `ep%ddir` setting at `0xCA77E0`.

The separate path-setup routine at `0xCA75C0` uses the same virtual
registration method. It first registers a path with fifth argument `-1` at
`0xCA7675`. Its indexed loop starts with zero at `0xCA7C37`, increments the
index at `0xCA8543`, and repeats while the index is at most 31. On one
guarded path, the call at `0xCA84E9` passes `1 << index`
as the fifth argument. Another branch at `0xCA8465` passes `0x20000`.
This establishes ascending **registration attempts** with per-index values;
it does not establish package enumeration order or collision resolution.

One consuming method is also visible. Vtable slot `+0x2C` resolves to
`0xCA5ED0`. It finds a registered key, copies its candidate list through
`0xCA4B10`, then walks candidate records. The copy walks source nodes forward
and appends each copy. The consumer tests record `+0x28` against a requested
mask, calls another virtual method for a matching candidate, and can break
the current candidate loop after a successful result. It then has a second
candidate pass. This establishes mask-dependent attempts in this routing
layer, but does not establish the downstream package lookup or the winner for
the `WantTuning` duplicate key.

The duplicate key is used directly by this executable: the caller around
`0x494082` builds `(type=0, group=0xCDA53B6F, instance=0x2D7EE26B,
extra=0)` and invokes a resource-service virtual method at `+0x9C` at
`0x4940BE`, branching on its success result. That proves a lookup attempt for
this exact key, not which of the 16 installed `WantTuning.package` copies
supplies its payload. The service pointer is cached by `0x20DEB5` after
`0x20DB69` queries the runtime service registry with identifiers
`0x056B906E` and `0x656B8EFC`.

### Resource-service provider follow-up — 2026-10-22

The constructor at `0x9B3F30` installs a base vtable at `0xE60274` and tags
the object with service ID `0x056B906E`. Its first method at `0x9B5100`
accepts interface ID `0x656B8EFC`. The factory at `0x1D3E20` allocates the
derived object through constructor `0x1D8B90`, then passes that object to the
runtime service manager at `0x1D3E90`. The derived constructor replaces the
base vtable with `0xDA5D74`. This ties the registry query to a concrete
provider rather than just the interface IDs.

For that derived vtable, slot `+0x9C` is `0x1E2850`; the base slot is
`0x9B50A0`. The exact `WantTuning` caller passes zero as the third argument
at `0x4940AA`. The derived method has a guarded fast path depending on fields
at object `+0x22D` and `+0x84`; its fallback at `0x1E2C04` calls the base
method. The base method calls virtual `+0x88` to select a source, then calls
that source's `+0x58` method to open the key. These static branches do not say
which guard state is active when the game looks up `WantTuning`.

The derived `+0x88` method at `0x1DEA30` normalizes part of the resource key,
finds a per-key candidate vector at object `+0x114`, and returns the first
source whose virtual `+0x50` method accepts the requested key. When the vector
is absent, `0x1E95C0` builds it by enumerating the shared source list through
virtual `+0x94` (`0x9B45F0`); callback `0x1E9710` appends qualifying sources
to the vector. The shared list's enumeration walks forward from its head.
Derived source attachment through `+0x70` (`0x1E36F0`) calls the base routine
`0x9B52C0`; derived `+0x74` (`0x1E36E0`) delegates to `+0x70`.
Correction (2026-10-22, later pass): `0x9B52C0` is **not** a prepend. It locks
the container at object `+0x68`, add-references the source, and stores the
pointer into the dense slot array of an open-addressing hash set at object
`+0x70` (buckets `+0x04`, count `+0x08`, mask `+0x0C`, size `+0x10`), growing
it through `0x1D4740` when full. `0x9B45F0` enumerates that same container by
walking the dense index from `+0x7C` up to `+0x7C + +0x80`, mapping each index
to `bucket[index / 4][index % 4]`. So enumeration order is **attachment order,
oldest first**, and a cold rebuild visits older attachments first.
The rebuild then partitions the candidate vector at `0x1E9635` (or `0x1E96C1`
for larger vectors). The small-vector routine `0x1D6B00` is a stable insertion
sort whose comparator asks each source for interface ID `0x286D4A6A` and keeps
only the boolean (`setne` at `0x1D6B8B`/`0x1D6BA7`), shifting while the left
value is below the right (`cmp`/`jae` at `0x1D6BD0`-`0x1D6BDA`). It therefore
only moves sources that answer that interface ahead of sources that do not; it
never reorders within one class. Thus collection order is the order within each
class, and the first matching source is selected from that partitioned vector.
The behavior for later updates still needs validation.
The derived constructor initializes a counter at object `+0xC8` to `0x1388`
(5,000) at `0x1D8C10`. On the `+0x70` path, when the source is absent from
the auxiliary list at object `+0xD4`, `0x1E37CF` takes the current counter
and increments it; `0x1E37E7` passes the taken value to that source's virtual
`+0x40` method. This proves an increasing value for newly seen sources, but
not what a source does with it or which installed package it represents.
Attachment also calls map-maintenance routines `0x1E9B50` and `0x1E97B0`;
their effect on an already populated per-key vector has not been resolved.
The installed package-to-source attachment sequence and any later reordering
remain untraced, so this does not identify a winning `WantTuning.package` copy.

This confirms an explicit directory/key registration path and a difference
between at least some game and user-directory arguments. The fifth argument
participates in a candidate-mask check; its bit assignments and the downstream
package lookup remain unresolved.
These registration calls do not prove which product root is searched first,
whether duplicate directories are merged, or which package wins a duplicate
key. This evidence therefore does not change `ReadOnlyResourceMount`'s
caller-defined order.

## Product enumeration and precedence — 2026-10-22 (second pass)

A focused pass over the directory-registry class and its product-setup method
resolved the product iteration order and the candidate ordering that the
earlier sections left open. All addresses are RVAs in the pinned analysis
image.

### The class

The vtable at `0xEB5468` (second implementation; the first is at `0xE98510`,
constructed at `0xC261AC`/`0xC266F6`, this one at `0xCA4CDC`/`0xCA4DEC`) is the
directory registry:

| slot | target | role |
| --- | --- | --- |
| `+0x0C` | `0xCA7230` | register a path under a `(key, subkey)` pair with a mask |
| `+0x2C` | `0xCA5ED0` | resolve a key: walk candidates, first success wins |
| `+0x38` | `0xCA75C0` | product setup (the loop below) |
| `+0x3C` | `0xCA8710` | logical subdirectory table (`Sys/`, `Res/`, `Wants/`, ...) |

Its own string pool sits immediately after the vtable: `TSData` at `0xEB54B0`,
`ep%ddir` at `0xEB54B8`, `/out/` at `0xEB54C0`, `NonShip` at `0xEB54C8`, and
then the logical directory names `Sys/`, `Control/`, `Res/`, `Logs/`,
`Export/`, `Downloads/`, `SavedSims/`, `Teleport/`, `PackObject/`, `Movies/`,
`Music/`, `HTTPCache/`, `PackagedLots/`, `PackagedSims/`, `Accessory.cache`,
`ContentRegistry`, `Packed/Objects/`, `Packed/Skins/`. `0xEA05A4` holds
`Directories`, the registry subkey these values live under.

### Product setup (`0xCA75C0`)

1. Before the loop, the already-resolved install root is registered twice under
   key `0x4BCFCE5E` with subkey `0`: once with mask `1` at `0xCA7871` and once
   with mask `0x20000` at `0xCA788F`. `0x1ACD4F` converts the string to a
   C-string argument; the flag argument is `0`.
2. The loop runs `edi` from `0` to `0x1F` inclusive (`inc edi` at `0xCA8543`,
   `cmp edi, 0x1f` / `jbe 0xCA7C40` at `0xCA8547`). Each iteration is skipped
   when the availability byte `[ebp + edi - 0xBC]` is zero (`0xCA7C40`); that
   array is filled by the detection pass in the same function's first half.
3. Per index the setting name is formatted from `ep%ddir` at `0xCA7C55` and read
   through the settings service (vtable `+0x20`) into `[ebp-0x60]` at `0xCA7CA2`.
   A missing value falls back to a second settings key `0x6C253729` at
   `0xCA7CF8`, then to branches using `/out/` (`0xCA813D`), `TSData`
   (`0xCA82D4`) and `NonShip` (`0xCA8307`).
4. Each resolved path is registered under key `0x4BCFCE5E`, subkey `0`, with
   mask `1 << index` (`mov eax, 1` / `shl eax, cl` at `0xCA84CA`-`0xCA84CF`,
   call at `0xCA84E9`). A companion registration of a second path variant uses
   the constant mask `0x20000` at `0xCA8465`. `0xB39360` returns that same
   constant `0x20000`, and `0xB39370` is the `1 << index` helper, so `0x20000`
   is a record class bit (the one used by the logical-subdirectory records such
   as `Objects/`, `Overrides/` and `Wants/`), not a product bit.
5. Index `0x11` is special: after its registration, `0xCA84EC`-`0xCA84FE` also
   stores the resolved path into the global string setting returned by
   `0x9C59D9` through that setting's virtual `+0x4C`. No `TS2DownloadsDir`
   reference exists in this function, so index `0x11` is a game-defined extra
   slot whose exact meaning is not established here.

The hardcoded product list lives at `0xEB7328` and is the only list split by
`0xCB4AA0` (its `push 0xa0eb7328` at `0xCB4AB2`), which `0xCB4BB0` calls and
which `0xCA7997` inside product setup calls:

```text
Sims2EP1.exe,Sims2EP2.exe,Sims2EP3.exe,Sims2SP1.exe,Sims2SP2.exe,
Sims2EP4.exe,Sims2EP5.exe,Sims2SP4.exe,Sims2SP5.exe,Sims2EP6.exe,
Sims2SP6.exe,Sims2EP7.exe,Sims2SP7.exe,Sims2SP8.exe,Sims2EP8.exe,Sims2EP9.exe
```

Sixteen entries in ascending index order, `Sims2EP9.exe` last. That is the
**registration order**, and it matches EA's release order rather than any
alphabetical order.

### Candidate ordering

`0xCA5ED0` (registry slot `+0x2C`) copies the candidate list for a key and
walks it forward, testing each record's `+0x28` mask against the requested mask
and breaking out of the loop as soon as a candidate succeeds. Registration
inserts records at the **front** of that list (`0xCA9B00` region reached from
`0xCA7230`, confirmed as a push-front insert in the earlier pass). Combining
the two: **the last product registered is the first candidate returned**, so
`Sims2EP9.exe`'s `TSData/Res` root precedes EP8, SP8, SP7, EP7, SP6, EP6, SP5,
SP4, EP5, EP4, SP2, SP1, EP3, EP2, EP1, and the install root registered before
the loop.

### Reading of that order at the resource-service layer

Sources are attached in the order their directories are enumerated, appended to
the insertion-ordered set described in the corrected paragraph above, and a
per-key candidate vector is built in that same order and only partitioned by the
`0x286D4A6A` interface test. So within one interface class the **first
attached** source wins. The per-directory `*.package` enumeration itself (the
pattern at `0xDCBC50`, used from `0xC2FA6C` and the sibling call sites in the
`0xC38000`-`0xC47FFF` cluster) was not traced end to end, so the attachment
sequence itself remains inferred from directory order rather than observed.

### Conclusion for the 16 `WantTuning.package` copies

With registration order EP1 → EP9, front-inserted candidates, and
first-candidate-wins resolution, the live copy for a fully installed Legacy
Collection is:

```text
EP9/TSData/Res/Wants/WantTuning.package
  size  9,211
  sha256 ac339abcb87d2fd371d564594e29c577ba4392d84c4045a6ebd36ab6519d51d9
```

The installed content agrees independently: that EP9 payload is a strict
superset of the EP3 copy (which every SP1/SP2/SP4/SP5 duplicate matches byte for
byte), so no lower-priority product can be the live copy without discarding the
newer wants records that ship in EP9. This is the answer the first section of
this document said it could not give.

Confidence: registration order, mask arguments, front insertion, forward walk
with break-on-success, and interface-partitioned first-match selection are read
directly out of the pinned image. The exact `ep<index>dir` → product-name
mapping is runtime registry data and is inferred from the hardcoded exe list
order. The `0x20000` record class and the `0x11` special case are described as
observed, not interpreted. No runtime trace was taken, so this remains static
evidence plus content-level corroboration.

### Ghidra cross-check — 2026-10-22 (second toolchain)

Queried the same pinned image through the persistent Ghidra 12.2 project
(`scripts/ghidra-query.sh`, image `63a545db…59985`, `x86:LE:32:default`, image base
`0xA0000000`, 44,151 analyzed functions). New or corroborating facts:

- `0xDCBC50` is a defined 12-byte string `*.package`, confirming the pattern address used above.
- Ghidra's analyzed references to that string are twelve `READ` sites: `0x4A2A1C`, `0x4A2B7D`, `0x4A2DBA`, `0x4A3137`, `0x4A47DC`, `0x4C14CA`, `0x4C3820`, `0x4C67F9`, `0x4D2C21`, `0x4D5DB8` and two more beyond the result cap. `0xC2FA6C` is **not** among them.
- At `0xC2FA6C` Ghidra has no instruction and no reference, yet the bytes there begin `50 bc dc a0`, the little-endian dword `0xA0DCBC50` — a real pointer to `*.package` sitting in a region Ghidra never decoded. So the earlier pointer scan and Ghidra's xref set genuinely differ in both directions, and a complete call-site list needs their union, not either one alone.
- The base source-attach routine `0x9B52C0` has exactly **one** caller: the derived `+0x70` implementation `0x1E36F0`, which has no direct (non-vtable) callers of its own. There is a single attachment funnel, so ordering is decided purely by the indirect call order of `+0x70` — which remains untraced.
- The per-key candidate rebuild `0x1E95C0` has nine callers: `0x1DF300`, `0x1E0140`, `0x1E5670`, `0x1E2510`, `0x1DEA30`, `0x1DF880`, `0x1DF740`, `0x1DE470`, `0x1DEC80`. The candidate vector is therefore rebuilt from many entry points, not only the `+0x88` selector `0x1DEA30`; any later attachment can invalidate a cached vector through several paths.
- Function extent, caller and callee queries at `0x1070`, `0x1250`, `0x1AB665` and `0x1ABD40` reproduce [OBJECT_QUERY_CALLER.md](OBJECT_QUERY_CALLER.md), including the `+0x34`/`+0x1C` guards, the `+0x7C` mode byte with `+0x60` string, the two direct callers of `0x1AB665`, and `0x1ABD40` passing `[+0x34]` to five accessors.

Limits: Ghidra auto-analysis leaves executable regions undecoded (the `0xC2FA6C` case above), so "no function at this RVA" is never evidence that no code exists; Ghidra function names, prototypes and pseudocode stay hypotheses. This subsection adds mapping/xref corroboration plus the single-funnel and multi-rebuild observations. It does **not** establish the attachment sequence, so the EP9 conclusion above keeps exactly the confidence it already claimed.

#### Open lead: who owns the `+0x70` attach slot

Derived from the Ghidra index only, with no runtime evidence, and left here as a
trace trail rather than a conclusion:

- The **only** reference to the derived attach routine `0x1E36F0` is a data pointer at RVA `0xDA5DE4`, typed `undefined *` in `.rdata`. That is a vtable slot, which is why the routine has zero code callers.
- Subtracting the interface offset gives vtable base `0xDA5D74`. The 32 bytes there decode to a dense table of pointers into code (`0x1E2E50`, `0x1DAB30`, `0x1E3980`, `0x1E0890`, `0x1E08E0`, `0x1E04A0`, `0x9B4C20`, `0x9B4B70`), so the base is a real vtable and the slot arithmetic is consistent. Slots `+0x18`/`+0x1C` sit in the same `0x9B4xxx` cluster as the base attach routine `0x9B52C0`.
- `0xDA5D74` itself is referenced from exactly two code sites, `0x1D8BD5` and `0x1D9CD2`, inside `FUN_a01d8b90` and `FUN_a01d9cb0`. Those look like the two construction sites of the object carrying the attach slot: `FUN_a01d8b90` (one caller `0x1D3E20`; six callees including `operator_new` at `0x9B4632`) and `FUN_a01d9cb0` (one caller `0x1DA310`; fourteen callees including `guard_check_icall` at `0x140FE0`, so it dispatches indirectly).

Suggested next step for a worker: walk `0x1D3E20` and `0x1DA310` upward toward the startup path and determine which site builds the long-lived resource service, then check whether the first `+0x70` call happens inside that flow or later in the product loop. The ordering question lives between those two construction sites, not inside `0x9B52C0`. Still unproven: that either constructor runs in the real game, that both run, and that the two sites are the same class rather than two classes sharing a layout.

## Durable read-only pointer search — campaign run 2, iteration 1

After sourcing `. scripts/campaign/worker-env.sh` on this host:

```sh
scripts/pointer-scan.sh --va 0xA0DCBC50 \
  > work/phase1-run2-001/package-pointers.json
```

`tools/pointer_scan.py` uses pinned `pefile` and defaults to the ignored
`work/interop-legacy-002/analysis-image.bin`. It opens the image read-only,
accepts PE32 only, and searches every byte offset (including unaligned and
overlapping words) for an exact 4-byte little-endian VA. Output contains only
RVAs, total count and truncation status; no image bytes or hashes. The default
256-result cap can be changed with `--max-results` (maximum 100000). Input is
bounded to 256 MiB. Truncation is not a complete result list.

Mapping is deliberately explicit: disk-backed headers and raw sections, including
raw padding; no overlay, virtual zero-fill or words crossing mapping boundaries.
Truncated, overlapping or out-of-image mappings fail closed. This is a raw search,
not an instruction decoder or an executable/hash authorization gate. Callers must
verify image provenance separately before interpreting results.

Measured here: exit 0, **21** pointer occurrences, not truncated, including RVA
`0xC2FA6C`. Bulk output remains ignored in `work/phase1-run2-001/`.
Six synthetic tests pass, including high-bit targets, RVA/file-offset mapping,
unaligned/overlapping words, caps, overlay exclusion, invalid mappings and CLI
read-only/error behavior. No fresh Ghidra query was run.

**Union rule:** collect the union of Ghidra references and raw pointer occurrences
as the candidate-reference inventory. Neither alone is complete (as the existing
12 READ references versus raw-only `0xC2FA6C` demonstrates). Normalize addresses to
RVAs before deduplicating. Even their union is **not a proven complete call-site
list**: raw matches may be data or cross-instruction coincidences; computed targets
may appear in neither set. Verify instruction alignment, reference type, consumers
and indirect dispatch independently before calling any candidate a caller.

**Attachment timing: undetermined.** No runtime binding or automatic precedence
was added. HYPOTHESIS: the two construction paths lead to the resource service,
but current evidence cannot label its first `+0x70` invocation startup-time versus
later. Settling this requires a verified constructor/service identity and a
reachable caller chain (or controlled unmodified-game trace) that records the
first and subsequent slot invocations relative to startup/product enumeration.
A pointer occurrence count cannot settle that ordering. Keep caller-supplied
mount order and the prior EP9 conclusion's static/inferred limits unchanged.

## Factory-range owner — run 3 iteration 2

One read-only persistent-index query at `0x1D3BE2` (40 instructions, no
pseudocode) resolves the containing function to `0x1D3B70`. Independent pinned
PE/Capstone decoding matches all 40 instruction boundaries and 17 selected
operand contracts; 17 single-instruction substitutions reject. This is static
inspection, not an original execution/reference-state result.

New dependencies and edges, all RVAs in the established analysis image:

- Before the range stores, `0x1D3B88` reads `FS:[+0x2C]`; `0x1D3B8E` loads
  the index from global `0x10DF814`, and `0x1D3B94` dereferences the indexed
  four-byte slot. `0x1D3B97`/`0x1D3B9C` compare global `0x10CC0FC` with
  that thread-data object's `+4`; the conditional branch is at `0x1D3BA2`.
  **HYPOTHESIS:** compiler thread-safe static initialization using Windows TLS.
  Neither a generic FS base nor a zero-filled image supplies this state.
- A guarded branch calls `0x824D4F` at `0x1D3BBC`, tests the global against
  `-1` at `0x1D3BC4`, and can return the global range object's address without
  entering initialization. Helper semantics and actual guard values are untested.
- Initialization calls `0x1ADFFA` at `0x1D3BD9` before the already known range
  stores at `0x1D3BE2`/`0x1D3BEC`. Calls at `0x1D3C01` and `0x1D3C11` target
  `0x1AE0DA`, each after passing a returned value with the range object in ECX.
  **HYPOTHESIS:** range/container augmentation; not a proven factory invocation.

The indexed owner has zero callers/references, and exact absolute-pointer search
also returns zero. **This does not prove unreachability:** an independent raw
`CALL rel32` search over executable raw sections finds candidates at `0x141039`
and `0x1410CF`, each arithmetically targeting `0x1D3B70`. Nearby local decoding
suggests the returned object is subsequently consumed, but the starts used for
that decoding are not established function boundaries. Keep these as candidates,
not verified call edges. This is another concrete exclusion of the assumption
that Ghidra's zero-caller summary is complete.

Limits: instruction and callee lists are truncated; the standing Ghidra OS
CA-bundle ERROR remains recorded despite headless/query exit 0. No initialization
helper, factory, guard or TLS behavior executed. Range semantics and first/later
`+0x70` timing remain **undetermined**; caller-supplied mount order is unchanged.
Private checks, candidate searches and provenance are under
`work/phase1-run3-002/`; sanitized reproduction is in the task report.

Next single query: `--rva 141039 --instructions 40` with explicit private `--out`
to resolve the caller boundary and consumer, then independently verify its call
and argument flow. Defer `D90870`: another initializer cannot explain consumers
as directly as these newly found call candidates. Do not synthesize TLS or bind
an inferred factory to turn static evidence into a runtime pass.

## Caller-candidate consumers — run 3 iteration 3

The one persistent query at `0x141039` returns **address-only**, mapped and
executable, with **zero indexed instructions**. `guard_check_icall` at
`0x140FE0` is merely the nearest preceding indexed function (89 bytes away),
not an established owner. No indexed references are returned. Truncation flags
are false because there are no indexed results, not because the code is fully
analyzed. The known OS CA-bundle ERROR remains despite query exit 0.

Independent pinned PE/Capstone inspection narrows two candidate bodies to
`[0x140FF3,0x14107C)` and `[0x14107C,0x141112)`: respectively 44 and 59
instructions, each ending in a return with no conditional branches. These are
**locally inferred boundaries**, not indexed or runtime-proven entries. Seventeen
selected operand contracts pass; 18 substitutions reject, including replacing
the newly observed `+0x10` slot with `+0x70`.

- At `0x141039`, the decoded call targets `0x1D3B70`; its returned value is
  pushed at `0x14103E`, and `0x141041` calls `0x1AE0DA` with the stack-supplied
  destination in ECX. **HYPOTHESIS:** collection consumer; this is not proof of
  an original factory invocation.
- At `0x1410CF`, another decoded call targets `0x1D3B70`. Its return is used
  as ECX and its first word supplies the table pointer for an indirect call at
  `0x1410D9`, offset **`+0x10`**, with the stack-supplied argument pushed.
  **HYPOTHESIS:** interface/registration dispatch. The owner's full return
  contract and actual table contents at this point are unvalidated; do not
  equate this with resource attachment `+0x70` or a proven factory invocation.
- Absolute-pointer scans for the two inferred entries return zero. Raw executable
  `CALL rel32` scans instead find `0xC2BC77` targeting `0x140FF3`, and
  `0xC2BFA3` targeting `0x14107C`. These incoming candidates are not independently
  aligned or proven reachable. Their existence strengthens a boundary hypothesis,
  not a startup-order claim.

This changes strategy after the index gap: do not treat the preceding guard as
an owner or repeatedly query neighboring undecoded bytes. Next one query:
`--rva C2BFA3 --instructions 40`, explicit private output, to seek indexed caller
context for the indirect-consumer path. If that is also address-only, prioritize
bounded independent control-flow/boundary evidence rather than another index
walk. `D90870` remains deferred. Factory invocation and first/later `+0x70`
timing remain **undetermined**; caller-supplied mount order is unchanged.

Private scripts/results: `work/phase1-run3-003/`; reproduction and regression
results are in the task report. No game code executed or runtime service added.

## Normal-flow caller candidate — run 3 iteration 4

The single persistent query `C2BFA3` also resolves address-only with no indexed
instructions. Nearest indexed `OnStart` at `C2BEEC` is only context, not evidence
that Ghidra owns the queried instruction or that startup executes it. Known
CA-bundle ERROR remains. Rather than querying more undecoded neighbors, bounded
independent recursive decoding starts at that indexed entry candidate.

Within a 0x400-byte bound, normal control flow reaches 209 non-overlapping
instructions, 224 edges, 17 branches and one return at `C2C123` (end `C2C126`),
with no outgoing edges beyond the bound. Separate linear decoding confirms all
boundaries and edges. The previously raw `C2BFA3` candidate is aligned along
this flow and directly targets `14107C`; the instruction at `C2BFA2` supplies
ESI as the stack argument. Removing the call node disconnects the normal return
from the seed; adding a bypass edge defeats this property as expected. Four
edge/target/argument mutations reject.

**Limits:** this is a locally inferred region and normal-return graph, assuming
calls return normally. It does not model exceptions, non-returning callees,
callback effects or runtime entry reachability. HYPOTHESIS: a lifecycle-named
candidate leads to the earlier interface/registration consumer. Its name does
not prove startup timing. No actual original function ran; no factory invocation
or resource attachment +70 was demonstrated. `C2BC77` remains unverified.

Raw pointer scan to `C2BEEC` returns one candidate at `E9920C`, corroborated by
an independent word read. Table base/slot, installation and indirect dispatch
are unproven; do not label it a vtable solely from an executable pointer. Next
one query should use indexed entry `C2BEEC` for prologue/name/reference metadata,
then combine it with bounded data-table evidence around `E9920C` rather than
continue adjacent address-only queries. `D90870` deferred; first/later +70
order remains **undetermined** and caller-supplied mount order unchanged.

Private checks/results: `work/phase1-run3-004/`. Task report records commands,
helper corrections, host passes and missing Android/validator gates. No runtime
service, automatic precedence or guest dispatch binding changed.

## Indexed lifecycle entry and candidate table — run 3 iteration 5

Reflection checkpoint: the checked loader maps original-image **data**, while
recent call-path increments establish static dependencies only. None invokes
startup or closes gameplay gates. One query at indexed `C2BEEC` deliberately
replaces the preceding address-only queries; no second query or re-import.

The index resolves `function-at`, name `OnStart`, source `IMPORTED`, with a
`cTSAppFWCOMDirector` thiscall signature/comment. These are symbol metadata,
not independently validated ABI or lifecycle behavior. Only **two instructions**
are indexed (initial move and call at `C2BEF1` to `8248B0`); independent decoding
confirms their boundaries/mnemonics and call target. The prior 209-instruction
region remains locally inferred, not an indexed body. False truncation flags and
one listed callee do not make that body/callee inventory complete. Known
CA-bundle ERROR retained despite query exit0.

- In-image indexed references are `E9920C` (absolute pointer, also the raw-scan
  hit) and `FE7D80` (`ImageBaseOffset32`). Independent reads confirm the latter
  stores **RVA** `C2BEEC`, not VA `A0C2BEEC`; an absolute-VA scan cannot find it.
  The external reference from address zero is not an in-image caller or RVA.
- Bounded 32-word inspection around `E9920C` finds 17 consecutive executable
  pointers in `[E991FC,E99240)`, bracketed by non-executable pointers. This does
  not prove complete table extent. **HYPOTHESIS:** vtable base `E991FC`, with
  `C2BEEC` at **+10**, not resource attachment +70.
- Raw pointer scan for `A0E991FC` finds two occurrences (`C2BBC5`, `C2BCD0`).
  Independent instructions at `C2BBC3`/`C2BCCE` store that value to `[ESI]` and
  `[ECX]`, respectively. These support an installed-table hypothesis, not actual
  construction/execution or a proven long-lived service identity.
- Separate linear and recursive decoding of locally inferred
  `[C2BBA4,C2BCB3)` agree on 80 reachable instructions/79 normal edges ending
  in a return at `C2BCB2`. The first table store and the pending incoming call
  `C2BC77` are aligned; that call targets `140FF3`. HYPOTHESIS: an object-setup
  path reaches the earlier collection consumer. No factory invocation proven.
  The second store has local operand evidence only, not a verified caller body.

Four slot/target/store-displacement/base contract mutations reject. These checks
are static, not an x86 behavioral oracle or ARM64 comparison; returning-call and
SEH/non-return limitations remain. Startup reachability, actual indirect +10
invocation and first/later resource +70 timing remain **undetermined**. No runtime
binding, TLS initialization or automatic precedence changed.

Private evidence `work/phase1-run3-005/`; reproducible commands and baseline
results in the task report. Next ONE query `C2BBA4` (small instruction/reference
caps, explicit private output) seeks indexed installer identity/incoming metadata.
If it has another coverage gap, use targeted incoming rel32/alignment evidence,
not neighboring empty queries. D90870 stays deferred. Do not confuse this
candidate lifecycle table's +10 with the unrelated owner-return consumer's +10.

## Global-object caller of candidate installer — run 3 iteration 6

One persistent query `C2BBA4` is address-only (mapped/executable, no indexed
instructions/references); nearest preceding function is not an owner. Known
CA-bundle ERROR retained. Independent pinned raw rel32 scan finds one installer
candidate `C2BECD`, now aligned in locally inferred `[C2BE73,C2BEE6)`.
Separate linear/recursive decoding agree on 35 reachable instructions/36 normal
edges, return `C2BEB0`; four target/node/return/edge mutations reject.

`C2BE8A` loads global-object address RVA `10FDF60` into EDI; `C2BECB` copies
EDI to ECX before `C2BECD` calls `C2BBA4`. This narrows the candidate installed
table's object address, not observed construction or lifetime. `C2BE7D` reads
FS:+2C and `C2BEA8` writes FS:+0. HYPOTHESIS: guarded global initialization
with thread/exception dependencies; helper/TLS/SEH semantics unvalidated.
Normal-flow evidence assumes returning calls and excludes exception behavior.

Absolute-pointer scans for installer and inferred accessor return zero,
untruncated. Raw rel32 scan for accessor `C2BE73` finds `C26BFA`/`C26C0C`;
these are still unaligned candidates. Next one query `C26BFA` seeks caller
context before independently aligning both. No actual startup, factory/table
dispatch or first/later resource +70 timing established. D90870 deferred;
caller-defined mount order unchanged. Private checks: `work/phase1-run3-006/`;
commands, regression evidence and acceptance gaps in task report.

## Global-accessor consumer and conditional lifecycle dispatch — run 3 iteration 7

Single persistent query `C26BFA` resolves containing function `C26BF5` (automatic
name, unknown ABI), unlike prior index gaps. Independent pinned decoding agrees
on all 22 indexed boundaries in `[C26BF5,C26C30)`, and recursive normal flow
agrees on 22 nodes/21 edges ending with tail jump `C26C2B`→`140F40`. Known
CA-bundle ERROR retained; calls assumed returning normally, exceptions excluded.

Both `C26BFA`/`C26C0C` are aligned calls to global-object accessor candidate
`C2BE73`. First return is pushed to `14491B`, whose return becomes the receiver
for `1AE0DA`. Second return goes EAX→ESI at `C26C11`, then `[ESI]`→EDI at
`C26C13`. After helper `1AE18D`, its result is pushed and ESI supplied as ECX
before `C26C1D` calls `[EDI+10]`. Candidate installed table `E991FC` slot+10
independently reads `C2BEEC`. **HYPOTHESIS / conditional edge:** lifecycle-named
entry dispatch, IF the accessor returns the previously identified object, its
table remains unchanged and helpers preserve expected state. No runtime return,
ABI, lifetime, invocation or startup established. This directly consumes the
global accessor, unlike the unrelated owner-return +10 consumer; neither proves
resource attachment +70. Four wrong slot/base/target/receiver mutations reject;
no behavioral reference or original execution.

Caller entry has one absolute pointer, `E984E8`, in both indexed and raw sets,
independently checked. Bounded 32-word inspection suggests table `E984B8`, with
this entry at +30: 15 consecutive executable words, bracketed by non-executable
words, NOT proven full extent/identity. Raw table-base hits `C261A1`/`C266E8`
remain unaligned candidates. Next ONE query `C261A1`, small caps/explicit output,
then independent alignment. On coverage gap, use bounded flow, not adjacent empty
queries. D90870 deferred. Factory invocation and first/later +70 order remain
undetermined; mount order stays caller-defined. Private `work/phase1-run3-007/`;
reproduction/checks/audit in task report. No runtime binding changed.

## Candidate caller table installs at subobject +1C — run 3 iteration 8

One persistent query C261A1 returns address-only (nearest indexed C26147 is
context, not established enclosing body). Known CA-bundle ERROR retained;
no adjacent queries/re-import. Independent pinned recursive decoding from
C26147 reaches 331 nodes/342 normal edges, return C265D6 (end C265D9).
Separate linear boundaries agree. Second locally inferred C266B9 region:
48 nodes/48 edges, return C26772 (end C26773). Both are local normal-flow
regions, not runtime reachability or full indexed ownership; returning calls
assumed, exceptions/non-return behavior unmodelled.

Raw base-pointer scan again finds exactly C261A1/C266E8, untruncated. These
align to immediate fields of stores C2619E/C266E5: E984B8 is stored at
**[EDI+1C] / [ESI+1C]**, not object offset zero. ECX is copied to EDI/ESI
at C26157/C266D2; helper preservation/entry ABI still unvalidated. Four
wrong displacement/table mutations reject. Candidate slot E984B8+30 still
reads C26BF5. HYPOTHESIS: subobject lifecycle interface; installation offset
must not be discarded in a future receiver model. No actual dispatch/lifetime
or startup execution demonstrated, no runtime binding enabled.

Aligned calls C2617E→CA4CB0 and C26759→CA4DE0 connect the known directory
registry neighborhood without proving service identity or initialization order.
Raw executable rel32 scan finds sole incoming candidates C2BB09→C26147 and
C267DC→C266B9; incoming alignment unproven. Next ONE query C2BB09 with small
caps/explicit private output, then independent bounded alignment, not adjacent
empty queries on index gap. D90870 deferred. Original factory invocation and
first/later +70 order remain undetermined; caller-defined mount order unchanged.
Private evidence work/phase1-run3-008/; commands/checks/audit in task report.
Host CTest7/7/Python60 pass; Android SDK and trusted-validator gates remain.

## Installer caller receiver narrowed — run 3 iteration 9

ONE persistent query C2BB09 is address-only; nearest indexed C2A79D is
context, not owner. Known CA-bundle ERROR retained. Independent bounded
recursive/linear decoding of locally inferred C2B87C agrees on 184 reachable
instructions/190 normal edges, return C2BA82, furthest end C2BB25. C2BB09 is
an aligned call to C26147. Calls assumed returning normally; exceptions and
helper effects are not modeled. No runtime entry/ABI/ownership proof.

C2BB07 supplies EDI as ECX. Normal-flow predecessor analysis identifies its
last explicit EDI writer as C2BA14, loading global-object address 10FDCF0;
that load and the receiver copy dominate the call in this local graph.
HYPOTHESIS: C26147 installs the candidate E984B8 interface at this object's
+1C, conditional on helper preservation and the earlier constructor model.
The nearby C2BA9F load of **10FDCE8 is NOT** the call's last explicit receiver
definition. A proximity-only receiver model is rejected; no runtime binding.
Four wrong target/address/register/offset contracts reject. No behavioral
reference or original execution is claimed.

Two exploratory failures are retained: seeding after return C2BA82 at C2BA85
escapes backward to C2BA0F, disproving that return-based boundary guess; a
claim that nearby C2BA9F dominates the call also fails. Expanded local flow and
backward reaching-definition analysis replace those assumptions, not game
inputs or tests. Boundary C2B87C remains inferred, not indexed ownership.

Raw absolute-pointer scan to C2B87C returns zero, untruncated; raw rel32 scan
finds candidate 82481A, not yet aligned. Next ONE query 82481A with explicit
private output, then bounded independent caller alignment. C267DC remains
pending; D90870 deferred. Factory invocation / first-later resource +70 ordering
remain undetermined, caller-supplied mount order unchanged. Private evidence
work/phase1-run3-009/; task report has commands, failures and completion audit.
Host CTest7/7 + Python60/no skips pass; Android SDK/validator remain blocked.

## Original-entry connection — run 3 iteration 10 reflection

ONE persistent query 82481A returns address-only; nearest indexed
operator_new at 824632 is context, not enclosing ownership. Known CA-bundle
ERROR retained. Independent pinned decoding aligns 82481A→C2B87C inside
[824727,8248A3): 110 reachable instructions/118 normal edges, return 82488C;
separate linear boundaries agree. Four contiguous argument pushes immediately
precede the call; their ABI/meaning and helper effects remain unvalidated.

The original entry RVA **8248A3**, already recorded from approved metadata in
INTEROP_EXPERIMENT.md, calls 8258A9 and then jumps at 8248A8 to 824727.
This supplies a static entry-connected path to the previous candidate installer
caller, not observed startup. Normal return 82488C is reachable even with
82481A removed: the game call does **not** dominate return. Four wrong target/
entry-target/alignment/argument-count contracts reject. Calls assumed returning;
exceptions, helper effects and runtime guard state excluded. No behavioral
reference, executed original code, factory invocation or +70 timing proven.

Reflection: the accumulated chain now connects to original entry metadata;
continuing arbitrary caller queries is lower value than resolving the earliest
unsupported startup dependency. Next ONE query **8258A9**, small caps/explicit
private output, then independent operand/reference validation before proposing
any runtime service. Its role is unknown, not inferred from address proximity.
C267DC and D90870 remain pending; resource attachment order undetermined.
The PE header still points at the preserved wrapper; this observation neither
changes its entry nor authorizes launching the analysis image. No dispatch
binding or automatic precedence change. Private work/phase1-run3-010/;
focused0, host0 CTest7/7/Python60 no skips; Android1 SDK absent, acceptance78
validator unset. All Phase 1 P0/P1 remain open.

## Decision and next evidence

`ReadOnlyResourceMount` retains caller-defined order and last-layer-wins key
resolution. No automatic product ordering or full-installation import is
enabled. A deterministic host inventory may inspect an explicitly selected
small package set, report collisions, and leave winner selection to a supplied
order. Before adopting game-wide precedence, trace where directory and package
sources are attached to the derived resource service (now known to funnel only
through `+0x70` → `0x1E36F0` → `0x9B52C0`), including which entries use its
prepend path, the final attachment sequence, and whether the fast path changes
selection. Enumerate `*.package` call sites as the union of Ghidra references and
raw pointer scans, because the two disagree. A controlled trace of an unmodified game run with isolated
user data can validate product order, directory merging, and user overrides.
