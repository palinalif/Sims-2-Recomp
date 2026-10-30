# Checked PE32 guest-data image loader

`load_guest_image()` in `native/include/ts2/guest_image.hpp` maps PE32/i386
headers and sections into a **fresh owned `GuestMemory`**, returning preferred
base, image size, entry RVA and section extents. This is data mapping, **not
original-code execution or game startup**. No caller memory is overwritten.

## Contract and intentionally unsupported behavior

- Caller supplies a bounded borrowed file span and separately authorizes/verifies
  its provenance. Format validation is not hash authorization. The default
  expected preferred base is `0xA0000000`; any mismatch rejects. An explicit
  alternate expected base is possible, but **no relocation** is performed.
- File and image budgets are 256 MiB each, section count 1–96. Only PE32/i386
  is accepted, with power-of-two section alignment >=4096, file alignment
  512–65536, and section alignment >= file alignment. Low-alignment images
  are intentionally unsupported, not silently remapped.
- DOS/PE/optional/section headers, declared directory-record capacity,
  SizeOfHeaders/SizeOfImage, raw backing/start alignment, section RVAs, and unsigned
  base+size bounds are checked before guest allocation or writes.
- Headers map at preferred base; each section maps at **base + RVA**, never file
  offset. Extent is max(VirtualSize, SizeOfRawData), preserving raw padding.
  Raw lengths need not be multiples of FileAlignment: the pinned image's final
  section has an exact 186,320-byte raw length (remainder 464 at alignment 512).
  A synthetic short-tail regression first failed, then passed with exact-length
  copying; truncated input still rejects. No source bytes are rounded up.
  Rounded virtual extents must be disjoint from headers and one another. Raw
  extents must be disjoint from headers and one another. Truncation, overlaps,
  wrapping or out-of-image extents reject. Empty raw sections are zero-filled.
- Fresh anonymous memory zeros the entire image, including gaps, alignment tails
  and virtual zero-fill. Raw bytes then overwrite only their validated ranges.
  `GuestMemory::write_bytes` checks the complete destination before copying; an
  invalid bulk write cannot partially modify its committed prefix.
- The complete image is committed read/write **data**, never executable. Host
  page rounding remains `GuestMemory` policy; this is not PE section-permission
  enforcement. Image gaps are readable/writable. A mapping failure destroys the
  fresh memory; there is no partially loaded result or global module registry.
- Entry must be nonzero and raw-backed in an executable-marked section. It is
  returned as **PE metadata only**: the pinned analysis image still declares its
  preserved wrapped entry, not an established original-game startup target.
- Imports/IAT, delay imports, relocations, TLS callbacks, TEB/SEH, stack/return
  ABI, loader ordering, OS services and original-function bindings are **not
  modelled**. Neither directories nor callbacks execute. Never invoke the entry
  merely because mapping succeeded. No x86 execution engine is introduced.

The native diagnostic app does not consume this API yet. Do not ship the private
image or generated original-code artifacts in an APK.

## Reproduction and checks

After `. scripts/campaign/worker-env.sh` on this host:

```sh
cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --target ts2_guest_image_tests ts2_guest_image_probe --parallel 2
build/host/ts2_guest_image_tests
scripts/test-host.sh
# Private, owner-authorized input only; independently verify the pinned SHA first:
build/host/ts2_guest_image_probe work/interop-legacy-002/analysis-image.bin
```

The host-only probe emits RVAs, sizes and counts, never original bytes or names.
It accepts an explicit input path, opens read-only, caps input size, and never
writes the file. No discovery, recovery or modified-PE launch is performed.

`tests/guest_image_tests.cpp` is entirely authored: distinct raw offsets/RVAs,
fixed high base and byte expectations, two independent mappings, zero-fill/raw
padding, malformed/truncated headers, overlaps, overflow, wrong machine/base,
invalid entry, and failure-atomic bulk writes. The mapping assertions inspect
explicit independent VAs, not addresses calculated by the loader under test.
Results and private-image metadata cross-check are recorded in the task report.
No trusted original x86 loader differential or Android execution is claimed.
