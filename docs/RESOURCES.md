# Native package decoding and Android probe

The portable C++ reader now decodes the QFS/RefPack variant observed in the
supplied Legacy Collection packages. This is a resource-loading slice, not game
execution, simulation or a rendered game frame.

## Supported contract

- DBPF 1.0/1.1, index 7.0/7.1 (20-byte entries) and 7.2 (24-byte entries).
- Unsigned type/group and 64-bit instance keys, validated index/payload bounds,
  duplicate-key rejection and DIR compression records.
- QFS `10 FB`, a three-byte big-endian decoded size, optionally preceded by a
  four-byte little-endian total stored size (zero means unspecified).
- All four command classes, literal trailers, overlapping copies and the full
  131,072-byte back-reference distance. Decoded size must equal the DIR record;
  bounds, stop marker and exact input/output consumption are checked.
- Ambiguous raw/prefixed headers are fully validated with at most two bounded
  attempts. Failed output storage is released before the second attempt.

Other header flags, padding after the stop marker, and nonzero stored-size fields
that exclude their own header are rejected. Supporting another variant needs
evidence and tests. This is not a claim that every installation/mod package works.

`Dbpf` borrows immutable input bytes; callers retain ownership and lifetime.
`stored_resource()` returns bounded stored bytes; `resource()` borrows only
uncompressed bytes. `decode_resource()` returns owned decoded bytes, with a default
64 MiB output cap, including for uncompressed copies. `ReadOnlyResourceMount` now
indexes caller-supplied parsed packages by relative path and resource key. Package
paths are copied; package objects and their immutable bytes remain caller-owned.
The mount normalizes separators and ASCII case for path lookup, rejects invalid or
colliding paths, and lets the last supplied package win a duplicate resource key.
DIR compression metadata is excluded from the cross-package resource index.
Its `decode_resource()` delegates the output budget to `Dbpf`; it has no decoded
cache. This is an in-memory read-only index, not an installation importer or the
game's established expansion load order. Actual Legacy package precedence still
needs evidence before mounting a full installation or mods. The small authored
decoder avoids adding another runtime/toolchain dependency; OpenTS2/DBPFSharp and
the format documentation were references, not embedded engines. Independent
verification uses a separate decoder.

## Host commands

```sh
scripts/test-host.sh
scripts/test-package-stream.sh   # Requires full JDK 17+, uses JAVA_HOME if set.
build/host/ts2_dbpf_probe '/path/to/sample.package'
build/host/ts2_dbpf_probe '/path/to/sample.package' TYPE GROUP INSTANCE
```

The optional keys accept hexadecimal `0x...`; the CLI writes a selected decoded
payload to stdout only after successful decoding. It limits package input to
256 MiB and decoded output to 64 MiB. Keep any redirected proprietary payload in
ignored `work/`; do not redirect over original files.
The CLI sets binary stdout mode on Windows; an authored LF-byte regression test
guards against CRLF conversion of decoded payloads.

For an independent comparison, obtain the exact reference source URL in
`config/dependencies.lock.json` under `qfs_reference`, placing it in ignored
`work/qfs-reference/refpack.c`. Its required SHA-256 is
`d3d0345596978e0907a8b8e4230edb9eb9752ca48a542eae09a2b5e8597e05f2`.
Then:

```sh
python tools/verify_qfs_reference.py \
  --reference-source work/qfs-reference/refpack.c \
  --package '/path/to/FaceInfo.package' \
  --package '/path/to/WantTuning.package' \
  --package '/path/to/lighting.package'
```

The script verifies the pinned source hash, builds its C decoder into a temporary
host library, independently reads package indexes/DIRs, and compares complete
payload bytes with the native CLI. It requires a POSIX host with `cc`, Python and
the built CLI. It limits input/count/output and compile/run time. It writes no
game payloads and is an explicit host-only check, never an Android dependency.
This reference check currently accepts the explicit prefixed format observed in
the two compressed samples. It is not a general DBPF validation oracle.

## Android path and device checklist

Choose **Game files → Inspect one package** and select a `.package` document.
Android opens only a read grant, streams actual bytes with a 16 MiB input cap on
the worker, then invokes the portable native probe. It indexes the package and
decodes its first non-DIR resource with an 8 MiB output cap. Large first resources
fail explicitly; the probe does not silently choose a different resource.

The report shows resource counts, selected key, decoded byte count and SHA-256.
Only a private `package-report.json` is written. Package/payload originals are
never changed or copied to writable game directories. PNG preview uses Android's
image decoder after checking dimensions (at most 2048 × 2048). It is an asset
preview, not the game's renderer. Successful results wait for a resumed, focused
Activity without another app dialog. Cancellation is cooperative: interruption
cannot guarantee an immediate return from a blocked document-provider read.

This path builds but **has not run on Android**. On the Thor or another ARM64 device:

1. Install/launch the diagnostic APK using README.md. Use D-pad/A to open Game files.
2. Select each small package. Match byte counts and hashes in TARGET_LEGACY.md.
   Lighting should preview a 64 × 64 PNG; FaceInfo/WantTuning should report decoded
   bytes without attempting image preview. No original files should change.
3. Cancel selection; select malformed/truncated and >16 MiB documents; deny/revoke
   provider access. Expect explicit failure, then normal input and retry.
4. Background/resume while loading, open another dialog, disconnect/reconnect the
   controller, and destroy/recreate the Activity. Check result delivery and no
   stale input; preserve `adb logcat -s TS2Native` and private reports.
5. Repeat using a local provider and a cloud provider. This is not a full game
   installation importer; do not select the 10 GB installation ZIP as a package.
