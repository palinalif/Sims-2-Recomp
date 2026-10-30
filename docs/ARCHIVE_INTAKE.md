# Installation archive intake

This workflow prepares a legitimate user-supplied ZIP for **analysis only**.
It does not execute the game, unpack DRM, import assets into Android, or change the
source archive. We can fingerprint the executable and middleware without expanding
the entire installation first.

## Preview first

```sh
python tools/archive_intake.py '/path/to/Legacy Collection.zip' \
  --report work/legacy-archive-preview.json
```

Without `--extract-binaries`, this reads ZIP central-directory metadata and writes
only the requested new report. Standard output shows EXE/DLL candidates, their
combined size, package count and any blocking path/format/budget problems. The full
report includes every inspected member's path, size, compression size and declared
CRC. It supports standard ZIP/ZIP64 through Python's standard library; other archive
formats need a separate intake path.

`crc_verified=false` means payloads have **not** been checked. A successful preview
does not establish payload integrity, executable compatibility, or a valid game
installation. It is a preflight for selective extraction. Metadata member-count
limits apply after the standard ZIP parser has loaded the central directory.
If preflight rejects a member or reaches a limit, totals can be partial; inspect
the reported errors before using them as space estimates.

## Stage only analysis binaries

```sh
python tools/archive_intake.py '/path/to/Legacy Collection.zip' \
  --extract-binaries game-files/legacy-analysis-001
python tools/analyze_install.py --install game-files/legacy-analysis-001 \
  --include-dlls --output work/legacy-binaries-001.json
```

The destination must be a **new** directory under this repository's ignored
`game-files/` or `work/`. Existing directories are refused, including previous
partial attempts. Only `.exe` and `.dll` files are copied, preserving their relative
paths. Game resources, videos, music and saves remain in the ZIP. Consequently,
the staged tree's package count is zero even when the archive contains packages.

Extraction streams each selected file, checks its ZIP CRC, counts actual bytes and
records SHA-256, size and relative path in `intake-manifest.json`. Copied files have
read/write permissions only; the tool never launches them. The manifest changes to
`status=complete` only after every selected binary passes. Errors leave a diagnostic
`failed` or `incomplete` manifest and partial directory; choose a new staging name
when retrying. No original tree is overwritten or cleaned up.

## Preflight rules and limits

- Reject traversal/absolute/drive/UNC paths, control characters, Windows device
  names and ambiguous path components. Backslash file paths are normalized.
- Reject duplicate paths, case/Unicode-equivalent collisions (including implicit
  parent-directory aliases), file/directory collisions, symlinks and special files.
- Reject encrypted members and unsupported compression before staging.
- Default data limits: 200,000 members, 64 GiB declared uncompressed total,
  256 MiB per selected binary and 1 GiB combined selected binaries. EXE/DLL extraction
  reserves an additional 64 MiB of free disk space and checks streamed byte budgets.
- Path limits: 2,048 UTF-8 bytes per path, 64 components, 255 bytes per component,
  32 MiB combined path bytes and 300,000 indexed component nodes. Path indexing
  uses a component tree rather than constructing every full parent prefix.

These limits are centralized in `Limits` for review, rather than silently expanded
when a file fails. Full asset extraction has not been implemented. A larger valid
installation or unusual ZIP layout should be inspected and handled explicitly.

## Executable and DLL reports

`analyze_install.py --include-dlls` inspects discovered DLLs as well as `Sims2*.exe`.
Use `--exe` for another filename. Tree analysis defaults to 128 binaries and a
1 GiB total inspection budget, including malformed inputs. `--max-binaries` changes
the count limit. Reports state `analysis_truncated` when discovery/count/byte limits
prevent a complete census; individual file errors remain visible.

Each import includes its named/ordinal form and guest IAT virtual address, including
delay imports. TLS callback arrays are read as PE32/PE32+ pointers, bounded to 64
entries and raw-backed section data. Errors/truncation are reported; callback
addresses are never called or assumed to be verified function starts.

The executable hash registry still accepts no game build. Recognition, import
enumeration or successful ZIP extraction never enables execution.
