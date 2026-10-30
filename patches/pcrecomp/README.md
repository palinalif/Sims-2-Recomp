# Isolated pcrecomp analysis patch

Base: `sp00nznet/pcrecomp`, revision
`c0cbd3e3653010782b17e8a87b58953608ea411c`.
Pristine `tools/drm/steamstub.py` SHA-256:
`6a3724044bdb471454646d8504d53fe60f6aad45a07dc1d841e7bacaff0433f7`.
Original MIT notice is retained in LICENSE.upstream. This patch is local; it has
not been submitted upstream. The pinned dependency directory remains unchanged.

`0001-steamstub-analysis-metadata.patch` adds two separate APIs:

- `inspect_v3(raw, header_size=None, expected_appid=None)`: metadata only; does not
  recover code or change image bytes. The known upstream copy pattern still works.
  A caller-reviewed size can be supplied for another loader; it is not guessed.
  Validates architecture, prologue, raw backing, signature/base/App ID, code size,
  original entry and non-overlap with headers, other sections and certificate data.
- `recover_v3_analysis(...)`: revalidates metadata, uses the existing upstream
  cipher/padding checks, returns an analysis image with only the code range changed.
  It preserves entry point, PE headers, wrapper, imports and overlay, and never calls
  `finish()`. It does not execute anything or implement Steam authentication.

The existing CLI and `unwrap()` behavior are unchanged. These APIs are for a
manually approved local interoperability experiment, not an automatic importer.
Metadata inspection reports flags; the caller must review layout/flags before
recovery. The completed experiment used flags zero and the observed 0xF0 header.
No general flag-variant handling, process dumping or authentication bypass is added.

Independent authored tests need the pinned source and optional analysis dependency:

```sh
pip install -r tools/interop-requirements.txt
python tools/fetch_pcrecomp.py
python -m unittest discover -s tests -p test_steamstub_patch.py -v
```

Tests check the source hash, apply the patch to a fresh temporary source copy,
then exercise synthetic PE/header/cipher fixtures. No game files are opened.
If the dependency/source is missing, tests explicitly skip; they do not fetch or
unpack anything implicitly. Current local result: seven tests pass, plus the
upstream self-test on the separately patched source.

To prepare a separate local tool tree, copy the pinned source into ignored work/
and run `patch --batch -p1 -i /absolute/path/to/0001-steamstub-analysis-metadata.patch`
from that copy. Do not patch the verified dependency in place. Recovery commands
and proprietary outputs from the approved experiment stay private under work/.
See docs/INTEROP_EXPERIMENT.md for evidence, limitations and the scope boundary.
