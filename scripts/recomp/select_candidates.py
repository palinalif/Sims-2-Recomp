#!/usr/bin/env python3
"""Emit non-proprietary, deterministic run-5 selection metadata, not lifted code.

Selection is documentary, not a whole-image scan or a boundary/behavior proof.
The fixed order intentionally keeps hard startup/resource cases ahead of leaves.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

IMAGE_SHA = "63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985"
MAX_FUNCTIONS = 25
CATEGORIES = (
    "simple leaf, no calls", "branching arithmetic", "stack operations",
    "memory access through pointers", "direct call", "indirect call / vtable",
    "startup or resource path",
)
RESOURCE = "docs/RESOURCE_PRECEDENCE.md"
OBJECT = "docs/OBJECT_QUERY_CALLER.md"
LOCAL = "docs/LOCAL_VALIDATION.md"

# This is an explicit reviewed shortlist, NOT random sampling of 44,151 entries.
# Unknown sizes must stay null until individually validated. Categories/roles
# outside the historical leaves are static stress hypotheses, not behavior claims.
CATALOG = (
    (0x9B52C0, None, (6, 4), RESOURCE, "resource attachment funnel", "unvalidated"),
    (0x1E36F0, None, (6, 5), RESOURCE, "indirect resource entry; sole funnel caller", "unvalidated"),
    (0x1E95C0, None, (6, 4), RESOURCE, "candidate rebuild with nine callers", "unvalidated"),
    (0x1ABD40, None, (3, 4), OBJECT, "five-query cache refresh caller", "unvalidated"),
    (0x1D3E20, None, (6, 3), RESOURCE, "resource constructor seed", "unvalidated"),
    (0x1DA310, None, (6, 3), RESOURCE, "second resource constructor seed", "unvalidated"),
    (0x8248A3, None, (6, 4), "docs/INTEROP_EXPERIMENT.md", "original entry metadata, not wrapped PE entry", "metadata-entry-only"),
    (0x8258A9, None, (6,), RESOURCE, "first entry-connected unsupported dependency", "unvalidated"),
    (0x82585C, None, (6, 5, 2), "scripts/recomp/README.md", "measured direct dependency of 8258A9; four absolute IAT calls", "indexed-entry-local-flow-only"),
    (0x824727, None, (6, 4, 2), RESOURCE, "unimplemented original-entry tail; bounded normal flow before entry", "address-only-index-local-flow-hypothesis"),
    (0x1460, None, (5, 2, 3), OBJECT, "callback producer and failure cleanup", "unvalidated"),
    (0x1AB7E0, None, (4, 5), OBJECT, "cache consumer reaches indirect jump-table helper", "unvalidated"),
    (0x1070, 19, (0, 3), LOCAL, "historical original pointer-store helper", "historical-reviewed-range"),
    (0x1240, 11, (0, 3), LOCAL, "reuse pinned group reference first", "historical-reviewed-range"),
    (0x1250, 27, (1, 3), LOCAL, "reuse pinned branching group reference first", "historical-reviewed-range"),
    (0x1270, 30, (1, 3), LOCAL, "reuse pinned guarded group reference first", "historical-reviewed-range"),
    (0x1AB770, None, (2, 3, 4), LOCAL, "historical cache wrapper with saved references", "historical-reviewed-range"),
    (0x1AB78C, None, (2, 3, 4), LOCAL, "paired historical cache wrapper with saved references", "historical-reviewed-range"),
    (0x825BB0, 69, (6, 2, 3), "scripts/recomp/README.md", "first tail helper; composed nonzero-FS reference precedes lift", "indexed-entry-and-bounded-reference-not-full-SEH"),
    (0x82A6D3, 55, (6, 4, 2), "scripts/recomp/README.md", "first callee of resource failure boundary 82A797; three direct dependencies", "indexed-normal-return-flow-only-not-behavior"),
    (0x82A47B, 72, (6, 1, 2, 3), "scripts/recomp/README.md", "first direct dependency of 82A6D3; bounded indexed leaf with globals", "indexed-normal-return-flow-only-not-behavior"),
)
# Preserve rejected suggestions, rather than silently turning instruction sites
# into functions. No rejection licenses substituting another easy leaf.
REJECTED = (
    (0x1AB79C, LOCAL, "documented call instruction inside wrapper, not function entry"),
    (0xC261A1, RESOURCE, "documented table immediate site; address-only index result, not entry"),
)


def select_candidates() -> dict:
    """Pure metadata policy; no file reads, timestamps, random state or execution."""
    if len(CATALOG) > MAX_FUNCTIONS:
        raise ValueError("selection exceeds owner function budget")
    rvas = [row[0] for row in CATALOG] + [row[0] for row in REJECTED]
    if len(set(rvas)) != len(rvas):
        raise ValueError("duplicate candidate RVA")
    selected = []
    for rank, (rva, size, categories, source, rule, boundary) in enumerate(CATALOG, 1):
        selected.append({
            "rank": rank, "rva": f"0x{rva:X}", "size_bytes": size,
            "categories": [CATEGORIES[c] for c in categories], "source": source,
            "selection_rule": rule, "boundary_evidence": boundary,
            "reliable_ghidra_boundary": None,
            "dependencies": None,
            "status": "selected-not-attempted-this-run",
        })
    return {
        "schema": "sims2-recomp-selection/1", "image_sha256": IMAGE_SHA,
        "authorization_limit": MAX_FUNCTIONS,
        "policy": "fixed documented shortlist, hard dependencies first; no replacements on failure",
        "category_interpretation": "HYPOTHESIS: static stress coverage, not validated behavior",
        "sampling_limit": "not representative statistically; no executable-wide extrapolation",
        "unknowns": "null means unmeasured, not absent, zero or passed",
        "counts": {"selected": len(selected), "rejected": len(REJECTED),
                   "attempted": 0, "lifted": 0, "compiled_for_aarch64": 0,
                   "matched_x86_reference": 0, "executed_under_qemu": 0},
        "selected": selected,
        "rejected": [{"rva": f"0x{rva:X}", "source": source, "reason": reason}
                     for rva, source, reason in REJECTED],
    }


def verify_image(path: Path) -> None:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != IMAGE_SHA:
        raise ValueError("analysis image pin mismatch")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=Path("work/interop-legacy-002/analysis-image.bin"))
    args = parser.parse_args(argv)
    try:
        verify_image(args.image)
        manifest = select_candidates()
    except (OSError, ValueError):
        # Do not leak private paths or observed hashes on failure.
        print("selection failed: pinned analysis image unavailable/invalid or invalid catalog", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
