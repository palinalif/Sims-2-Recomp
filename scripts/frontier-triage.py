#!/usr/bin/env python3
"""Frontier triage: classify indexed functions by verification shape and emit
templated batch queues so workers lift+verify several same-shape functions per
iteration instead of one bespoke target per iteration.

Input : work/ghidra-index/functions.jsonl (from scripts/ghidra-index-dump.sh;
        last record per rva wins — the dumper appends after crash rewrites)
Output: work/ghidra-index/triage.json  (machine-readable queue for workers)
        plus a human summary on stdout.

Shape classes (cheapest to verify first):
  leaf-getter  <=2 params, 1 caller class shape, small body, calls nothing
  leaf-setter  stores a param, tiny body, no calls
  thunk        direct jump to one target (verify as a pair with its target)
  small-leaf   small body, no external calls, single exit
  branchy      multiple direct callees — needs per-call contract work
  large        body or CFG too big for templating; schedule individually
Reads are pure-python; nothing here mutates the index.
"""
import json
import re
import sys
import os
import argparse
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEF_IN = os.path.join(REPO, "work/ghidra-index/functions.jsonl")
DEF_OUT = os.path.join(REPO, "work/ghidra-index/triage.json")

SMALL_BYTES = 96
TINY_BYTES = 48
LARGE_BYTES = 1200


def load(path):
    recs = {}
    bad = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                bad += 1
                continue  # partial tail line; cursor will have rewritten it
            recs[r.get("rva")] = r  # last wins
    return recs, bad


def callees_of(r):
    return [c for c in r.get("callees", []) if isinstance(c, dict)]


def classify(r, by_rva):
    size = r.get("sizeBytes", -1)
    callees = callees_of(r)
    ncalls = len(callees)
    internal = [c for c in callees if c.get("rva") in by_rva]
    # A callee that is auto-named and outside the index is an unresolved
    # external; templated classes require zero internal calls.
    if r.get("thunk"):
        return "thunk"
    if size < 0:
        return "unknown"
    if size > LARGE_BYTES or ncalls > 6:
        return "large"
    if ncalls == 0:
        p = r.get("params", 0)
        if size <= TINY_BYTES and p <= 4:
            sig = (r.get("sig") or "").lower()
            pseudo = r.get("pseudo") or ""
            stores = re.search(r"\*\s*\([^)]*\)\s*\([^)]*\)\s*=", pseudo) is not None
            returns = re.search(r"return\s+\w*param", pseudo) is not None
            if returns or "get" in sig:
                return "leaf-getter"
            if stores or "set" in sig:
                return "leaf-setter"
            return "small-leaf"
        return "small-leaf"
    return "branchy"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=DEF_IN)
    ap.add_argument("--out", default=DEF_OUT)
    ap.add_argument("--batch-size", type=int, default=6)
    ap.add_argument("--limit-classes", default="",
                    help="comma list; default all (thunk,leaf-getter,leaf-setter,"
                         "small-leaf,branchy,large,unknown)")
    args = ap.parse_args()

    if not os.path.isfile(args.index):
        sys.exit(f"no index at {args.index}; run scripts/ghidra-index-dump.sh first")

    by_rva, bad = load(args.index)
    if not by_rva:
        sys.exit("index is empty (dump still starting?)")
    classes = defaultdict(list)
    for rva, r in by_rva.items():
        classes[classify(r, by_rva)].append(rva)

    wanted = set(x.strip() for x in args.limit_classes.split(",") if x.strip())
    order = ["thunk", "leaf-getter", "leaf-setter", "small-leaf", "branchy", "large", "unknown"]
    queues = {}
    for cls in order:
        if wanted and cls not in wanted:
            continue
        # Prefer auto-named (untouched) functions with known callers first:
        # they are frontier work, not already-promoted assets.
        items = sorted(classes.get(cls, []),
                       key=lambda k: (-by_rva[k].get("callerTotal", 0), k))
        batches = [items[i:i + args.batch_size]
                   for i in range(0, min(len(items), 600), args.batch_size)]
        queues[cls] = {
            "count": len(items),
            "batches_shown": len(batches),
            "verified_hint": sum(1 for k in items if not by_rva[k].get("autoNamed")),
            "batches": [[{"rva": k, "size": by_rva[k].get("sizeBytes"),
                          "callers": by_rva[k].get("callerTotal", 0)}
                         for k in b] for b in batches],
        }

    out = {"schema": "sims2-frontier-triage/1", "index_records": len(by_rva),
           "bad_lines": bad, "batch_size": args.batch_size, "classes": queues}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1)
    print(f"index: {len(by_rva)} functions ({bad} bad lines skipped) -> {args.out}")
    for cls in order:
        q = queues.get(cls)
        if q:
            print(f"  {cls:11s} {q['count']:6d} functions, "
                  f"{q['verified_hint']:4d} promoted, {q['batches_shown']} batches")


if __name__ == "__main__":
    main()
