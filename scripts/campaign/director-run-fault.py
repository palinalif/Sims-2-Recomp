#!/usr/bin/env python3
"""Decide whether a zero-progress run was actually a MODEL/PROVIDER outage.

The director measures engineering progress from committed content, so a run
whose iterations ALL died inside the model call (usage limit, rate limit,
provider 5xx, transport failure before the agent acted) looks identical to a
lazy worker: zero diff, classification "none". Routing that through the
stagnation machine is wrong twice over — it blocks the objective and it
charges the fleet-wide stagnation streak. Observed 2026-10-28T22:18Z: BOTH
lanes produced 0-diff runs whose every iteration carried
"Model request failed: Codex error: The usage limit has been reached", and
the fleet stopped as stopped:blocker citing gate 78.

Usage:  director-run-fault.py <iterations.jsonl> <loop-token-prefix>

Reads the Ralph runner's iterations.jsonl (records carry status and
rpcTelemetry.error) and prints exactly one line:

  fault <detail>   EVERY iteration of this run errored (error/timeout) AND
                   every error matches a provider-fault pattern AND the run
                   completed at least two iterations. A pure outage.
  clean            Anything else — a behaved iteration, a non-provider error,
                   an unreadable file, a single iteration. Fail-closed: the
                   run stays classified as worker stagnation.

This tool only reclassifies OUTCOMES; it never weakens a gate, never
launches anything, and is deliberately conservative (one behaved iteration
makes the whole run clean).
"""
import json, re, sys

FAULT_RE = re.compile(
    r"usage limit|rate[ _-]?limit|quota|payment required|overloaded"
    r"|temporarily unavailable|model request failed|exceeded your"
    r"|insufficient (?:balance|credit)|too many requests"
    r"|token has expired|authentication|unauthorized|invalid api key"
    r"|\b(?:429|502|503|529)\b",
    re.IGNORECASE)

def main(argv):
    if len(argv) != 3:
        print("clean"); return 0
    path, tok = argv[1], argv[2]
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            recs = [json.loads(l) for l in fh if l.strip()]
    except (OSError, ValueError):
        print("clean"); return 0
    iters = [r for r in recs
             if isinstance(r, dict)
             and (not tok or str(r.get("loopToken") or "").startswith(tok))]
    if len(iters) < 2:
        print("clean"); return 0
    detail = ""
    for r in iters:
        if r.get("status") not in ("error", "timeout"):
            print("clean"); return 0      # a behaved iteration: not an outage
        err = str((r.get("rpcTelemetry") or {}).get("error") or "")
        if not FAULT_RE.search(err):
            print("clean"); return 0      # unexplained error: stay stagnation
        detail = detail or err
    print(f"fault {detail[:180]}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
