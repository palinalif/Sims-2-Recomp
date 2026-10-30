#!/usr/bin/env python3
"""Decide whether a run's verify.json describes an integrity violation.

Why this file exists: the same rule was written out twice - once in campaign-verify.sh,
which produced the verdict, and once inside campaign-director.sh's decide(), which acted on
verify.json. When the gate was relaxed on 2026-10-24 the director's copy was missed, so run
4 of recomp-benchmark-20261023 was verified clean (verdict "pass", build ok, CTest 22/22,
572 Python tests, 0 skips, acceptance fail-closed at 78) and was STILL ended as
"integrity-violation", because the director read the legacy informational field
"tests_modified_or_deleted" (1) instead of the signals that actually matter. One rule, one
implementation, two callers.

Guilt is a measurable LOSS of coverage, never plain modification - this campaign extends
the differential harnesses its own earlier runs added, so test files are edited on every
healthy run. The authoritative answer is the "integrity_violation" boolean written by
campaign-verify.sh. Older verify.json files that predate it fall back to the three loss
signals, and files that predate even those are judged by the rule of their own era (any
modification), which is recorded here rather than quietly reinterpreted.

Usage: campaign-integrity-check.py <verify.json>   -> clean | violation | unknown
Exit: 0 clean, 1 violation, 2 unknown (unreadable)
"""
import json
import sys

LOSS_KEYS = ("test_files_deleted", "test_functions_removed", "skip_markers_added")


def verdict(path):
    with open(path) as fh:
        integrity = (json.load(fh) or {}).get("integrity") or {}
    acc = bool(integrity.get("acceptance_script_modified")) or bool(
        integrity.get("completion_promise_claimed"))
    if "integrity_violation" in integrity:
        return bool(integrity["integrity_violation"]) or acc
    if any(k in integrity for k in LOSS_KEYS):
        return acc or any(integrity.get(k, 0) > 0 for k in LOSS_KEYS)
    return acc or integrity.get("tests_modified_or_deleted", 0) > 0


def reasons(path):
    """Human-readable trigger list, for the director's stop message."""
    integrity = (json.load(open(path)) or {}).get("integrity") or {}
    labels = [("test_files_deleted", "test file(s) deleted"),
              ("test_functions_removed", "test function(s) removed"),
              ("skip_markers_added", "skip/xfail marker(s) added"),
              ("acceptance_script_modified", "acceptance script modified"),
              ("completion_promise_claimed", "completion promise claimed")]
    hits = ["%s %s" % (integrity.get(n), label)
            for n, label in labels if integrity.get(n) not in (None, 0, False)]
    if not hits and "integrity_violation" not in integrity \
            and not any(k in integrity for k in LOSS_KEYS) \
            and integrity.get("tests_modified_or_deleted", 0) > 0:
        # Only files written before the loss signals existed may be blamed on "modified";
        # a file that reports the real signals and reports them clean must not be.
        hits.append("%s test file(s) MODIFIED under the pre-2026-10-24 rule "
                    "(that rule could not distinguish growth from weakening)"
                    % integrity["tests_modified_or_deleted"])
    return hits


def main(argv):
    # Flags may come before or after the path; the old code read argv[1] unconditionally and
    # tried to open the literal "--why" as a file.
    rest = [a for a in argv[1:] if a not in ("--why", "-")]
    why = "--why" in argv[1:]
    path = rest[0] if rest else "-"
    if why:
        try:
            hits = reasons(path if path != "-" else "/dev/stdin")
            print("; ".join(hits) if hits else "no integrity signal set")
            return 0
        except Exception as exc:  # noqa: BLE001 - a broken report is "unknown", not a crash
            print("unreadable verify.json: %s" % exc)
            return 2
    try:
        bad = verdict(path if path != "-" else "/dev/stdin")
    except Exception:  # noqa: BLE001 - fail closed to "unknown", the director bounds it
        print("unknown")
        return 2
    print("violation" if bad else "clean")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
