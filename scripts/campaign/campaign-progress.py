#!/usr/bin/env python3
"""Engineering-progress classifier for the Ralph campaign director.

Why this exists. The Ralph runner records a boolean `progress` per iteration, and
run 3 proved two things about relying on it or on the surrounding files: a worker
that only writes prose still counts as progress (25 of 50 iterations produced zero
code while the runner reported progress every time), and `changedFiles` reports
only uncommitted leftovers, so it under-reported 6,876 lines of code as docs-only.
A director that chains runs must not inherit either blind spot, so it derives
progress itself from committed content.

Rules, deliberately simple and auditable:

  engineering  code lines added >= --min-code-lines AND (a test/check was added
               OR at least one new code file appeared)
  partial      enough code lines, but no new check and no new code file
  trivial      some code lines, below the threshold
  docs-only    no code lines at all, prose added
  none         nothing changed in the range

Self-reported flags are never consulted. Only `git diff`/`git show` output for the
requested range is used, so the verdict is reproducible after the fact.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

CODE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh",
    ".py", ".sh", ".bash", ".ts", ".tsx", ".js", ".mjs", ".cjs",
    ".cmake", ".gradle", ".kts", ".java", ".kt", ".rs", ".go",
}
CODE_NAMES = {"CMakeLists.txt", "Makefile", "build.gradle", "build.gradle.kts"}
DOC_SUFFIXES = {".md", ".rst", ".txt", ".adoc"}

# Directories whose prose is engineering evidence at most, never progress on its own.
DOC_DIR_PREFIXES = ("docs/",)


def git(repo: str, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def classify_path(path: str) -> str:
    """Return 'code', 'doc' or 'other' for one repository-relative path."""
    if path.startswith(DOC_DIR_PREFIXES):
        return "doc"
    name = path.rsplit("/", 1)[-1]
    if name in CODE_NAMES:
        return "code"
    suffix = Path(name).suffix.lower()
    if suffix in CODE_SUFFIXES:
        return "code"
    if suffix in DOC_SUFFIXES:
        return "doc"
    return "other"


def count_checks(repo: str, rev: str) -> dict:
    """Count independent checks at a revision: Python test defs plus CTest cases.

    This is a *proxy* for verification surface, not a test run. The director runs
    the real suites separately; this number only detects a run that added
    capability without adding any way to check it.
    """
    def hits(pattern: str, paths: tuple[str, ...]) -> int:
        # Count matching LINES rather than using -c: with a revision argument git
        # prints `rev:path:count`, which is not a bare number and silently summed
        # to zero in the first draft of this file.
        proc = subprocess.run(
            ["git", "-C", repo, "grep", "-I", "-h", "-E", "-e", pattern, rev, "--", *paths],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode not in (0, 1):  # 1 = no match, anything else is an error
            raise RuntimeError(f"git grep failed for {pattern!r} at {rev}: {proc.stderr.strip()}")
        return sum(1 for line in proc.stdout.splitlines() if line.strip())

    out = {
        "python_tests": hits(r"^[[:space:]]*def test_", ("tests",)),
        # CTest cases live in the ROOT CMakeLists.txt as well as native/ and tests/.
        # Restricting to native/tests silently reported 0 for 12 real targets.
        "ctest_cases": hits(r"^[[:space:]]*add_test\(", ("CMakeLists.txt", "native", "tests")),
    }
    out["total"] = out["python_tests"] + out["ctest_cases"]
    return out


def measure(repo: str, rev_from: str, rev_to: str, min_code_lines: int) -> dict:
    diff = git(repo, "diff", "--numstat", f"{rev_from}..{rev_to}", "--")
    code = {"files": 0, "added": 0, "deleted": 0}
    doc = {"files": 0, "added": 0, "deleted": 0}
    other = {"files": 0, "added": 0, "deleted": 0}
    new_code_files: list[str] = []

    name_status = git(repo, "diff", "--name-status", f"{rev_from}..{rev_to}", "--")
    added_paths = set()
    for line in name_status.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        if status.startswith("A") and classify_path(path) == "code":
            added_paths.add(path)

    for line in diff.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        add_s, del_s, path = parts[0], parts[1], parts[2]
        # Binary files report "-" for both counts.
        added = int(add_s) if add_s.isdigit() else 0
        deleted = int(del_s) if del_s.isdigit() else 0
        kind = classify_path(path)
        bucket = {"code": code, "doc": doc, "other": other}[kind]
        bucket["files"] += 1
        bucket["added"] += added
        bucket["deleted"] += deleted

    checks_before = count_checks(repo, rev_from)
    checks_after = count_checks(repo, rev_to)
    checks_added = checks_after["total"] - checks_before["total"]

    reasons: list[str] = []
    new_code_files = sorted(added_paths)
    if code["added"] >= min_code_lines and (checks_added >= 1 or new_code_files):
        classification = "engineering"
        evidence = (
            f"+{checks_added} checks" if checks_added >= 1
            else f"{len(new_code_files)} new code file(s)"
        )
        reasons.append(f"+{code['added']} code lines, {evidence}")
    elif code["added"] >= min_code_lines:
        classification = "partial"
        reasons.append(f"+{code['added']} code lines but no new check and no new code file")
    elif code["added"] > 0:
        classification = "trivial"
        reasons.append(f"+{code['added']} code lines is below the {min_code_lines}-line threshold")
    elif doc["added"] > 0 or other["added"] > 0:
        classification = "docs-only"
        reasons.append(f"no code lines changed (doc +{doc['added']}, other +{other['added']})")
    else:
        classification = "none"
        reasons.append("no tracked content changed in range")

    commits = int(git(repo, "rev-list", "--count", f"{rev_from}..{rev_to}") or 0)

    return {
        "range": f"{rev_from}..{rev_to}",
        "commits": commits,
        "code": code,
        "doc": doc,
        "other": other,
        "new_code_files": new_code_files,
        "checks": {"before": checks_before, "after": checks_after, "added": checks_added},
        "classification": classification,
        "reasons": reasons,
        "progress": classification == "engineering",
        # Recorded so a reader can confirm the runner's own flag was not consulted.
        "self_reported_progress_used": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Classify committed work in a git range.")
    ap.add_argument("--repo", default=".", required=False)
    ap.add_argument("--from", dest="rev_from", required=True)
    ap.add_argument("--to", dest="rev_to", default="HEAD")
    ap.add_argument("--min-code-lines", type=int, default=150)
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    try:
        result = measure(args.repo, args.rev_from, args.rev_to, args.min_code_lines)
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}))
        return 4
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
