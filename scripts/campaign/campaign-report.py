#!/usr/bin/env python3
"""Consolidated report across every run of one campaign.

One document, not one document per run. The operator asked not to have to stitch
run reports together, and the interesting quantity is the campaign: did committed
engineering work accumulate, did independent verification stay green, what did the
director decide between runs, and why did it stop.

Every number here is derived from git or from a verification result written at the
time. Nothing is taken from the runner's self-reported progress flags, which run 3
showed can be true for 25 consecutive prose-only iterations.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import subprocess
import sys

EXIT_MEANING = {
    0: "loop reached a terminal status on its own",
    3: "supervisor enforced a budget/streak stop and the loop settled",
    4: "stop enforced but loop did not settle (unsafe)",
    5: "loop could not be observed (unsafe)",
    64: "supervisor usage error (a bug)",
}

REASON_HINT = {
    "budget-runs": "the configured number of consecutive runs was used up",
    "budget-wall": "the overall wall-clock budget was used up",
    "mission-complete": "the trusted acceptance gate actually exited 0",
    "stagnation": "repeated runs with no committed engineering artifact",
    "test-regression": "build or suites still failing after one repair run",
    "integrity-violation": "a protection moved, or completion was claimed falsely",
    "manual-stop": "an operator wrote the STOP file",
    "human-blocker-provisioning": "no engineering progress while acceptance stays fail-closed",
    "unsafe-infrastructure": "the loop or verifier could not be trusted to observe reality",
}


def run_files(state: str) -> list[str]:
    files = glob.glob(os.path.join(state, "runs", "*", "run.json"))
    return sorted(files, key=lambda p: int(p.split(os.sep)[-2]))


def git_short(sha: str) -> str:
    return (sha or "?")[:7]


def num(d: dict, *keys: str) -> int:
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return 0
        cur = cur.get(k, 0)
    return cur if isinstance(cur, int) else 0


def build(state: str) -> str:
    camp = json.load(open(os.path.join(state, "campaign.json")))
    runs = [json.load(open(p)) for p in run_files(state)]
    if not runs:
        return (f"# Campaign report: {camp.get('campaign')}\n\n"
                "No run has closed yet, so there is nothing to report. Per-run evidence "
                "appears under `runs/<n>/` once a run finishes and is verified.\n")
    open_runs = []
    for p in glob.glob(os.path.join(state, "runs", "*", "open.json")):
        try:
            open_runs.append(json.load(open(p)))
        except Exception:
            pass

    stop = camp.get("stop") or {}
    reason = stop.get("reason", "in progress")
    out: list[str] = []
    a = out.append

    a(f"# Campaign report: {camp.get('campaign')}")
    a("")
    a(f"- Task: `{camp.get('task')}` on branch `{camp.get('branch')}`")
    a(f"- Created: {camp.get('created_utc')}  |  Ended: {camp.get('stopped_utc', '-')}"
      f"  |  Runs recorded: {len(runs)}"
      + (f"  |  Open (interrupted): {len(open_runs)}" if open_runs else ""))
    b = camp.get("budget", {})
    a(f"- Budget: {b.get('max_wall_minutes')} min overall, {b.get('max_runs')} runs max, "
      f"{b.get('run_iterations')} iterations / {b.get('run_minutes')} min per run")
    a(f"- Overall outcome: **{reason}** — {stop.get('detail') or REASON_HINT.get(reason, '')}")
    a("")

    # ------------------------------------------------------------ run table
    a("## Runs")
    a("")
    a("| # | Window (UTC) | Token | Runner status | Iter | Sup exit | Build | CTest | Py tests | Code ±  | Checks | Class |")
    a("|---|---|---|---|---|---|---|---|---|---|---|---|")
    totals = {"code_add": 0, "code_del": 0, "commits": 0, "checks": 0}
    for r in runs:
        prog = r.get("progress") or {}
        ver = r.get("verification") or {}
        build_ok = ver.get("build_ok")
        if build_ok is None:
            build_txt = "n/a"
        elif build_ok:
            build_txt = "ok"
        else:
            build_txt = "FAIL"
        ctest_total = num(ver, "ctest_total")
        if ctest_total:
            ctest = "%d/%d" % (ctest_total - num(ver, "ctest_failed"), ctest_total)
        else:
            ctest = "-"
        a("| {n} | {s} -> {e} | `{t}` | {st} | {it} | {sx} | {bo} | {ct} | {py} | +{ca}/-{cd} | {ch} | `{cl}` |".format(
            n=r.get("run"),
            s=(r.get("started_utc") or "-")[11:], e=(r.get("ended_utc") or "-")[11:],
            t=str(r.get("loop_token") or "?")[:8],
            st=r.get("runner_status") or "?",
            it=r.get("iterations_reported") if r.get("iterations_reported") is not None else "?",
            sx=f"{r.get('supervisor_exit')}",
            bo=build_txt,
            ct=ctest,
            py=num(ver, "python_ran"),
            ca=num(prog, "code", "added"), cd=num(prog, "code", "deleted"),
            ch=num(prog, "checks", "added"),
            cl=prog.get("classification", "?"),
        ))
        totals["code_add"] += num(prog, "code", "added")
        totals["code_del"] += num(prog, "code", "deleted")
        totals["commits"] += num(prog, "commits")
        totals["checks"] += max(0, num(prog, "checks", "added"))
    a("")
    a(f"**Totals across runs:** {totals['commits']} commits, "
      f"+{totals['code_add']}/-{totals['code_del']} code lines, "
      f"{totals['checks']} net new checks (Python test defs + CTest cases).")

    # Campaign-wide git measurement, independent of the per-run arithmetic.
    base = camp.get("start_sha")
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if base and runs:
        rng = f"{base}..{head}"
        count = subprocess.run(["git", "rev-list", "--count", rng], capture_output=True, text=True).stdout.strip()
        numstat = subprocess.run(["git", "diff", "--numstat", rng], capture_output=True, text=True).stdout
        code_add = code_del = 0
        for line in numstat.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            path = parts[-1]
            if path.startswith("docs/") or path.endswith((".md", ".rst", ".txt")):
                continue
            if parts[0].isdigit():
                code_add += int(parts[0])
            if parts[1].isdigit():
                code_del += int(parts[1])
        a("")
        a(f"Campaign range `{git_short(base)}..{git_short(head)}`: {count} commits, "
          f"+{code_add}/-{code_del} non-documentation lines (measured directly from git, "
          "not summed from per-run reports).")

    # ------------------------------------------------------- verification trend
    a("")
    a("## Independent verification between runs")
    a("")
    a("Verification is `scripts/campaign/campaign-verify.sh`: clean CMake/Ninja build, all CTest "
      "suites, the full Python suite, the fail-closed acceptance gate, and the protection checks. "
      "It never consults worker self-reporting.")
    a("")
    a("| # | Verify exit | Verdict | Build | CTest failed | Python ran/skips | Acceptance exit | Protections |")
    a("|---|---|---|---|---|---|---|---|")
    for r in runs:
        ver = r.get("verification") or {}
        integ = ver.get("integrity") or {}
        prot = "clean"
        bad = []
        bOK = ver.get("build_ok")
        if bOK is None:
            bTxt = "?"
        elif bOK:
            bTxt = "ok"
        else:
            bTxt = "FAIL"
        # Guilt is lost or muted coverage, never an edited test file: this campaign extends
        # the harnesses its own earlier runs added. "modified" is shown as context only.
        if integ.get("test_files_deleted"):
            bad.append(f"test file(s) deleted ×{integ['test_files_deleted']}")
        if integ.get("test_functions_removed"):
            bad.append(f"test function(s) removed ×{integ['test_functions_removed']}")
        if integ.get("skip_markers_added"):
            bad.append(f"skip/xfail marker(s) added ×{integ['skip_markers_added']}")
        if integ.get("acceptance_script_modified"):
            bad.append("acceptance script modified")
        if integ.get("completion_promise_claimed"):
            bad.append("completion promise claimed")
        if bad:
            prot = "**" + ", ".join(bad) + "**"
        elif integ.get("tests_modified_or_deleted"):
            prot = "clean ({} test file(s) extended)".format(integ["tests_modified_or_deleted"])
        a("| {n} | {vx} | {vd} | {bo} | {cf} | {py}/{sk} | {ac} | {prot} |".format(
            n=r.get("run"), vx=r.get("verify_exit"), vd=ver.get("verdict", "?"),
            bo=bTxt,
            cf=ver.get("ctest_failed"), py=num(ver, "python_ran"), sk=num(ver, "python_skips"),
            ac=ver.get("acceptance_exit"), prot=prot,
        ))
    a("")
    a("The acceptance gate exiting 78 is the **expected** state: it fails closed until an "
      "independently owned validator is provisioned. A 0 there would mean the mission's "
      "completion promise was satisfied by a trusted external runner.")

    # ------------------------------------------------------------- directives
    directives = sorted(glob.glob(os.path.join(state, "directives", "*.md")))
    if directives:
        a("")
        a("## Director directives issued between runs")
        a("")
        for d in directives:
            text = open(d).read().strip().splitlines()
            head = text[1] if len(text) > 1 else ""
            a(f"- `{os.path.basename(d)}`: {head[:160]}")

    # --------------------------------------------------------------- evidence
    a("")
    a("## Evidence retained per run")
    a("")
    a("```")
    for r in runs:
        n = r.get("run")
        a(f"runs/{n}/  run.json  supervisor.log  verify.json  verify.err  progress.json"
          + ("  loop-output.log" if r.get("loop_output_archived") else ""))
    a("```")
    if open_runs:
        a("")
        a("**Note:** one or more runs are recorded as open, i.e. the director was interrupted "
          "while they were live. Re-running the director adopts them instead of starting a "
          "duplicate worker.")
    a("")
    a(f"_Generated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
      "by scripts/campaign/campaign-report.py._")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True, help="campaign state directory")
    ap.add_argument("--out", help="write to this path instead of stdout")
    args = ap.parse_args()
    if not os.path.isdir(args.state):
        print(f"campaign-report: no such state dir: {args.state}", file=sys.stderr)
        return 5
    text = build(args.state)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(args.out)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
