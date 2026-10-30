#!/usr/bin/env python3
"""Continuous campaign coordinator for the Sims 2 native Android port.

Hierarchy: coordinator -> campaign-director -> budgeted-supervisor -> Ralph runs.
This layer ONLY decides *when* a bounded campaign may run, *which objective* it
pursues, and *whether history permits continuation*. It never touches workers,
never edits protected files, never weakens a gate, and is itself bounded
(trial deadline, max campaigns, resource guards, sticky manual stop).

State machine per poll:
  STOP file            -> settle active campaign, state=stopped-manual, exit
  trial deadline       -> settle active campaign, state=trial-complete, exit
  resource guard fail  -> block NEW launches (active campaign is never killed)
  foreign live owner   -> refuse (never double-own the worktree)
  active director dead -> classify from durable records; resume/continue/stop
  no active campaign   -> pick next objective, launch a fresh bounded campaign

Durable, auditable records under --coordinator-root (default work/coordinator):
  state.json            atomic current state (tmp+rename, fsync)
  coordinator.log       append-only decisions with UTC stamps
  coordinator.lock/     owner.json + heartbeat (same pattern as the director)
  STOP                  sticky manual stop; start refuses while it exists
  OBJECTIVE.md          the objective handed to the next campaign
  campaigns/<id>.json   explicit start/end record per campaign

Exit codes: 0 finished/stopped cleanly, 3 stopped by policy (blocker/regression/
budget), 4 integrity violation, 5 infrastructure, 6 refused (already owned /
sticky stop).
"""
import argparse, json, os, shlex, shutil, signal, subprocess, sys, time
from datetime import datetime, timezone

def utcnow(): return datetime.now(timezone.utc)
def iso(t=None): return (t or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
def parse_iso(s):
    try: return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception: return None

def atomic_write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load_json(path, default=None):
    try:
        with open(path) as f: return json.load(f)
    except Exception:
        return default

def pid_alive(pid):
    """True only for a live (non-zombie) process; zombies keep /proc until reaped."""
    try:
        pid = int(pid)
        if not os.path.isdir(f"/proc/{pid}"): return False
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        state = data[data.rfind(b")") + 1:].split()[0]
        return state != b"Z"
    except Exception: return False

def epoch(): return int(time.time())

class Coord:
    def __init__(self, a):
        self.a = a
        self.root = a.coordinator_root
        self.state_root = a.state_root
        self.lock = os.path.join(self.root, "coordinator.lock")
        self.state_file = os.path.join(self.root, "state.json")
        self.log_file = os.path.join(self.root, "coordinator.log")
        self.stop_file = os.path.join(self.root, "STOP")
        self.objective_file = os.path.join(self.root, "OBJECTIVE.md")
        self.camp_dir = os.path.join(self.root, "campaigns")
        self.director = os.environ.get("TS2_COORDINATOR_DIRECTOR",
                                       "scripts/campaign/campaign-director.sh")
        self.child = None
        self.launched_at = 0.0
        self.nslots = max(1, getattr(a, "parallel", 1))
        self.slot_meta = {}  # slot -> {child, launched_at}

    # ---------- plumbing ----------
    def say(self, msg):
        os.makedirs(self.root, exist_ok=True)
        line = f"{iso()} {msg}"
        with open(self.log_file, "a") as f: f.write(line + "\n")
        print(line, flush=True)

    def heartbeat(self):
        try:
            with open(os.path.join(self.lock, "heartbeat"), "w") as f: f.write(str(epoch()))
        except Exception: pass

    def save(self, st):
        st["updated_utc"] = iso(); atomic_write(self.state_file, st)

    def acquire_lock(self, st):
        os.makedirs(self.root, exist_ok=True)
        if os.path.isdir(self.lock):
            own = load_json(os.path.join(self.lock, "owner.json"), {})
            hb = os.path.join(self.lock, "heartbeat")
            age = epoch() - int(os.path.getmtime(hb)) if os.path.exists(hb) else 1 << 40
            if pid_alive(own.get("pid")) and own.get("pid") != os.getpid():
                print(f"REFUSE coordinator already owned by live pid {own['pid']} (heartbeat {age}s)", file=sys.stderr)
                sys.exit(6)
            stale = os.path.join(self.root, f"coordinator.lock.stale-{epoch()}")
            os.rename(self.lock, stale); self.say(f"STALE coordinator lock (pid={own.get('pid')}, hb={age}s) moved to {stale}")
        os.makedirs(self.lock)
        atomic_write(os.path.join(self.lock, "owner.json"),
                     {"pid": os.getpid(), "started_utc": iso(), "role": "coordinator"})
        self.heartbeat()

    # ---------- campaign helpers ----------
    def run_git(self, args, cwd=None):
        try:
            r = subprocess.run(["git", "--no-pager"] + args,
                               cwd=cwd, capture_output=True, text=True, timeout=120)
            return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
        except Exception as exc:
            return 1, "", str(exc)

    def mainline_branch(self, st):
        if not st.get("mainline_branch"):
            rc, out, _ = self.run_git(["rev-parse", "--abbrev-ref", "HEAD"])
            if rc == 0 and out and out != "HEAD":
                st["mainline_branch"] = out
        return st.get("mainline_branch")

    def make_worktree(self, cid):
        """Parallel slot isolation: own worktree + branch; shared private work/
        via symlink (ignored pattern already covers it). Returns worktree path."""
        wt = os.path.abspath(os.path.join(self.a.worktree_root, cid))
        branch = f"coord/{cid}"
        if os.path.isdir(wt):
            return wt  # resume of an existing slot campaign; reuse its worktree
        base = self.mainline_branch(self.st_ref) if getattr(self, "st_ref", None) else "HEAD"
        os.makedirs(os.path.abspath(self.a.worktree_root), exist_ok=True)
        rc, _, err = self.run_git(["worktree", "add", "-f", wt, "-b", branch, base or "HEAD"])
        if rc != 0:
            rc2, _, err2 = self.run_git(["worktree", "add", "-f", wt, branch])
            if rc2 != 0:
                self.say(f"WORKTREE add failed for {cid}: {err[:120]} | {err2[:120]}")
                return None
        link = os.path.join(wt, "work")
        if not os.path.lexists(link):
            os.symlink(os.path.dirname(os.path.abspath(self.state_root)), link)
        npm_src = os.path.join(os.getcwd(), ".pi", "npm")
        npm_link = os.path.join(wt, ".pi", "npm")
        if os.path.isdir(npm_src) and not os.path.lexists(npm_link):
            os.makedirs(os.path.dirname(npm_link), exist_ok=True)
            os.symlink(os.path.abspath(npm_src), npm_link)  # read-only skills/mcp payload
        return wt

    def remove_worktree(self, wt):
        if wt:
            self.run_git(["worktree", "remove", "--force", wt])

    def merge_slot_branch(self, st, cid, rec):
        """Merge a finished slot branch onto the mainline; optional post-merge
        verify reverts the merge commit on failure. Never touches a dirty
        mainline: refuses instead of stashing anyone else's work."""
        br = rec.get("branch")
        if not br:
            return True, "no branch (mainline campaign)"
        rc, dirty, _ = self.run_git(["status", "--porcelain"])
        if rc != 0 or dirty:
            return False, f"mainline dirty; merge deferred for review (branch {br})"
        rc, n, _ = self.run_git(["rev-list", "--count", f"HEAD..{br}"])
        if rc != 0 or int(n or 0) == 0:
            self.remove_worktree(rec.get("worktree"))
            return True, "nothing to merge"
        rc, _, err = self.run_git(["merge", "--no-edit", "--no-ff", br])
        if rc != 0:
            self.run_git(["merge", "--abort"])
            return False, f"merge conflict on {br}; kept for review: {err[:160]}"
        self.say(f"MERGED branch={br} into {self.mainline_branch(st)}")
        if self.a.post_merge_verify:
            vcmd = shlex.split(self.a.verify_script or "scripts/campaign/campaign-verify.sh")
            v = subprocess.run(vcmd + ["--build-dir", "work/campaign-verify-build-coordinator"], capture_output=True)
            if v.returncode != 0:
                self.run_git(["reset", "--hard", "ORIG_HEAD"])
                self.say(f"MERGE-REVERTED {br}: post-merge verify exit {v.returncode}")
                return False, "post-merge verify failed; merge reverted"
        self.remove_worktree(rec.get("worktree"))
        return True, "merged"

    def campaign_commits(self, cid):
        """Commits recorded across a campaign's run receipts - measured by the
        director from git, never worker self-report. Zero means the campaign
        proved nothing and must not be credited as objective completion."""
        tot = 0
        rd = os.path.join(self.state_root, cid, "runs")
        if os.path.isdir(rd):
            for d in os.listdir(rd):
                r = load_json(os.path.join(rd, d, "run.json"), {})
                try: tot += int(r.get("progress", {}).get("commits", 0) or 0)
                except Exception: pass
        return tot

    def director_lock_owner(self, campaign):
        own = load_json(os.path.join(self.state_root, campaign, "director.lock", "owner.json"), {})
        return own.get("pid")

    def foreign_live_directors(self, except_campaign):
        out = []
        if not os.path.isdir(self.state_root): return out
        for cid in os.listdir(self.state_root):
            if cid == except_campaign: continue
            pid = self.director_lock_owner(cid)
            if pid and pid_alive(pid): out.append((cid, pid))
        return out

    def director_log_tail(self, campaign):
        p = os.path.join(os.path.dirname(self.state_root.rstrip("/")), "campaign-logs",
                         f"director-{campaign}.log")
        alt = os.path.join(self.root, f"director-{campaign}.log")
        for cand in (p, alt):
            try:
                with open(cand) as f: return f.read()
            except Exception: pass
        return ""

    def campaign_end_record(self, campaign):
        """Return (reason, detail) from the durable director log, else None."""
        for line in reversed(self.director_log_tail(campaign).splitlines()):
            if f"CAMPAIGN {campaign} ended reason=" in line:
                try:
                    reason = line.split("reason=", 1)[1].split(" ", 1)[0]
                    detail = line.split("detail=", 1)[1] if "detail=" in line else ""
                    return reason, detail
                except Exception: return "unknown", line
        return None

    def launch_director(self, campaign, objective, slot=0):
        # Safety interlock: a disposable selftest tree must never end up driving
        # the REAL director (a manual repro with the fake env var unset once
        # launched a live campaign against a scratch state root). Selftest always
        # passes its own fake; production never names coord-selftest.
        if "coord-selftest" in str(self.state_root) and "campaign-director.sh" in self.director:
            self.say(f"REFUSE real director against disposable state root {self.state_root}")
            return None
        log = os.path.join(self.root, f"director-{campaign}.log")
        rec = {"campaign": campaign, "objective": objective, "start_utc": iso(),
               "director_pid": None, "end_utc": None, "reason": None, "detail": None,
               "exit_code": None, "slot": slot}
        cwd = None
        if self.nslots > 1 and slot > 0:
            wt = self.make_worktree(campaign)
            if not wt:
                return None
            rec["worktree"] = wt
            rec["branch"] = f"coord/{campaign}"
            cwd = wt
        cmd = shlex.split(self.director)
        # Run the MAIN checkout's director, not a worktree's older copy - but only
        # when cmd[0] IS a relative path; a bare program name (python3, and the
        # selftest's fake director) must be resolved via PATH as-is.
        if not os.path.isabs(cmd[0]) and "/" in cmd[0] and os.path.exists(cmd[0]):
            cmd[0] = os.path.abspath(cmd[0])
        cmd = cmd + [
            "--task", self.a.task, "--campaign", campaign, "--yes",
            "--max-wall-minutes", str(int(self.a.campaign_hours * 60)),
            "--max-runs", str(self.a.campaign_runs),
            "--run-iterations", "50", "--run-minutes", str(self.a.campaign_run_minutes),
            "--max-stagnant-runs", "2", "--poll", "30",
            "--state-root", os.path.abspath(self.state_root)]
        if self.a.directive_writeback: cmd.append("--directive-writeback")
        os.makedirs(os.path.abspath(self.state_root), exist_ok=True)
        env = dict(os.environ)
        if self.nslots > 1: env["CAMPAIGN_ALLOW_PARALLEL"] = "1"
        if self.nslots > 1 and slot > 0: env["CAMPAIGN_VERIFY_BUILD_DIR"] = f"work/campaign-verify-build-slot{slot}"
        with open(log, "ab") as lf:
            p = subprocess.Popen(["setsid"] + cmd, stdout=lf, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True, cwd=cwd, env=env)
        rec.update({"director_pid": p.pid})
        meta = self.slot_meta.setdefault(str(slot), {})
        meta["child"] = p
        meta["launched_at"] = time.time()
        atomic_write(os.path.join(self.camp_dir, f"{campaign}.json"), rec)
        self.say(f"LAUNCH slot={slot} campaign={campaign} pid={p.pid} objective={objective}"
                 + (f" worktree={rec.get('worktree')}" if rec.get("worktree") else ""))
        return rec

    def settle_active(self, st, reason):
        cids = [c for c in (st.get("slots") or {}).values() if c]
        if st.get("active_campaign") and st["active_campaign"] not in cids:
            cids.append(st["active_campaign"])
        for cid in cids:
            pid = self.director_lock_owner(cid)
            if pid and pid_alive(pid):
                self.say(f"SETTLE campaign={cid} via director --stop ({reason})")
                subprocess.run(shlex.split(self.director) + ["--campaign", cid, "--stop", "--reason",
                                f"coordinator: {reason}"], capture_output=True)

    # ---------- objective selection ----------
    DEFAULT_OBJECTIVES = [
        ("init-chain", "Continue verified original-function dependency chains for game initialization (G1/G2: composed 0x1AB665 + GuestMemory/GuestDispatch integration)"),
        ("abi-services", "Expand reusable Win32/guest ABI runtime services required by newly verified dependencies"),
        ("upward-graph", "Walk the verified dependency graph upward toward the initialization sequence (G3)"),
        ("android-native", "Carry newly verified functions into the Android native library + JNI probe bundle (build-side)"),
        ("evidence-debt", "Fresh reproduction receipts, docs reconciliation, requirement-to-evidence audit"),
    ]

    def next_objective(self, st, busy=None, slot=0):
        q = load_json(os.path.join(self.root, "objective-queue.json"), None)
        blocked = set(st.get("blocked_objectives", {}))
        done = set(st.get("done_objectives", []))
        busy = busy or set()
        lane = "A" if slot == 0 else "B"
        if q:
            for strict in (True, False):
                for item in q:
                    if item.get("status") != "open" or item["id"] in blocked | done | busy:
                        continue
                    if strict and item.get("lane", "any") not in ("any", lane):
                        continue
                    if not strict and item.get("strict_lane") and \
                            item.get("lane", "any") not in ("any", lane):
                        continue
                    return item["id"], item.get("brief", item["id"])
        for oid, brief in self.DEFAULT_OBJECTIVES:
            if oid not in blocked | done | busy: return oid, brief
        return None, None

    def write_objective(self, oid, brief, st, slot=0):
        txt = (f"# CURRENT OBJECTIVE (coordinator-generated {iso()})\n\n"
               f"- id: `{oid}`\n- brief: {brief}\n"
               f"- campaign: `{st.get('slots', {}).get(str(slot)) or st.get('active_campaign')}`\n"
               f"- Standing authorization applies (docs/STANDING_AUTHORIZATION.md); "
               f"verification discipline and gates are unchanged; stop only for "
               f"safety/infrastructure/licensing/cost.\n")
        if self.nslots > 1:
            txt += (f"- You are parallel slot {slot} of {self.nslots}. For batch objectives, "
                    f"take batches whose index ≡ {slot} (mod {self.nslots}) from "
                    f"work/ghidra-index/triage.json; record completed batch indices in "
                    f"work/coord-slots/slot-{slot}-progress.json; never take another slot's "
                    f"batches or address ranges. Commit on the current branch only; never push.\n")
        txt += ("- When this objective is complete or genuinely blocked, update "
                "work/coordinator/objective-queue.json and OPEN_QUESTIONS.md.\n")
        with open(self.objective_file, "w") as f: f.write(txt)

    # ---------- classification ----------
    def stale_pretrial_record(self, st, rec):
        """True when a campaign was LAUNCHED before the current trial window.
        Its outcome belongs to a previous trial: it must not charge this
        trial's stagnation streak. Observed 2026-10-28T09:01:40Z: a fresh
        trial reset the streak to 0, then the FIRST thing it did was classify
        a leftover stagnant campaign from the dead trial (auto40-s1) and take
        the streak to 1 - so the next single stagnation (auto44-s1, itself a
        provider outage) stopped the whole fleet at 2. Terminal reasons
        (integrity/regression/infra) still apply regardless of vintage."""
        s = rec.get("start_utc") or ""
        t = st.get("trial_start_utc") or ""
        return bool(s) and bool(t) and s < t

    def classify(self, st, cid, exit_code, slot="0"):
        end = self.campaign_end_record(cid)
        reason = end[0] if end else ("exit-code-5" if exit_code == 5 else "interrupted")
        detail = end[1] if end else f"director exit {exit_code}, no end record"
        rec = load_json(os.path.join(self.camp_dir, f"{cid}.json"), {}) or {}
        rec.update({"end_utc": iso(), "reason": reason, "detail": detail, "exit_code": exit_code})
        atomic_write(os.path.join(self.camp_dir, f"{cid}.json"), rec)
        st["history"].append({"campaign": cid, "objective": rec.get("objective"),
                              "reason": reason, "start_utc": rec.get("start_utc"),
                              "end_utc": rec["end_utc"]})
        st["active_campaign"] = None
        st.setdefault("slots", {})[str(slot)] = None
        if reason == "integrity-violation" or exit_code == 4:
            return "STOP-INTEGRITY", "integrity violation - human review required"
        if reason in ("test-regression",) or exit_code == 44:
            if st["repair_budget"] > 0:
                st["repair_budget"] -= 1
                return "REPAIR", "one bounded repair campaign allowed"
            return "STOP-REGRESSION", "verification still failing after repair budget"
        if reason in ("budget-runs", "budget-wall", "mission-complete"):
            # A budget-exhausted campaign with ZERO committed content proves
            # nothing: runs crashed, spun, or were blocked. Count it as
            # stagnation so neither the objective nor the streak is credited.
            produced = self.campaign_commits(rec["campaign"]) > 0
            if produced:
                st["streak_stagnation"] = 0
                # Only a fully-consumed run budget (or explicit completion) plus
                # real commits proves the objective done; a wall termination can
                # be an outage artifact, so the objective stays open.
                if rec.get("objective") and reason in ("budget-runs", "mission-complete"):
                    st.setdefault("done_objectives", []).append(rec["objective"])
                return "CONTINUE", reason
            if self.stale_pretrial_record(st, rec):
                return "CONTINUE", f"pre-trial record ({reason}, zero progress); streak not charged"
            oid = rec.get("objective")
            st["streak_stagnation"] = st.get("streak_stagnation", 0) + 1
            if oid:
                st.setdefault("blocked_objectives", {})[oid] = f"{reason} with zero committed progress"
            if st["streak_stagnation"] >= self.a.max_stagnation_streak:
                return "STOP-BLOCKER", f"{st['streak_stagnation']} consecutive stagnant campaigns"
            return "CONTINUE", f"{reason} with zero committed progress; next objective"
        if reason in ("stagnation", "human-blocker-provisioning"):
            if self.stale_pretrial_record(st, rec):
                return "CONTINUE", f"pre-trial record ({reason}); streak not charged"
            oid = rec.get("objective")
            st["streak_stagnation"] = st.get("streak_stagnation", 0) + 1
            if oid: st.setdefault("blocked_objectives", {})[oid] = f"{reason}: {detail[:200]}"
            if st["streak_stagnation"] >= self.a.max_stagnation_streak:
                return "STOP-BLOCKER", f"{st['streak_stagnation']} consecutive stagnant campaigns"
            return "CONTINUE", f"stagnated ({reason}); next objective"
        if reason in ("unsafe-infrastructure",) or exit_code == 5:
            st["infra_retries"] = st.get("infra_retries", 0) + 1
            if st["infra_retries"] > self.a.max_infra_retries:
                return "STOP-INFRA", "infrastructure failures exceed tested recovery budget"
            if cid:  # resume the SAME campaign once (director adopts open run)
                st.setdefault("slots", {})[str(slot)] = cid; st["resumes"] = st.get("resumes", 0) + 1
                return "RESUME", f"resume {cid} once after {reason}"
            return "STOP-INFRA", reason
        if reason == "operator-stop":
            return "STOP-MANUAL", "director reports operator stop"
        if reason in ("manual-stop", "stopped"):
            # A manual stop from a PREVIOUS session (coordinator settle or
            # director --stop). The stop itself was already honored then;
            # reaching classify() on a fresh start means the operator now
            # wants work to continue. Release the slot without blocking or
            # completing the objective and without touching streak counters
            # (observed 21:01Z 2026-10-28: this outcome hit STOP-UNKNOWN and
            # killed the START with exit 3).
            return "CONTINUE", "prior manual stop honored earlier; slot released"
        if reason == "interrupted":
            st["infra_retries"] = st.get("infra_retries", 0) + 1
            if st["infra_retries"] > self.a.max_infra_retries:
                return "STOP-INFRA", "repeated interruption without end record"
            st.setdefault("slots", {})[str(slot)] = cid
            return "RESUME", f"resume {cid} (no end record; director will adopt or refuse)"
        return "STOP-UNKNOWN", f"unrecognized outcome {reason}"

    # ---------- resource guards ----------
    def guards_ok(self):
        try:
            st = os.statvfs(self.root)
            free_gb = st.f_bavail * st.f_frsize / 1e9
            if free_gb < self.a.min_disk_gb:
                return False, f"disk free {free_gb:.0f}G < {self.a.min_disk_gb}G"
        except Exception: pass
        try:
            la = os.getloadavg()[0]; n = os.cpu_count() or 4
            if la > 2.5 * n: return False, f"load1 {la:.1f} > {2.5*n:.0f}"
        except Exception: pass
        return True, ""

    # ---------- main loop ----------
    def run(self):
        st = load_json(self.state_file)
        if st is None:
            corrupt = self.state_file
            if os.path.exists(corrupt):
                keep = corrupt + f".corrupt-{epoch()}"
                shutil.copy(corrupt, keep)
                self.say(f"CORRUPT state preserved at {keep}; reinitializing from campaign records")
                campaigns = {}
                if os.path.isdir(self.camp_dir):
                    for fn in os.listdir(self.camp_dir):
                        r = load_json(os.path.join(self.camp_dir, fn))
                        if r: campaigns[r["campaign"]] = r
                st = {"schema": 1, "trial_start_utc": iso(),
                      "history": [{"campaign": k, "objective": v.get("objective"),
                                   "reason": v.get("reason") or "recovered-unknown",
                                   "start_utc": v.get("start_utc"), "end_utc": v.get("end_utc")}
                                  for k, v in campaigns.items()]}
            else:
                st = {"schema": 1, "trial_start_utc": iso(), "history": []}
        st.setdefault("active_campaign", None); st.setdefault("history", [])
        st.setdefault("repair_budget", self.a.repair_campaigns)
        st.setdefault("streak_stagnation", 0); st.setdefault("infra_retries", 0)
        st.setdefault("blocked_objectives", {}); st.setdefault("done_objectives", [])
        slots = st.setdefault("slots", {})
        if st.get("active_campaign") and not any(slots.values()):
            slots["0"] = st["active_campaign"]
        # Fresh-trial semantics (Hermes shift fix 2026-10-28): an *expired*
        # deadline or terminal trial-complete state means the previous trial
        # is over, so a new `start` opens a new window. A deadline still in
        # the future belongs to a live/paused trial and is PRESERVED on plain
        # restart — only --force-new-trial overrides it. Without this, every
        # post-trial start was a no-op that instantly re-hit
        # "STOPPED trial deadline reached" (observed 22:47Z via shift bridge).
        _old_dl = parse_iso(st.get("trial_deadline_utc") or "") or None
        _expired = (st.get("state") == "trial-complete") or (
            _old_dl is not None and utcnow() >= _old_dl)
        if self.a.force_new_trial or _old_dl is None or _expired:
            st["trial_start_utc"] = iso()
            st["trial_deadline_utc"] = iso(utcnow().fromtimestamp(
                utcnow().timestamp() + self.a.trial_hours * 3600))
            # History spans trials; the max-campaigns counter counts only
            # campaigns from this trial's start onwards.
            st["trial_campaign_floor"] = len(
                {h.get("campaign") for h in st.get("history", [])})
            st["streak_stagnation"] = 0
            st["infra_retries"] = 0
            st["repair_budget"] = self.a.repair_campaigns
            self.say(f"FRESH-TRIAL window {st['trial_start_utc']} -> "
                     f"{st['trial_deadline_utc']} (previous deadline: "
                     f"{_old_dl.strftime('%Y-%m-%dT%H:%M:%SZ') if _old_dl else 'none'}"
                     f"{', forced override' if self.a.force_new_trial else ''})")
        # else: live deadline preserved (restart/resume of the same trial).
        st["state"] = "running"; self.st_ref = st; self.acquire_lock(st); self.save(st)
        self.mainline_branch(st)
        self.say(f"START trial_deadline={st['trial_deadline_utc']} max_campaigns={self.a.max_campaigns} "
                 f"parallel={self.nslots} merge_on_green={self.a.merge_on_green} director={self.director}")

        while True:
            self.heartbeat()
            if os.path.exists(self.stop_file):
                self.settle_active(st, "manual stop"); st["state"] = "stopped-manual"; self.save(st)
                self.say("STOPPED manual stop file honored"); return 0
            dl = parse_iso(st["trial_deadline_utc"])
            if dl and utcnow() >= dl:
                self.settle_active(st, "trial deadline"); st["state"] = "trial-complete"; self.save(st)
                self.say("STOPPED trial deadline reached"); return 0
            active_any = any(slots.values())
            if len({h.get("campaign") for h in st["history"]}) - st.get("trial_campaign_floor", 0) >= self.a.max_campaigns and not active_any:
                st["state"] = "trial-complete"
                # Advance the floor so the NEXT fresh trial counts from here.
                st["trial_campaign_floor"] = len(
                    {h.get("campaign") for h in st["history"]})
                self.save(st)
                self.say("STOPPED max campaigns reached"); return 0

            # Deferred slot merges run only while NO director is active: merging
            # into the mainline under a running mainline campaign would mutate
            # that campaign's tree mid-run (observed 21:27Z).
            if self.a.merge_on_green and st.get("pending_merges") and not active_any:
                for pm in list(st["pending_merges"]):
                    rec_pm = load_json(os.path.join(self.camp_dir, f"{pm}.json"), {}) or {}
                    okp, whyp = self.merge_slot_branch(st, pm, rec_pm)
                    self.say(f"PENDING-MERGE {pm} ok={okp} why={whyp}")
                    if okp or "conflict" in whyp or "dirty" in whyp:
                        st["pending_merges"].remove(pm)
                    else:
                        break
                self.save(st)

            tracked = set(c for c in slots.values() if c)
            foreign = [(c, p) for (c, p) in self.foreign_live_directors(None) if c not in tracked]
            empty_slots = [s for s in range(self.nslots) if not slots.get(str(s))]
            if foreign and empty_slots:
                if len(foreign) == 1:
                    fcid, fpid = foreign[0]
                    slot = str(empty_slots[0]); slots[slot] = fcid
                    atomic_write(os.path.join(self.camp_dir, f"{fcid}.json"),
                                 {"campaign": fcid, "objective": f"adopted:{fcid}",
                                  "start_utc": iso(), "director_pid": fpid, "adopted": True,
                                  "slot": int(slot),
                                  "end_utc": None, "reason": None, "detail": None, "exit_code": None})
                    self.save(st)
                    self.say(f"ADOPT slot={slot} campaign={fcid} pid={fpid} (no duplicate launch)")
                    continue
                if st.get("foreign_seen") is None: st["foreign_seen"] = 0
                st["foreign_seen"] += 1
                self.say(f"WAIT foreign directors live: {foreign} (poll {st['foreign_seen']})")
                if st["foreign_seen"] > self.a.foreign_wait_polls:
                    st["state"] = "stopped-foreign-owner"; self.save(st)
                    self.say("STOPPED foreign owner persists; refusing to double-own the worktree")
                    return 6
                self.save(st); time.sleep(self.a.poll); continue
            st["foreign_seen"] = 0

            for slot_i in range(self.nslots):
                slot = str(slot_i)
                cid = slots.get(slot)
                if cid:
                    pid = self.director_lock_owner(cid)
                    meta = self.slot_meta.setdefault(slot, {})
                    # setsid may fork-and-exit, so the Popen handle is not a
                    # reliable liveness signal; the director lock owner is.
                    if meta.get("child") and time.time() - meta.get("launched_at", 0) < self.a.launch_grace \
                            and pid is None:
                        continue  # director still booting; do not classify yet
                    if not (pid and pid_alive(pid)):
                        if meta.get("child"): meta["child"].poll(); meta["child"] = None
                        action, why = self.classify(st, cid, -1, slot)
                        self.save(st)
                        self.say(f"CLASSIFY slot={slot} campaign={cid} exit=-1 action={action} why={why}")
                        if action.startswith("STOP"):
                            st["state"] = "stopped:" + action.split("-", 1)[1].lower()
                            self.save(st)
                            return {"stopped:integrity": 4}.get(st["state"], 3)
                        if action == "CONTINUE":
                            st["infra_retries"] = 0
                        rec_c = load_json(os.path.join(self.camp_dir, f"{cid}.json"), {}) or {}
                        if self.a.merge_on_green:
                            others = [c2 for k2, c2 in slots.items() if c2 and str(k2) != str(slot)]
                            if others and rec_c.get("branch"):
                                pml = st.setdefault("pending_merges", [])
                                if cid not in pml: pml.append(cid)
                                self.say(f"MERGE-DEFERRED {cid}: other slots still busy; merge queued for an idle window")
                            else:
                                ok, mwhy = self.merge_slot_branch(st, cid, rec_c)
                                self.say(f"SLOT-MERGE slot={slot} campaign={cid} ok={ok} why={mwhy}")
                        if action in ("RESUME", "REPAIR"):
                            rec = load_json(os.path.join(self.camp_dir, f"{cid}.json"), {}) or {}
                            if action == "REPAIR":
                                n = len(st["history"]) + 1
                                cid = f"recomp-repair{n}-s{slot}-{utcnow().strftime('%Y%m%dT%H%M%S')}"
                                slots[slot] = cid; self.save(st)
                                self.write_objective("repair-verification",
                                                     "Reproduce and repair the failing verification; preserve evidence; do not weaken any gate", st, slot_i)
                                self.launch_director(cid, "repair-verification", slot_i)
                            else:
                                self.launch_director(cid, rec.get("objective", "resumed"), slot_i)
                else:
                    ok, why = self.guards_ok()
                    if not ok:
                        st["guard_wait"] = st.get("guard_wait", 0) + 1
                        self.save(st)
                        self.say(f"GUARD wait: {why}")
                        if st["guard_wait"] > self.a.guard_wait_polls:
                            st["state"] = "stopped-resource"; self.save(st); return 5
                        continue
                    st["guard_wait"] = 0
                    if len({h.get("campaign") for h in st["history"]}) - st.get("trial_campaign_floor", 0) >= self.a.max_campaigns: continue
                    busy = set()
                    for ccid in slots.values():
                        if not ccid: continue
                        crec = load_json(os.path.join(self.camp_dir, f"{ccid}.json"), {}) or {}
                        if crec.get("objective"): busy.add(crec["objective"])
                    oid, brief = self.next_objective(st, busy, slot_i)
                    if oid is None:
                        if not any(slots.values()):
                            if st.get("pending_merges") and \
                                    st.get("stop_defer_polls", 0) < 3:
                                st["stop_defer_polls"] = st.get("stop_defer_polls", 0) + 1
                                self.save(st)
                                self.say("PRE-STOP: deferring exit to drain pending merges")
                                continue
                            st["state"] = "stopped-no-work"; self.save(st)
                            self.say("STOPPED no credible authorized objective remains"); return 3
                        continue
                    n = len(st["history"]) + 1
                    cid = f"recomp-auto{n}-s{slot}-{utcnow().strftime('%Y%m%dT%H%M%S')}"
                    slots[slot] = cid; self.save(st)
                    self.write_objective(oid, brief, st, slot_i)
                    rec = self.launch_director(cid, oid, slot_i)
                    if rec is None:
                        slots[slot] = None; self.save(st)
            st["active_campaign"] = next((c for c in slots.values() if c), None)
            self.save(st)
            time.sleep(self.a.poll)

    # ---------- modes ----------
    def status(self):
        st = load_json(self.state_file, {}) or {}
        own = load_json(os.path.join(self.lock, "owner.json"), {}) if os.path.isdir(self.lock) else {}
        hb = os.path.join(self.lock, "heartbeat")
        out = dict(st)
        out["coordinator_alive"] = pid_alive(own.get("pid"))
        out["heartbeat_age_s"] = epoch() - int(os.path.getmtime(hb)) if os.path.exists(hb) else None
        slots = st.get("slots") or {}
        if not any(slots.values()) and st.get("active_campaign"):
            slots = {"0": st["active_campaign"]}
        out["slots"] = {k: {"campaign": v, "director_alive": bool(v and pid_alive(self.director_lock_owner(v)))}
                        for k, v in slots.items() if v}
        out["active_director_alive"] = any(d["director_alive"] for d in out["slots"].values())
        print(json.dumps(out, indent=1)); return 0

    def stop(self, reason):
        st = load_json(self.state_file, {}) or {}
        with open(self.stop_file, "w") as f: f.write(f"{iso()} {reason}\n")
        self.say(f"STOP requested: {reason}")
        self.settle_active(st, f"manual stop: {reason}")
        return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", default="start",
                    choices=["start", "status", "stop", "clear-stop", "report"])
    ap.add_argument("--task", default="./tasks/android-phase1")
    ap.add_argument("--coordinator-root", default="work/coordinator")
    ap.add_argument("--state-root", default="work/campaigns")
    ap.add_argument("--trial-hours", type=float, default=48)
    ap.add_argument("--force-new-trial", action="store_true",
                    help="open a fresh trial window even if the stored "
                         "trial_deadline_utc is still in the future")
    ap.add_argument("--max-campaigns", type=int, default=12)
    ap.add_argument("--campaign-hours", type=float, default=4)
    ap.add_argument("--campaign-runs", type=int, default=3)
    ap.add_argument("--campaign-run-minutes", type=int, default=75)
    ap.add_argument("--max-stagnation-streak", type=int, default=2)
    ap.add_argument("--repair-campaigns", type=int, default=1)
    ap.add_argument("--max-infra-retries", type=int, default=2)
    ap.add_argument("--launch-grace", type=int, default=120)
    ap.add_argument("--poll", type=int, default=60)
    ap.add_argument("--min-disk-gb", type=float, default=20)
    ap.add_argument("--foreign-wait-polls", type=int, default=240)
    ap.add_argument("--guard-wait-polls", type=int, default=240)
    ap.add_argument("--directive-writeback", action="store_true")
    ap.add_argument("--verify-script", default="scripts/campaign/campaign-verify.sh")
    ap.add_argument("--parallel", type=int, default=1,
                    help="concurrent campaign slots (each beyond the first runs in "
                         "its own git worktree + coord/<cid> branch, merged only after "
                         "the campaign ended green)")
    ap.add_argument("--worktree-root", default="../sims2-coord-worktrees")
    ap.add_argument("--merge-on-green", action="store_true",
                    help="merge a slot's coord branch into the mainline when its "
                         "campaign ends with verification passing (parallel mode)")
    ap.add_argument("--post-merge-verify", action="store_true",
                    help="after merging, run scripts/campaign/campaign-verify.sh on the "
                         "mainline and revert the merge commit if it fails")
    ap.add_argument("--reason", default="operator stop request")
    a = ap.parse_args()
    c = Coord(a)
    if a.mode == "status": return c.status()
    if a.mode == "stop": return c.stop(a.reason)
    if a.mode == "clear-stop":
        if os.path.exists(c.stop_file): os.remove(c.stop_file); c.say("STOP file cleared")
        return 0
    if a.mode == "report":
        st = load_json(c.state_file, {}) or {}
        print(f"# Coordinator report {iso()}\n\nstate={st.get('state')} "
              f"trial={st.get('trial_start_utc')} -> {st.get('trial_deadline_utc')}\n")
        for h in st.get("history", []):
            print(f"- {h.get('campaign')}: objective={h.get('objective')} "
                  f"reason={h.get('reason')} {h.get('start_utc')} -> {h.get('end_utc')}")
        return 0
    if os.path.exists(c.stop_file):
        print("REFUSE sticky STOP file present; run 'clear-stop' first", file=sys.stderr); return 6
    c.last_exit_codes = {}
    try:
        return c.run()
    finally:
        try:
            own = load_json(os.path.join(c.lock, "owner.json"), {})
            if own.get("pid") == os.getpid(): shutil.rmtree(c.lock, ignore_errors=True)
        except Exception: pass

if __name__ == "__main__":
    sys.exit(main())
