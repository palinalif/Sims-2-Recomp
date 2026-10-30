# Phase 1 provisioning brief (operator-owned infrastructure)

Purpose: the two things no agent iteration can create — a **trusted independent
Phase 1 validator** and a **compatible Android execution target** — plus how to
prove they are wired up correctly. Everything an agent may do is described;
nothing in here asks an agent to author the validator.

Audience: the owner (and any human operator acting for them). Sections 1 and 5
are the parts an agent cannot fake. Section 6 is what I change afterwards.

Status reference: `scripts/phase1-acceptance.sh` exits **78** while
`TS2_TRUSTED_PHASE1_VALIDATOR` is unset. That is correct behaviour, not a bug to
remove. Five P0 items in `tasks/android-phase1/OPEN_QUESTIONS.md` stay open
until this brief is executed.

---

## 1. The validator contract (read from `scripts/phase1-acceptance.sh`)

The gate is 45 lines of POSIX shell. It refuses **before** running anything
unless all of these hold:

| Requirement | Enforced as |
|---|---|
| `TS2_TRUSTED_PHASE1_VALIDATOR` set | otherwise `exit 78`, "validator is unset" |
| Value is an **absolute** path | `case "$VALIDATOR" in /*)` |
| Target is a regular, **executable** file | `-f` and `-x` |
| `readlink -f` resolves **outside** the checkout | resolved path may not start with `$TS2_ROOT/` (rejects symlinks back into the repo) |
| Invocation shape | `exec "$RESOLVED_VALIDATOR" --repo "$TS2_ROOT" --task "$TS2_ROOT/tasks/android-phase1"` |
| Verdict | the validator's **exit status is returned verbatim** (`tests/test_phase1_acceptance.py::test_external_validator_exit_status_is_preserved`) |

`tests/test_phase1_acceptance.py` also asserts the four refusals above, so the
gate cannot be softened without breaking a test.

### 1.1 The independence requirement people skip

Placing the validator outside the checkout satisfies the *path* check. It does
not by itself make it trusted: if the validator is owned by the same user id the
agent runs as (this container runs as `node`), the agent can rewrite it. Pick
one:

- **Preferred:** the validator binary lives on the **machine attached to the
  device**, owned by a different account. On the agent host there is only a thin
  ssh client, `0555`, owned by another uid. The agent never holds write access to
  any program that contributes to the verdict.
- Acceptable single-host variant: validator lives in `/opt/ts2-validator`,
  owned `root:ts2audit`, mode `0755`/`0555`, agent is not in the group; the
  validator re-executes its real work as `ts2audit` (sudoers rule limited to that
  one path, `NOPASSWD`, no shell).

Prove it in both directions (section 5).

### 1.2 Exit-status convention

The gate preserves the number, so keep it boring and documented:

- `0` — every Phase 1 criterion proven on the device, evidence bundle complete.
- `1` — a criterion failed (this is a *result*, not an infrastructure problem).
- `2` — validator configuration/environment error (device gone, adb missing).
- `3` — refused input (APK not built from the requested commit, diagnostic
  build, stale evidence).

Never `78` (the gate reserves it), never `0` "because the APK installed".

---

## 2. What the validator must actually prove

Criteria come from the mission and `tasks/android-phase1/RALPH.md`; the
validator, not the repo, decides whether they are met. It must fail if evidence
is absent, partial, stale or diagnostic-only.

1. **Build identity.** Record the git rev of `--repo`, the APK SHA-256, and
   `aapt dump badging` output. Refuse (`3`) unless the APK under test was built
   by the build step run at invocation time from that rev.
2. **Refuse diagnostic builds.** `applicationId org.ts2native.diagnostic`,
   `versionName` matching `*-diagnostic*`, or the six-tile diagnostic activity
   ⇒ exit `3`. Today's APK must hit this branch.
3. **Real target.** Capture `ro.product.model`, `ro.build.version.sdk`,
   `ro.product.cpu.abi`, `getconf PAGE_SIZE`, battery/temperature, and require
   `arm64-v8a` within API 26…36 (see section 3).
4. **Legitimate assets, real menu.** The expected answers live **in the
   validator**, not the repo: owner-supplied asset/UI hashes from the owner's own
   game installation, held in the validator's private config. Assert against a
   screenshot plus `uiautomator dump`. A synthetic frame or an empty Activity
   fails.
5. **Scripted entry into a real neighborhood/lot.** The validator drives its own
   input sequence (its own script, never one read from `--repo`) and asserts the
   state transitions it expects via `logcat` + `dumpsys activity`.
6. **120 seconds of stability.** For ≥120 s: same PID throughout; no
   `FATAL EXCEPTION`, `AndroidRuntime`, fatal-signal or ANR markers in
   `logcat`/`dumpsys dropbox`/tombstones; frame production keeps advancing
   (`dumpsys gfxinfo <pkg>` or SurfaceFlinger frame counter delta > 0 across the
   window). A 120 s run with zero frames is not stability.
7. **Evidence bundle outside the checkout**, e.g.
   `/var/lib/ts2-validator/runs/<utc-timestamp>/`: APK hash, device
   fingerprint, screenshots, logcat, dropbox/tombstone listing, gfxinfo deltas,
   per-assertion pass/fail, and a `SHA256SUMS` manifest. Last stdout line is
   machine-readable:
   `TS2_PHASE1 verdict=PASS build=<sha256> device=<serial> seconds=<n>`
   (or `verdict=FAIL reason=<token>`). Exit `1`/`3` means it must *not* print
   `verdict=PASS`.

Device-identifying logs and any original game bytes/asset hashes stay private
(owner-only paths, never Git/CI) per `AGENTS.md`. The validator writes nothing
into the checkout; `--repo` is read-only input.

---

## 3. A compatible Android execution target

The APK is **`arm64-v8a` only** (`android/app/build.gradle`: `abiFilters
'arm64-v8a'`, `minSdk 26`, `compileSdk 35`, `targetSdk 35`, NDK
`27.2.12479018`, C++20, `c++_shared`). A "compatible target" therefore means:

- arm64-v8a, API 26…36, installable with `adb install -r`, no requested
  permissions (so no interactive permission grants needed);
- host can run `adb install/screencap/logcat/shell/uiautomator`;
- screen stays on and unlocked, `adb input` injection works;
- dropbox/tombstones readable over `adb shell`.

### Option A — reuse the authorized physical device (recommended)

The Samsung **SM-S931B**, Android 16 / API 36, `arm64-v8a`, Adreno, 4 KiB pages
already installed and cold-launched this app with native surface acquisition
(`docs/LOCAL_VALIDATION.md`, "Diagnostic APK phone pass"). Highest fidelity,
zero new cost, and it is the device the owner already authorized.

Setup (on the validator host):

```sh
adb wait-for-device
for p in ro.product.model ro.build.version.sdk ro.product.cpu.abi; do adb shell getprop "$p"; done
adb shell getconf PAGE_SIZE
adb shell svc power stayon true
adb shell settings put system screen_off_timeout 2147483647
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0
adb logcat -c && adb shell dumpsys dropbox --print > /tmp/dropbox-before.txt
```

Known gaps this leaves open: 4 KiB pages, so **16 KiB-page behaviour stays
untested** (the APK does pass `zipalign -c -P 16 4`, so it should install on a
16 KiB device — verify, don't assume); sustained runs, rotation, Android
TV/tablet and real controller hotplug. ADB-injected input is not a controller.

### Option B — hosted ARM64 device farm

Firebase Test Lab / AWS Device Farm give real ARM64 hardware, but two checks
come first: the provider must allow a custom long-running scripted session (not
only instrumentation), and the run needs legitimate game assets on the device —
uploading the owner's game data to a third party is a **licensing decision for
the owner**, not an engineering convenience. If that is not acceptable, a farm
cannot produce Phase 1 evidence.

### Option C — ARM64 emulator

An arm64 AVD needs an **arm64 host** (Graviton, ARM SBC, Apple Silicon) for
acceleration. An x86_64 host cannot accelerate an arm64 image, and the current
APK is arm64-only, so an x86_64 emulator cannot run it at all. Any emulator
result must be labelled emulator-only, with ARM64 hardware validation pending —
the task config already requires that wording.

### Explicitly out of scope

Wine, Winlator, Box86, or any runtime x86 emulation of the PC game is not a
target and not a shortcut (`AGENTS.md`). Optional: an `x86_64` ABI build of the
shell would enable a local x86_64 AVD for *diagnostics only* — it doubles the
verification matrix and must never be recorded as Phase 1 evidence.

---

## 4. Install the validator plumbing

```sh
# Operator host, as an operator/privileged account — never as the agent user.
install -d -m 0755 /opt/ts2-validator /var/lib/ts2-validator/runs
install -m 0555 ./ts2-phase1-validator /opt/ts2-validator/ts2-phase1-validator
# Agent-visible entry point if the real work runs elsewhere: thin ssh client, 0555.

# Make it visible to operator and worker shells (read-only from the agent):
echo 'export TS2_TRUSTED_PHASE1_VALIDATOR=/opt/ts2-validator/ts2-phase1-validator' \
  >> .dev-tools/env.sh        # sourced by scripts/campaign/worker-env.sh
```

Then confirm the gate stopped refusing and the refusals still work:

```sh
scripts/phase1-acceptance.sh; echo "exit=$?"           # no longer 78
python3 -m unittest tests.test_phase1_acceptance -v    # still 5 tests OK
```

Ship it **dry-run first**: a first version should print what it would check, list
the device it reached, and exit `2` (or `1`), never `0`. Flip to enforcing only
after a manual pass.

---

## 5. Prove the provisioning is real (do these five)

1. **Write attempt from the agent uid fails.**
   `su node -c 'printf x >> /opt/ts2-validator/ts2-phase1-validator'` ⇒ `EACCES`.
2. **Symlink escape refused.** Point the env var at a symlink inside the
   checkout that resolves outside it ⇒ gate exits `78` ("must live outside the
   agent-writable checkout").
3. **Negative test — today's APK.** Feed the validator the current *diagnostic*
   APK. It must exit `3` and must not print `verdict=PASS`. This is the single
   most important check: it proves the validator is not an install-check.
4. **Negative test — wrong build.** Feed an APK from a different rev or a stale
   bundle ⇒ exit `3`, no `PASS`.
5. **Positive test on hardware the agent cannot touch.** One supervised run
   against a build you believe is good; keep the bundle hash. If it cannot pass
   when it should, it is not a validator, it is a blocker.

---

## 6. What I change afterwards (no agent involvement needed from you)

1. Add the verified interface + evidence hash convention to `docs/VERIFICATION.md`
   and the engineering handoff (private record), and record that the validator is operator-owned.
2. Re-run `scripts/phase1-acceptance.sh` under the campaign, and a bounded
   campaign run whose P0 items can then move from "infrastructure unavailable"
   to "available, pending result".
3. Keep the validator, its expected-answer hashes, device identifiers and raw
   device logs **out of Git**; only the interface documentation is committed.

## 7. Effort and decision points

| Decision | Cost | Consequence if deferred |
|---|---|---|
| Dedicate SM-S931B + a Linux host with adb | ~1 h setup, ~1–2 h idle per run | Phase 1 unverifiable; campaigns keep stopping at the same wall |
| Author validator (scripted, your criteria) | largest item | acceptance stays fail-closed — correct, but terminal |
| Optional second device with 16 KiB pages | hardware | 16 KiB behaviour remains unclaimed |
| Cloud ARM64 farm | billing + asset-transfer approval | only needed if the physical device is unavailable |

Nothing here requires a repository change, an agent-written validator, or a
weaker gate.
