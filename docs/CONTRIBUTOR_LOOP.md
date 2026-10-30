# Running an autonomous contributor loop (Ralph-style) on your own machine

This is the *external contributor* version of our internal campaign loop.
You point an AI coding agent (Pi, Claude Code, Codex, or similar) at this
repository and let it work unattended. It follows the same rules you would
manually — it just never sleeps.

## Prerequisites (do these once, interactively)

1. Complete the setup in `README.md` until `scripts/doctor.sh` and
   `scripts/test-host.sh` both pass.
2. Get a dashboard `worker_key` from the project owner (optional but
   appreciated — it puts your machine on the public progress board).
3. Decide your worker name (e.g. `home-pc`).

## The loop

Give your agent this contract (adapt wording to your agent, keep the rules):

> You are an autonomous contributor to this repository. Loop forever:
>
> 1. **Claim**: check `https://github.com/palinalif/Sims-2-Recomp/issues?q=label:claim`
>    and `docs/VERIFIED_LEDGER.md`. Pick one small unclaimed function
>    (prefer thunks, getters/setters, tiny leaf helpers; startup-path
>    functions in `docs/STARTUP_CRITPATH.md` are extra welcome). Open an
>    issue titled `Claim 0xRVA: short description` with label `claim`.
>    Wait 2 minutes before starting work in case of a simultaneous claim —
>    first open issue wins.
> 2. **Study**: read `AGENTS.md` (especially source readability rules) and
>    `docs/VERIFICATION.md`. Recover behaviour from your own analysis of
>    permitted inputs; never assume decompiler output is truth.
> 3. **Implement** on branch `recomp/<rva>-<name>`: readable C++, semantic
>    names, evidence cited in comments.
> 4. **Verify**: run `scripts/test-host.sh` plus any relevant tests. Attach
>    full command output as evidence in the PR. You may self-declare at most
>    tier T3 (host-proven); the maintainer re-runs everything before any
>    ledger row is granted.
> 5. **PR**: open a pull request referencing your claim issue. One function
>    per PR. Close your claim issue when the PR merges (or if you abandon).
> 6. **Heartbeat** (if you have a key): after every iteration, POST
>    `{"worker":"<name>","worker_key":"<key>","task":"recomp/<rva>",
>    "model":"<model>","gpu":"<gpu>","iterations":N,"verified":M}` to the
>    dashboard endpoint the owner gave you.
> 7. **Idle rule**: if you cannot claim or complete anything after a few
>    honest attempts, stop and post a `BLOCKED:` issue with exact evidence.
>    Never fabricate results, never touch `docs/VERIFIED_LEDGER.md`,
>    `scripts/`, or CI configuration, never push to `main`.

## Hard rules (unchanged from AGENTS.md)

- No game binaries, resources, or private fixtures in any commit, PR, or
  issue. If your setup lacks private analysis images, work what you can
  statically or from your own lawful installation — and say so in the PR.
- Skipped or weakened tests are not passes. Faked progress ends participation.
- Anything you cannot execute, you label `HYPOTHESIS:`.

## How this differs from the internal fleet

The campaign scripts in `scripts/campaign/` (coordinator/director/supervisor)
run against private fixtures on the maintainer's hardware and assume private
infrastructure — external loops should not run them. Your infrastructure is:
issues = claims, PRs = proof, GitHub = the bus.
