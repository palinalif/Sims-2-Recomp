#!/usr/bin/env bash
# shift-watch.sh — Hermes shift-control bridge for Project Everlasting.
#
# Runs INSIDE the Pi container. Sole purpose: let the shift manager (Hermes,
# a different container) invoke the coordinator's EXISTING, supported commands
# via sentinel files. It never touches coordinator state directly, never
# bypasses gates, and never starts a campaign the coordinator would refuse.
#
# Protocol (all paths under $INBOX, default /pi-inbox/shift):
#   inbox/commands/START-<utc>.sentinel   -> clear-stop; then start if not running
#   inbox/commands/STOP-<utc>.sentinel    -> stop --reason "<first line of file>"
#   inbox/commands/STATUS-<utc>.sentinel  -> status (JSON) + report (markdown)
#   inbox/results/STATUS.json             -> written fresh after every command
#   inbox/results/LAST-<verb>.rc          -> exit code of the last command
#   inbox/commands/done/                  -> sentinels land here after processing
#
# Auth: every sentinel's first line must equal $SHIFT_TOKEN (set by the
# operator when launching this watcher). Mismatch => sentinel quarantined to
# inbox/commands/rejected/, nothing runs. If SHIFT_TOKEN is unset the watcher
# refuses to start entirely.
#
# Eligibility: this script never decides whether work is allowed. It calls
# `clear-stop`+`start` and lets the coordinator's own state machine refuse
# stopped:blocker / stopped:integrity / stopped:regression. Fail-closed by
# construction.
#
# Start (inside Pi, from the repo root):
#   SHIFT_TOKEN=*** setsid nohup bash /path/to/shift-watch.sh \
#     >> work/coordinator/shift-watch.out 2>&1 < /dev/null &
set -u

INBOX="${SHIFT_INBOX:-/pi-inbox/shift}"
REPO="${SHIFT_REPO:?set SHIFT_REPO to the sims2-native repo root}"
COORD="$REPO/scripts/campaign/campaign-coordinator.sh"
POLL="${SHIFT_POLL:-30}"
STATUS_STALE_MIN="${SHIFT_STATUS_STALE:-30}"   # minutes between heartbeat STATUS.json writes
CMD_TIMEOUT="${SHIFT_CMD_TIMEOUT:-600}"        # seconds; `stop` can settle for a while

[ -n "${SHIFT_TOKEN:-}" ] || { echo "shift-watch: SHIFT_TOKEN required (refusing to run unauthenticated)"; exit 64; }
[ -x "$COORD" ] || { echo "shift-watch: coordinator not found/executable at $COORD"; exit 65; }

umask 022
mkdir -p "$INBOX/commands/done" "$INBOX/commands/rejected" "$INBOX/results"
cd "$REPO" || exit 64

say() { printf '%s shift-watch: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

write_status() {
  # status command is read-only; on failure keep the old STATUS.json and record rc.
  local tmp="$INBOX/results/.STATUS.json.tmp"
  if timeout 120 "$COORD" status > "$tmp" 2>"$INBOX/results/.STATUS.err"; then
    mv -f "$tmp" "$INBOX/results/STATUS.json"
    : > "$INBOX/results/.status.ok"
  else
    say "status command failed (rc=$?)"
  fi
}

run_verb() {
  local verb="$1" sentinel="$2" reason="$3" rc
  case "$verb" in
    START)
      # Hermes bug fix 2026-10-28: `start` must NOT be hosted under
      # CMD_TIMEOUT — the coordinator is an always-on supervisor; hosting it
      # killed the fleet 10 min after every START (and rc 0 then only meant
      # "ran to some exit", hiding the fresh-trial no-op). Dispatch detached
      # per the documented recipe; rc 0 now means "launched and still alive
      # 5 s later". The shift manager must verify a fresh LAUNCH line via
      # STATUS.json — rc alone is never the proof.
      timeout 60 "$COORD" clear-stop; rc1=$?
      setsid nohup "$COORD" start >> "$INBOX/results/last-start.out" 2>&1 < /dev/null &
      echo $! > "$INBOX/results/coordinator.pid"
      sleep 5
      rc2=0; kill -0 "$(cat "$INBOX/results/coordinator.pid")" 2>/dev/null || rc2=1
      if [ "$rc2" -ne 0 ]; then
        # setsid may have exec'd (same pid) or forked (child pid);
        # fall back to the coordinator lock owner before declaring failure.
        LPID=$(cat "$REPO/work/coordinator/coordinator.lock" 2>/dev/null)
        if [ -n "$LPID" ] && kill -0 "$LPID" 2>/dev/null; then
          echo "$LPID" > "$INBOX/results/coordinator.pid"; rc2=0
        fi
      fi
      rc=$rc2; [ "$rc1" -ne 0 ] && [ "$rc1" != 0 ] && rc=$rc1 ;;
    STOP)
      timeout "$CMD_TIMEOUT" "$COORD" stop --reason "${reason:-scheduled end of shift}"; rc=$? ;;
    STATUS)
      write_status; rc=$?
      timeout 120 "$COORD" report > "$INBOX/results/REPORT.md" 2>/dev/null || true ;;
    *) rc=64 ;;
  esac
  printf '%s' "$rc" > "$INBOX/results/LAST-$verb.rc"
  mv -f "$sentinel" "$INBOX/commands/done/$(basename "$sentinel").rc$rc" 2>/dev/null
  write_status
  say "$verb finished rc=$rc"
}

say "watcher up (inbox=$INBOX repo=$REPO poll=${POLL}s)"
last_status_ts=0
while :; do
  # heartbeat: keep STATUS.json fresh even with no commands, so the shift
  # manager can distinguish "stopped" from "nobody home".
  now=$(date +%s)
  if [ $((now - last_status_ts)) -ge $((STATUS_STALE_MIN * 60)) ]; then
    write_status; last_status_ts=$now
  fi

  for SENT in "$INBOX"/commands/*.sentinel; do
    [ -e "$SENT" ] || continue
    TOKEN_LINE=$(head -n1 "$SENT" 2>/dev/null)
    NAME=$(basename "$SENT")
    if [ "$TOKEN_LINE" != "$SHIFT_TOKEN" ]; then
      say "AUTH FAIL on $NAME — quarantined"
      mv -f "$SENT" "$INBOX/commands/rejected/$NAME" 2>/dev/null
      continue
    fi
    VERB="${NAME%%-*}"                      # START-2026... -> START
    REASON=$(sed -n 2p "$SENT" 2>/dev/null)
    say "processing $NAME"
    run_verb "$VERB" "$SENT" "$REASON"
  done
  sleep "$POLL"
done
