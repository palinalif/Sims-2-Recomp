#!/usr/bin/env bash
# Source this BEFORE launching any Pi worker / Ralph loop so child sessions
# inherit the toolchain this container actually provides.
#
# Evidence (2026-10-22 smoke run): a loop started without this reported
# "Git is not installed" inside the worker, silently degrading every repository
# check the acceptance prompts ask for. Ralph spawns children with
# `pi --mode rpc --no-session --no-extensions`, so nothing else puts the
# vendored git/python/JDK/Ghidra on their PATH.
#
# Usage:  . scripts/campaign/worker-env.sh
# Override the toolchain root with TOOLS_ROOT=/path if this layout differs.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../" && pwd)"
TOOLS_ROOT="${TOOLS_ROOT:-$(cd "$REPO_ROOT/.." && pwd)/.local-tools}"
DEV_TOOLS="${DEV_TOOLS:-$(cd "$REPO_ROOT/.." && pwd)/.dev-tools/env.sh}"

# The operator env provisions vendored git/python/gh; it lives outside the repo
# and may legitimately be absent on another host, so warn instead of failing.
if [ -r "$DEV_TOOLS" ]; then
  # shellcheck disable=SC1090
  . "$DEV_TOOLS"
else
  echo "worker-env: WARNING: no operator env at $DEV_TOOLS (git/python may be missing)" >&2
fi

export LC_ALL=C.UTF-8
export GIT_PAGER=cat PAGER=cat GH_PAGER=cat
export JAVA_HOME="${JAVA_HOME:-$TOOLS_ROOT/jdk25}"
export GHIDRA_HOME="${GHIDRA_HOME:-$TOOLS_ROOT/ghidra-12.2}"
export PATH="$JAVA_HOME/bin:$GHIDRA_HOME/support:$PATH"

# Only override TLS trust when a readable bundle actually exists (the operator
# env already points git/gh at its own bundle).
for CAND in "$TOOLS_ROOT/ca-certificates.crt" "$HOME/.ca/ca-bundle.crt" /etc/ssl/certs/ca-certificates.crt; do
  if [ -r "$CAND" ]; then
    export PIP_CA_BUNDLE="$CAND" REQUESTS_CA_BUNDLE="$CAND" SSL_CERT_FILE="$CAND" NODE_EXTRA_CA_CERTS="$CAND"
    break
  fi
done

command -v pi >/dev/null 2>&1 || export PATH="/app/node_modules/.bin:$PATH"

# Overnight campaign model pin (2026-10-30). The ralph-loop runner has no model
# frontmatter of its own: it inherits the model of the parent `pi -p "/ralph"`
# session (pi-ralph-loop src/index.ts: `modelPattern = ctx.model.provider/id`)
# and replays it into every RPC worker via set_model. Unpinned, that parent
# resolves pi's default provider — on this host that was the openai-codex
# subscription in /agent/auth.json, whose quota/auth expiry stopped the fleet
# twice (2026-10-28T22:18Z and 2026-10-30T01:20Z). Workers now run on the local
# Strata Qwen (flashnext/swift-1.5-iq3_xxs, the interactive default); Codex
# stays available for interactive sessions, it is only off the overnight path.
# Pi itself parses an optional ":<thinking>" suffix on --model; the model is
# reasoning-capable and the loop leaves thinking at pi's configured default,
# so no suffix is appended here.
export TS2_WORKER_MODEL="${TS2_WORKER_MODEL:-flashnext/swift-1.5-iq3_xxs}"

# No-root host build toolchain (cmake/ninja + zig wrappers; docs/LOCAL_VALIDATION.md).
# This repository's acceptance command is scripts/test-host.sh, which needs a C++
# compiler, cmake and a generator, so workers must see it too.
#
# APPENDED, never prepended: the toolchain directory is a venv bin and its
# `python3` would otherwise shadow the vendored interpreter that carries
# pefile/capstone/unicorn, and the analysis tests then fail to import.
HOST_TOOLCHAIN="${TS2_HOST_TOOLCHAIN:-$(cd "$REPO_ROOT/.." && pwd)/.local-tools/toolchain/bin}"
if [ -d "$HOST_TOOLCHAIN" ]; then
  PATH="$PATH:$HOST_TOOLCHAIN"
  # Exported so callers (scripts/campaign/campaign-verify.sh, the §6d recipe in
  # docs/AUTONOMOUS_SETUP.md) can name the compilers instead of guessing the path.
  export TS2_HOST_TOOLCHAIN="$HOST_TOOLCHAIN"
fi
export PATH

# The vendored interpreter is the one carrying pefile/capstone/unicorn, and both
# the campaign director and worker iterations address it as "$PY". Derive and
# export it here so a caller that sourced this file (or could not source it, see
# the director's POSIX fallback) still has a single canonical interpreter. Always
# quoted by callers: this repository's path contains spaces.
if [ -z "${PY:-}" ]; then
  for CAND_PY in "${PY_HOME:-}/bin/python3" "$TOOLS_ROOT/python/bin/python3"; do
    if [ -n "$CAND_PY" ] && [ -x "$CAND_PY" ]; then
      PY="$CAND_PY"
      break
    fi
  done
fi
[ -n "${PY:-}" ] && export PY

# Self-check: refuse to pretend the loop is ready when basic tooling is missing.
for TOOL in git python3 pi; do
  command -v "$TOOL" >/dev/null 2>&1 || echo "worker-env: WARNING: $TOOL not on PATH" >&2
done
command -v cc >/dev/null 2>&1 ||
  echo "worker-env: WARNING: no C compiler on PATH (scripts/test-host.sh will fail)" >&2
unset CAND TOOL
