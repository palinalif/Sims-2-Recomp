#!/usr/bin/env bash
# Run only Linux ELF64 little-endian AArch64 binaries; NOT an Android runner.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TOOLS="${TS2_HOST_TOOLS:-$(dirname "$REPO")/.local-tools}"
QEMU="${TS2_QEMU_AARCH64:-$TOOLS/qemu-aarch64-root/usr/bin/qemu-aarch64}"
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <static-linux-aarch64-elf> [args...]" >&2
  exit 64
fi
if [ ! -f "$1" ]; then
  echo "ERROR: AArch64 executable not found: $1" >&2
  exit 66
fi
# ELF magic/class/data/version, then e_machine=183. No host-binary fallback.
header=$(od -An -tx1 -N7 -- "$1" | tr -d ' \n')
machine=$(od -An -tx1 -j18 -N2 -- "$1" | tr -d ' \n')
if [ "$header" != 7f454c46020101 ] || [ "$machine" != b700 ]; then
  echo "ERROR: expected ELF64 little-endian AArch64 executable" >&2
  exit 65
fi
if [ ! -x "$QEMU" ]; then
  echo "BLOCKED: qemu-aarch64 missing; run scripts/campaign/provision-qemu-aarch64.sh --verify" >&2
  exit 78
fi
# Per-suite bound also applies when invoked directly rather than through CTest.
exec timeout --kill-after=5s 60s "$QEMU" "$@"
