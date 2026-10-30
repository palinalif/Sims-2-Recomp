#!/bin/bash
# Provision a host-side AArch64 user-mode emulator (qemu-aarch64) and prove that
# this container can execute real AArch64 code, without root and without apt.
#
# Why: the Phase 1 goal is ARM64 gameplay evidence, but the container has no
# Android SDK, no ADB, no device and no /dev/kvm. Executing the port's own
# AArch64 binaries under qemu-aarch64 is the strongest AArch64 evidence available
# locally. It is NOT Android evidence and does not satisfy Phase 1 acceptance.
#
# Source of truth (pinned): Alpine v3.20 community/x86_64 qemu-aarch64 9.0.2-r0.
# That package declares no dependencies at all - Alpine ships the user-mode
# emulator statically linked - so extraction alone is enough.
#
# Usage:
#   scripts/campaign/provision-qemu-aarch64.sh            # install if missing
#   scripts/campaign/provision-qemu-aarch64.sh --verify   # also run an AArch64 binary
#
# Everything stays in the ignored host toolchain tree (../.local-tools).
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PARENT="$(dirname "$REPO")"
TOOLS="${TS2_HOST_TOOLS:-$PARENT/.local-tools}"
CACHE="$TOOLS/apk-cache"
PREFIX="$TOOLS/qemu-aarch64-root"
TC="${TS2_HOST_TOOLCHAIN:-$TOOLS/toolchain/bin}"
DL="$REPO/.tools/campaign/dl.mjs"

VERSION=9.0.2-r0
NAME="qemu-aarch64-$VERSION"
URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/community/x86_64/$NAME.apk"
SHA256=3fd600a854bf43136c0e8a27969b3ab4f340e3570c2a946d0ef6324dc3ed2db9
SIZE=1882568

[ -f "$REPO/scripts/campaign/worker-env.sh" ] && . "$REPO/scripts/campaign/worker-env.sh" >/dev/null 2>&1 || true
command -v node >/dev/null || { echo "node is required to download (no curl/wget here)" >&2; exit 3; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 3; }

APK="$CACHE/$NAME.apk"
mkdir -p "$CACHE" "$PREFIX"

verify_sum() {
  printf '%s  %s\n' "$SHA256" "$APK" | sha256sum -c - >/dev/null 2>&1
}

if ! verify_sum; then
  echo "downloading $URL"
  rm -f "$APK"
  node "$DL" "$URL" "$APK" >/dev/null
  verify_sum || { echo "FATAL: apk sha256 mismatch (expected $SHA256)" >&2; exit 4; }
fi
[ "$(wc -c < "$APK")" = "$SIZE" ] || { echo "FATAL: apk size mismatch" >&2; exit 4; }

QEMU="$PREFIX/usr/bin/qemu-aarch64"
if [ ! -x "$QEMU" ]; then
  echo "extracting $NAME into $PREFIX"
  tar -xzf "$APK" -C "$PREFIX"
  chmod +x "$QEMU"
fi
[ -x "$QEMU" ] || { echo "FATAL: $QEMU missing after extract" >&2; exit 5; }
echo "qemu: $("$QEMU" --version | head -1)"

if [ "${1:-}" = "--verify" ]; then
  cat > /tmp/ts2-arm64-probe.c <<'C'
#include <stdio.h>
int main(void) { puts("arm64-ok"); return 7; }
C
  "$TC/zig-cc" -target aarch64-linux-musl -static -O1 -o /tmp/ts2-arm64-probe /tmp/ts2-arm64-probe.c
  header=$(od -An -tx1 -N5 /tmp/ts2-arm64-probe | tr -d ' \n')
  [ "$header" = "7f454c4602" ] || { echo "FATAL: not an ELF64 binary" >&2; exit 6; }
  set +e
  out=$("$QEMU" /tmp/ts2-arm64-probe 2>&1)
  rc=$?
  set -e
  echo "guest stdout: $out"
  echo "guest exit: $rc"
  [ "$out" = "arm64-ok" ] && [ "$rc" = "7" ] || { echo "FATAL: AArch64 execution did not behave as expected" >&2; exit 7; }
  echo "RESULT: AArch64 execution verified (qemu-aarch64 + zig aarch64-linux-musl static)"
fi

echo "prefix: $PREFIX"
echo "run: $QEMU <aarch64-elf> [args]"
