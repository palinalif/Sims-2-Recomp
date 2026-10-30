#!/bin/sh
set -eu
TS2_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if ! command -v javac >/dev/null 2>&1 && [ ! -x "${JAVA_HOME:-/nonexistent}/bin/javac" ]; then
    echo 'Install a full JDK 17+ and set JAVA_HOME (a JRE is insufficient).' >&2
    exit 1
fi
if [ -z "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ] && [ ! -f "$TS2_ROOT/android/local.properties" ]; then
    echo 'Set ANDROID_HOME or android/local.properties to your Android SDK.' >&2
    exit 1
fi
cd "$TS2_ROOT/android"
exec ./gradlew assembleDebug lintDebug --console=plain "$@"
