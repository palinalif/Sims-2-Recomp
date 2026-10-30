#!/bin/sh
set -u
for TS2_TOOL in cmake ctest ninja c++ python3 java javac adb sdkmanager; do
    if command -v "$TS2_TOOL" >/dev/null 2>&1; then
        printf '%-12s %s\n' "$TS2_TOOL" "$(command -v "$TS2_TOOL")"
    else
        printf '%-12s missing from PATH\n' "$TS2_TOOL"
    fi
done
python3 -c 'import struct; print("Host pointer bits:", struct.calcsize("P")*8)'
printf 'Android SDK: %s\n' "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-unset}}"
printf 'JDK: %s\n' "${JAVA_HOME:-unset}"
