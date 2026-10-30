#!/bin/sh
set -eu
TS2_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TS2_JAVA=${JAVA_HOME:+$JAVA_HOME/bin/}
mkdir -p "$TS2_ROOT/build/java-stream"
"${TS2_JAVA}javac" -d "$TS2_ROOT/build/java-stream" \
  "$TS2_ROOT/android/app/src/main/java/org/ts2native/diagnostic/BoundedInput.java" \
  "$TS2_ROOT/tests/java/org/ts2native/diagnostic/BoundedInputTest.java"
"${TS2_JAVA}java" -cp "$TS2_ROOT/build/java-stream" org.ts2native.diagnostic.BoundedInputTest
