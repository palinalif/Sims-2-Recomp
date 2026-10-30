#!/bin/sh
set -eu
TS2_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TS2_ROOT"
cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --parallel
ctest --test-dir build/host --output-on-failure
python3 -m unittest discover -s tests -p 'test_*.py' -v
