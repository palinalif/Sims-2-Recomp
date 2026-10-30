#!/bin/sh
# Upstream difftest omits libm on Linux. Keep the workaround outside upstream.
exec cc "$@" -lm
