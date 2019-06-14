#!/usr/bin/env bash

set -e

if [ -n "$SKIP_TESTS" ]; then
	exit 0
fi

ctest -V
