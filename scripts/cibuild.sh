#!/bin/sh

set -x

if [ -n "$COVERITY" ]; then
	exec scripts/coverity.sh
fi

mkdir _build
cd _build

cmake .. $OPTIONS
make -j2

./ntlm_tests
