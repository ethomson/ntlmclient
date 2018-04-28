#!/bin/sh

set -x

mkdir _build
cd _build

cmake .. $OPTIONS
make -j2

./ntlm_tests
