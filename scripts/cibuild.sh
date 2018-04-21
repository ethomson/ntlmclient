#!/bin/sh

set -x

mkdir _build
cd _build

cmake ..
make -j2

./ntlm_tests
