#!/usr/bin/env bash

set -e

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}
BUILD_DIR=$(pwd)
CC=${CC:-cc}

echo "Source directory: ${SOURCE_DIR}"
echo "Build directory:  ${BUILD_DIR}"
echo ""

if [ "$(uname -s)" = "Darwin" ]; then
	echo "macOS version:"
	sw_vers | indent
fi

if [ -f "/etc/debian_version" ]; then
	echo "Debian version:"
	lsb_release -a | indent
fi

echo "Kernel version:"
uname -a 2>&1 | indent

echo "CMake version:"
cmake --version 2>&1 | indent
echo "Compiler version:"
$CC --version 2>&1 | indent
echo ""

echo "##############################################################################"
echo "## Configuring build environment"
echo "##############################################################################"

echo cmake ${SOURCE_DIR} -DENABLE_WERROR=ON ${CMAKE_OPTIONS}
cmake ${SOURCE_DIR} -DENABLE_WERROR=ON ${CMAKE_OPTIONS}

echo ""
echo "##############################################################################"
echo "## Building ntlmclient"
echo "##############################################################################"

cmake --build .
