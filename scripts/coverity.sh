#!/bin/bash

if [ "$TRAVIS_BRANCH" != "master" -o "$TRAVIS_PULL_REQUEST" != "false" -o "$TRAVIS_REPO_SLUG" != "ethomson/ntlmclient" ]; then
	echo "Only analyzing the 'master' brach of the main repository."
	exit 0
fi

if [ -z "$COVERITY_TOKEN" ]; then
	echo "The COVERITY_TOKEN environment variable is not set"
	exit 1
fi

case $(uname -m) in
	i?86)         BITS=32 ;;
	amd64|x86_64) BITS=64 ;;
esac
SCAN_TOOL=https://scan.coverity.com/download/cxx/linux64
TOOL_BASE=$(pwd)/_coverity-scan

# Install coverity tools
if [ ! -d "$TOOL_BASE" ]; then
	echo "Downloading coverity..."
	mkdir -p "$TOOL_BASE"
	pushd "$TOOL_BASE"
	wget -O coverity_tool.tgz $SCAN_TOOL \
		--post-data "project=ntlmclient&token=$COVERITY_TOKEN"
	tar xzf coverity_tool.tgz
	popd
	TOOL_DIR=$(find "$TOOL_BASE" -type d -name 'cov-analysis*')
	ln -s "$TOOL_DIR" "$TOOL_BASE"/cov-analysis
fi

COV_BUILD="$TOOL_BASE/cov-analysis/bin/cov-build"

# Configure and build
rm -rf _build
mkdir _build
cd _build
cmake .. -DUNICODE=builtin
COVERITY_UNSUPPORTED=1 \
	$COV_BUILD --dir cov-int \
	cmake --build .

# Upload results
tar czf ntlmclient.tgz cov-int
SHA=$(git rev-parse --short HEAD)

HTML="$(curl \
	--silent \
	--write-out "\n%{http_code}" \
	--form token="$COVERITY_TOKEN" \
	--form email=ethomson@edwardthomson.com \
	--form file=@ntlmclient.tgz \
	--form version="$SHA" \
	--form description="Travis build" \
	https://scan.coverity.com/builds?project=ntlmclient)"

BODY="$(echo "$HTML" | head -n-1)"
STATUS_CODE="$(echo "$HTML" | tail -n1)"

if [ "${STATUS_CODE}" != "200" -a "${STATUS_CODE}" != "201" ]; then
	echo "Received error code ${STATUS_CODE} from Coverity" 1>&2
	echo "${BODY}" 1>&2
	exit 1
fi

echo "${BODY}"
