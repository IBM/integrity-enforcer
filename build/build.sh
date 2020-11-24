#!/bin/bash
set -e

echo "BUILD GOES HERE!"

echo "<repo>/<component>:<tag> : $1"

# Run our build target

make build-images

if [ ! -z "$UPSTREAM_ENV" ] || [ "$UPSTREAM_ENV" = false ]

	echo "Building integrity verifier bundle starting : $(date)"

	${IV_REPO_ROOT}/build/build_bundle.sh

	echo "Building integrity verifier bundle completed : $(date)"
fi
