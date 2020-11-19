#!/bin/bash
set -e

echo "BUILD GOES HERE!"

echo "<repo>/<component>:<tag> : $1"

# Run our build target

make build-images

if [ ! -z "$IBM_ENV" ] || [ "$IBM_ENV" = false ]

	echo "Building integrity enforcer bundle starting : $(date)"

	${IE_REPO_ROOT}/build/build_bundle.sh

	echo "Building integrity enforcer bundle completed : $(date)"
fi
