#!/bin/bash
set -e

echo "BUILD GOES HERE!"

echo "<repo>/<component>:<tag> : $1"

# Run our build target

make build-images

if [ ! -z "$UPSTREAM_ENV" ] || [ "$UPSTREAM_ENV" = false ]; then

        echo "Pushing images"

        ${IE_REPO_ROOT}/build/push_images_ocm.sh

        echo "Building integrity enforcer bundle starting : $(date)"

        ${IE_REPO_ROOT}/build/build_bundle_ocm.sh

        echo "Building integrity enforcer bundle completed : $(date)"
fi
