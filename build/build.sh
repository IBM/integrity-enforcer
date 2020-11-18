#!/bin/bash
set -e

echo "BUILD GOES HERE!"

echo "<repo>/<component>:<tag> : $1"

# Run our build target

make build-images
