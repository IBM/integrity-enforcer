#!/bin/bash
set -e

echo "BUILD GOES HERE!"

echo "<repo>/<component>:<tag> : $1"

echo "Building integrity enforcer starting : $(date)"

# Run our build target
make build-images

# Tag images with COMPONENT_TAG_EXTENSION
docker tag ${IE_ENFORCER_IMAGE_NAME_AND_VERSION} ${REGISTRY}/${IE_IMAGE}:${VERSION}${COMPONENT_TAG_EXTENSION}
docker tag ${IE_LOGGING_IMAGE_NAME_AND_VERSION} ${REGISTRY}/${IE_LOGGING}:${VERSION}${COMPONENT_TAG_EXTENSION}
docker tag ${IE_OPERATOR_IMAGE_NAME_AND_VERSION} ${REGISTRY}/${IE_OPERATOR}:${VERSION}${COMPONENT_TAG_EXTENSION}

export COMPONENT_VERSION=${VERSION}
export COMPONENT_DOCKER_REPO=${REGISTRY}

# Push ${IE_IMAGE}
export COMPONENT_NAME=${IE_IMAGE}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi

# Push ${IE_LOGGING}
export COMPONENT_NAME=${IE_LOGGING}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi

# Push ${IE_OPERATOR}
export COMPONENT_NAME=${IE_OPERATOR}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi

echo "Building integrity enforcer completed : $(date)"

echo "Building integrity enforcer bundle starting : $(date)"

${IE_REPO_ROOT}/build/build_bundle.sh

echo "Building integrity enforcer bundle completed : $(date)"
