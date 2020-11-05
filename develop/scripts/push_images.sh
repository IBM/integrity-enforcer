#!/bin/bash
#
# Copyright 2020 IBM Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


if ! [ -x "$(command -v docker)" ]; then
    echo 'Error: docker is not installed.' >&2
    exit 1
fi
if [ -z "$IE_REPO_ROOT" ]; then
   echo "IE_REPO_ROOT is empty. Please set root directory for IE repository"
   exit 1
fi

SERVICE_NAME=ie-server
IMAGE_LOCAL=integrityenforcer/ie-server:0.0.4dev
IMAGE_REMOTE=${IMAGE_LOCAL}
# IMAGE_REMOTE=<CUSTOM_IMAGE_NAME>
BASEDIR=./deployment
DOCKERFILE=./image/Dockerfile

LOGG_BASEDIR=${IE_REPO_ROOT}/logging/
LOGG_IMAGE_LOCAL=integrityenforcer/ie-logging:0.0.4dev
LOGG_IMAGE_REMOTE=${LOGG_IMAGE_LOCAL}
# LOGG_IMAGE_REMOTE=<CUSTOM_IMAGE_NAME>

OPERATOR_BASEDIR=${IE_REPO_ROOT}/integrity-enforcer-operator/
OPERATOR_IMAGE_NAME=integrity-enforcer-operator
OPERATOR_IMAGE_LOCAL=integrityenforcer/${OPERATOR_IMAGE_NAME}:0.0.4dev
OPERATOR_IMAGE_REMOTE=${OPERATOR_IMAGE_LOCAL}
# OPERATOR_IMAGE_REMOTE=<CUSTOM_IMAGE_NAME>


# Push ie-server image
echo -----------------------------
echo [1/3] Pushing ie-server image.
docker tag ${IMAGE_LOCAL} ${IMAGE_REMOTE}
docker push ${IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""


# Push ie-logging image
echo -----------------------------
echo [2/3] Pushing ie-logging image.
docker tag ${LOGG_IMAGE_LOCAL} ${LOGG_IMAGE_REMOTE}
docker push ${LOGG_IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""

# Push integrity-enforcer-operator image
echo -----------------------------
echo [3/3] Pushing integrity-enforcer-operator image.
docker tag ${OPERATOR_IMAGE_LOCAL} ${OPERATOR_IMAGE_REMOTE}
docker push ${OPERATOR_IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""

echo Completed.
