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


SS_BASEDIR=${IE_REPO_ROOT}/develop/signservice/signservice/
SS_IMAGE_REMOTE=integrityenforcer/ie-signservice:0.0.1
SS_IMAGE_LOCAL=signservice:dev

SS_OPERATOR_BASEDIR=${IE_REPO_ROOT}/develop/signservice/signservice-operator/
SS_OPERATOR_IMAGE_NAME=signservice-operator
SS_OPERATOR_IMAGE_REPO=integrityenforcer
SS_OPERATOR_IMAGE_TAG_LOCAL=dev
SS_OPERATOR_IMAGE_TAG=dev
SS_OPERATOR_IMAGE_LOCAL=${SS_OPERATOR_IMAGE_NAME}:${SS_OPERATOR_IMAGE_TAG_LOCAL}
SS_OPERATOR_IMAGE_REMOTE=${SS_OPERATOR_IMAGE_REPO}/${SS_OPERATOR_IMAGE_NAME}:${SS_OPERATOR_IMAGE_TAG}


# Push signservice image
echo -----------------------------
echo [1/2] Pushing signservice image.
docker tag ${SS_IMAGE_LOCAL} ${SS_IMAGE_REMOTE}
docker push ${SS_IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""


# Push signservice-operator image
echo -----------------------------
echo [2/2] Pushing signservice-operator image.
docker tag ${SS_OPERATOR_IMAGE_LOCAL} ${SS_OPERATOR_IMAGE_REMOTE}
docker push ${SS_OPERATOR_IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""

echo Completed.
