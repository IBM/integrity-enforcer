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

NO_CACHE=false

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty."
    exit 1
fi


# Build ishield-operator image
echo -----------------------------
echo [1/4] Pushing ishield-operator image to remote repository.
docker tag ${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
docker push ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}

# Build ishield-ac-server image
echo -----------------------------
echo [2/4] Pushing ishield-ac-server image to remote repository.
docker tag ${TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}  ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}
docker push ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}

# Build ishield-api-server image
echo -----------------------------
echo [3/4] Pushing ishield-api-server image to remote repository.
docker tag ${TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION} ${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION}
docker push ${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION}

# Build ishield-observer image
echo -----------------------------
echo [4/4] Pushing ishield-observer image to remote repository.
docker tag ${TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION}
docker push ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION}
