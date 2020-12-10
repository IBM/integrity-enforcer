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


if [ -z "$ISHIELD_SERVER_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_SERVER_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi



# Push integrity-shield-server image
echo -----------------------------
echo [1/3] Pushing integrity-shield-server image.
docker push ${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""


# Push integrity-shield-logging image
echo -----------------------------
echo [2/3] Pushing integrity-shield-logging image.
docker push ${ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""

# Push integrity-shield-operator image
echo -----------------------------
echo [3/3] Pushing integrity-shield-operator image.
docker push ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""

echo Completed.
