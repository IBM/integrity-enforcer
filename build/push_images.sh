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


if [ -z "$ISHIELD_API_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_API_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi



# Push integrity-shield-api image
echo -----------------------------
echo [1/4] Pushing integrity-shield-api image.
docker push ${ISHIELD_API_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""


# Push integrity-shield-observer image
echo -----------------------------
echo [2/4] Pushing integrity-shield-observer image.
docker push ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""


# Push integrity-shield-admission-controller image
echo -----------------------------
echo [3/4] Pushing integrity-shield-admission-controller image.
docker push ${ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""


# Push integrity-shield-operator image
echo -----------------------------
echo [4/4] Pushing integrity-shield-operator image.
docker push ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""

echo Completed.
