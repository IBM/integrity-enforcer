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
echo [1/4] Building ishield-operator image.
cd ${SHIELD_OP_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/integrity-shield-operator main.go
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build -t ${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} . --no-cache
    docker push ${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
else
    docker build -t ${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} .
    docker push ${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
fi

# Build ishield-ac-server image
echo -----------------------------
echo [2/4] Building ishield-ac-server image.
cd ${SHIELD_AC_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -o build/_bin/k8s-manifest-sigstore ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build -t ${TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION} . --no-cache
    docker push ${TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}
else
    docker build -t ${TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION} .
    docker push ${TEST_ISHIELD_ADMISSION_CONTROLLER_IMAGE_NAME_AND_VERSION}
fi

# Build ishield-api-server image
echo -----------------------------
echo [3/4] Building ishield-api-server image.
cd ${SHIELD_SERVER_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-api ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build -t ${TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION} . --no-cache
    docker push ${TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION}
else
    docker build -t ${TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION} .
    docker push ${TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION}
fi

# Build ishield-observer image
echo -----------------------------
echo [4/4] Building ishield-observer image.
cd ${SHIELD_OBSERVER_DIR}
go mod tidy
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-observer ./
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
    docker build -t ${TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} . --no-cache
    docker push ${TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION}
else
    docker build -t ${TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} .
    docker push ${TEST_ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION}
fi