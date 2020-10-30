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

if ! [ -x "$(command -v go)" ]; then
    echo 'Error: go is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v operator-sdk)" ]; then
    echo 'Error: operator-sdk is not installed.' >&2
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


# Build ie-server image
echo -----------------------------
echo [1/3] Building ie-server image.
cd ${IE_REPO_ROOT}/enforcer
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o image/${SERVICE_NAME} ./cmd/${SERVICE_NAME}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
docker build -f ${DOCKERFILE} -t ${IMAGE_LOCAL} image/
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build ie-logging image
echo -----------------------------
echo [2/3] Building ie-logging image.
cd ${LOGG_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
docker build -t ${LOGG_IMAGE_LOCAL} ${LOGG_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build integrity-enforcer-operator image
echo -----------------------------
echo [3/3] Building integrity-enforcer-operator image.
cd ${OPERATOR_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/${OPERATOR_IMAGE_NAME} main.go
docker build . -t ${OPERATOR_IMAGE_LOCAL}
# operator-sdk build ${OPERATOR_IMAGE_LOCAL}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

echo Completed.
