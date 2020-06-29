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
IMAGE_REMOTE=integrityenforcer/ie-server:latest
IMAGE_LOCAL=ie-server:local
BASEDIR=./deployment
DOCKERFILE=./image/Dockerfile

LOGG_BASEDIR=${REPO_ROOT}/logging/
LOGG_IMAGE_REMOTE=integrityenforcer/ie-logging:latest
LOGG_IMAGE_LOCAL=ie-logging:local

SS_BASEDIR=${REPO_ROOT}/develop/signservice/signservice/
SS_IMAGE_REMOTE=integrityenforcer/ie-signservice:latest
SS_IMAGE_LOCAL=signservice:dev

OPERATOR_BASEDIR=${REPO_ROOT}/operator/
OPERATOR_IMAGE_NAME=integrity-enforcer-operator
OPERATOR_IMAGE_REPO=integrityenforcer
CSV_VERSION_LOCAL=0.0.1
CSV_VERSION=0.0.1
OPERATOR_IMAGE_LOCAL=${OPERATOR_IMAGE_NAME}:${CSV_VERSION_LOCAL}
OPERATOR_IMAGE_REMOTE=${OPERATOR_IMAGE_REPO}/${OPERATOR_IMAGE_NAME}:${CSV_VERSION}

SS_OPERATOR_BASEDIR=${REPO_ROOT}/develop/signservice/signservice-operator/
SS_OPERATOR_IMAGE_NAME=signservice-operator
SS_OPERATOR_IMAGE_REPO=integrityenforcer
SS_OPERATOR_IMAGE_TAG_LOCAL=dev
SS_OPERATOR_IMAGE_TAG=dev
SS_OPERATOR_IMAGE_LOCAL=${SS_OPERATOR_IMAGE_NAME}:${SS_OPERATOR_IMAGE_TAG_LOCAL}
SS_OPERATOR_IMAGE_REMOTE=${SS_OPERATOR_IMAGE_REPO}/${SS_OPERATOR_IMAGE_NAME}:${SS_OPERATOR_IMAGE_TAG}

# Build ie-server image
echo -----------------------------
echo [1/5] Building ie-server image.
cd ${REPO_ROOT}/enforcer
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

# Build signservice image
echo -----------------------------
echo [2/5] Building signservice image.
cd ${SS_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ./build/_output/signservice ./cmd/signservice
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
docker build -t ${SS_IMAGE_LOCAL} ${SS_BASEDIR}
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
echo [3/5] Building ie-logging image.
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
echo [4/5] Building integrity-enforcer-operator image.
cd ${OPERATOR_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
# CGO_ENABLED=0 GOOS=linux build -ldflags="-s -w" -o ./build/_output/bin/${OPERATOR_IMAGE_NAME} ./cmd/manager
# docker build -f build/Dockerfile -t ${OPERATOR_IMAGE_LOCAL} .
operator-sdk build ${OPERATOR_IMAGE_LOCAL}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build signservice-operator image
echo -----------------------------
echo [5/5] Building signservice-operator image.
cd ${SS_OPERATOR_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
operator-sdk build ${SS_OPERATOR_IMAGE_LOCAL}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

echo Completed.
