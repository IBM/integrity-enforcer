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

CMDNAME=`basename $0`
if [ $# -ne 1 ]; then
  echo "Usage: $CMDNAME <no-cache>" 1>&2
  exit 1
fi

NO_CACHE=$1

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

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
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

if [ -z "$ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_INSPECTOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_INSPECTOR_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION is empty. Please set IShield build env settings."
    exit 1
fi

if [ -z "$ISHIELD_OPERATOR" ]; then
    echo "ISHIELD_OPERATOR is empty. Please set IShield build env settings."
    exit 1
fi


SERVICE_NAME=ishield-server


BASEDIR=./deployment
DOCKERFILE=./image/Dockerfile
LOGG_BASEDIR=${ISHIELD_REPO_ROOT}/logging/
OBSV_BASEDIR=${ISHIELD_REPO_ROOT}/observer/
INSP_BASEDIR=${ISHIELD_REPO_ROOT}/inspector/
OPERATOR_BASEDIR=${ISHIELD_REPO_ROOT}/integrity-shield-operator/

# Build ishield-server image
echo -----------------------------
echo [1/4] Building ishield-server image.
cd ${ISHIELD_REPO_ROOT}/shield
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

if [ "$NO_CACHE" = true ] ; then
    docker build -f ${DOCKERFILE} -t ${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION} image/ --no-cache
else
    docker build -f ${DOCKERFILE} -t ${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION} image/
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build ishield-logging image
echo -----------------------------
echo [2/4] Building ishield-logging image.
cd ${LOGG_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
     docker build -t ${ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION} ${LOGG_BASEDIR} --no-cache
else
     docker build -t ${ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION} ${LOGG_BASEDIR}
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build ishield-observer image
echo -----------------------------
echo [3/4] Building ishield-observer image.
cd ${OBSV_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/${ISHIELD_OBSERVER} main.go

if [ "$NO_CACHE" = true ] ; then
     docker build -t ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} ${OBSV_BASEDIR} --no-cache
else
     docker build -t ${ISHIELD_OBSERVER_IMAGE_NAME_AND_VERSION} ${OBSV_BASEDIR}
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build ishield-inspector image
echo -----------------------------
echo [3/4] Building ishield-inspector image.
cd ${INSP_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/${ISHIELD_INSPECTOR} main.go

if [ "$NO_CACHE" = true ] ; then
     docker build -t ${ISHIELD_INSPECTOR_IMAGE_NAME_AND_VERSION} ${INSP_BASEDIR} --no-cache
else
     docker build -t ${ISHIELD_INSPECTOR_IMAGE_NAME_AND_VERSION} ${INSP_BASEDIR}
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build integrity-shield-operator image
echo -----------------------------
echo [4/4] Building integrity-shield-operator image.
cd ${OPERATOR_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/${ISHIELD_OPERATOR} main.go

if [ "$NO_CACHE" = true ] ; then
    docker build . -t ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} --no-cache
else
    docker build . -t ${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

echo Completed.
