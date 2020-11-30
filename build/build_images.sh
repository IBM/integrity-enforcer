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

if [ -z "$IV_REPO_ROOT" ]; then
    echo "IV_REPO_ROOT is empty. Please set root directory for IV repository"
    exit 1
fi

if [ -z "$IV_SERVER_IMAGE_NAME_AND_VERSION" ]; then
    echo "IV_SERVER_IMAGE_NAME_AND_VERSION is empty. Please set iv build env settings."
    exit 1
fi

if [ -z "$IV_LOGGING_IMAGE_NAME_AND_VERSION" ]; then
    echo "IV_LOGGING_IMAGE_NAME_AND_VERSION is empty. Please set iv build env settings."
    exit 1
fi

if [ -z "$IV_OPERATOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "IV_OPERATOR_IMAGE_NAME_AND_VERSION is empty. Please set iv build env settings."
    exit 1
fi

if [ -z "$IV_OPERATOR" ]; then
    echo "IV_OPERATOR is empty. Please set iv build env settings."
    exit 1
fi


SERVICE_NAME=iv-server


BASEDIR=./deployment
DOCKERFILE=./image/Dockerfile
LOGG_BASEDIR=${IV_REPO_ROOT}/logging/
OPERATOR_BASEDIR=${IV_REPO_ROOT}/integrity-verifier-operator/

# Build iv-server image
echo -----------------------------
echo [1/3] Building iv-server image.
cd ${IV_REPO_ROOT}/verifier
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
    docker build -f ${DOCKERFILE} -t ${IV_SERVER_IMAGE_NAME_AND_VERSION} image/ --no-cache
else
    docker build -f ${DOCKERFILE} -t ${IV_SERVER_IMAGE_NAME_AND_VERSION} image/
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build iv-logging image
echo -----------------------------
echo [2/3] Building iv-logging image.
cd ${LOGG_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
if [ "$NO_CACHE" = true ] ; then
     docker build -t ${IV_LOGGING_IMAGE_NAME_AND_VERSION} ${LOGG_BASEDIR} --no-cache
else
     docker build -t ${IV_LOGGING_IMAGE_NAME_AND_VERSION} ${LOGG_BASEDIR}
fi

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo done.
echo -----------------------------
echo ""

# Build integrity-verifier-operator image
echo -----------------------------
echo [3/3] Building integrity-verifier-operator image.
cd ${OPERATOR_BASEDIR}
exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "failed"
    exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_output/bin/${IV_OPERATOR} main.go

if [ "$NO_CACHE" = true ] ; then
    docker build . -t ${IV_OPERATOR_IMAGE_NAME_AND_VERSION} --no-cache
else
    docker build . -t ${IV_OPERATOR_IMAGE_NAME_AND_VERSION}
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
