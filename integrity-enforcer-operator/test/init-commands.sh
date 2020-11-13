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


BIN_DIR=$1
OS=$(uname)

echo 'setup test env'
if [ -f $BIN_DIR/kubectl ]; then
    echo "A file named kubectl already exists."
else
    echo 'installing kubectl ...'
    if [ $OS = "Linux" ]; then
        curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
        chmod +x ./kubectl
        mv ./kubectl $BIN_DIR/kubectl
    elif [ $OS = "Darwin" ]; then
        curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/darwin/amd64/kubectl"
        chmod +x ./kubectl
        mv ./kubectl $BIN_DIR/kubectl
        $BIN_DIR/kubectl version
    fi
fi

if [ -f $BIN_DIR/kind ]; then
    echo "A file named kind already exists."
else
    echo 'installing kind...'
    if [ $OS = "Linux" ]; then
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.9.0/kind-linux-amd64
        chmod +x ./kind
        mv ./kind  $BIN_DIR/kind
    elif [ $OS = "Darwin" ]; then
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.9.0/kind-darwin-amd64
        chmod +x ./kind
        mv ./kind $BIN_DIR/kind
        $BIN_DIR/kind version
    fi
fi


if [ -f $BIN_DIR/kustomize ]; then
    echo "A file named kustomize already exists."
else
    echo 'installing kustomize...'
    tmpDir=`mktemp -d`
    if [[ ! "$tmpDir" || ! -d "$tmpDir" ]]; then
        echo "Could not create temp dir."
        exit 1
    fi

    function cleanup {
        rm -rf "$tmpDir"
    }

    trap cleanup EXIT

    pushd $tmpDir >& /dev/null

    opsys=windows
    if [[ "$OSTYPE" == linux* ]]; then
        opsys=linux
    elif [[ "$OSTYPE" == darwin* ]]; then
        opsys=darwin
    fi
    
    version=v3.8.5

    curl -s https://api.github.com/repos/kubernetes-sigs/kustomize/releases |\
    grep browser_download |\
    grep $opsys |\
    cut -d '"' -f 4 |\
    grep /kustomize/$version.*amd64 |\
    sort | xargs curl -sLO

    if [ -e ./kustomize_v*_${opsys}_amd64.tar.gz ]; then
        tar xzf ./kustomize_v*_${opsys}_amd64.tar.gz
    else
        echo "Error: kustomize binary with the version ${version#v} does not exist!"
        exit 1
    fi

    cp ./kustomize $BIN_DIR

    $BIN_DIR/kustomize version

    popd >& /dev/null
fi
