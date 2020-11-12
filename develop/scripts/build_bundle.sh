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

if ! [ -x "$(command -v opm)" ]; then
    echo 'Error: opm is not installed.' >&2
    exit 1
fi


if [ -z "$IE_REPO_ROOT" ]; then
    echo "IE_REPO_ROOT is empty. Please set root directory for IE repository"
    exit 1
fi


cd $IE_REPO_ROOT/integrity-enforcer-operator


# Build ie-operator bundle
echo -----------------------------
echo [1/4] Building bundle
make bundle
make bundle-build BUNDLE_IMG=${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}

# Push ie-operator bundle
echo -----------------------------
echo [2/4] Pushing bundle
docker push ${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}

# Prepare ie-operator bundle index
echo -----------------------------
echo [3/4] Adding bundle to index


docker pull ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} | grep "Image is up to date" && pull_status="pulled" || pull_status="failed"

if [ "$pull_status" = "failed" ]; then
        sudo $GOPATH/bin/opm index add -c docker --generate --bundles ${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION} \
                      --tag ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --out-dockerfile tmp.Dockerfile
else
	echo "Succesfulling pulled previous index"
	sudo $GOPATH/bin/opm index add -c docker --generate --bundles ${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION} \
                      --from-index ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} \
                      --tag ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --out-dockerfile tmp.Dockerfile
fi

sudo rm tmp.Dockerfile

# Build ie-operator bundle index
echo -----------------------------
echo [3/4]  Building bundle index
sudo docker build -f index.Dockerfile -t ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

# Push ie-operator bundle index
echo -----------------------------
echo [3/4]  Pushing bundle index
sudo docker push ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}

echo "Completed building bundle and index"
