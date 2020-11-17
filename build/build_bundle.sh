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

export ../ie-build.conf

if ! [ -x "$(command -v docker)" ]; then
    echo 'Error: docker is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v opm)" ]; then
    echo 'Error: opm is not installed.' >&2
    exit 1
fi


if [ -z "$ENFORCER_OP_DIR" ]; then
    echo "ENFORCER_OP_DIR is empty. Please set env."
    exit 1
fi


cd $ENFORCER_OP_DIR

echo "Current directory: $(pwd)"

export COMPONENT_VERSION=${VERSION}
export COMPONENT_DOCKER_REPO=${REGISTRY}

# Build ie-operator bundle
echo -----------------------------
echo [1/4] Building bundle
make bundle IMG=${IE_OPERATOR_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} VERSION=${VERSION}


csvfile="bundle/manifests/integrity-enforcer-operator.clusterserviceversion.yaml"
cat $csvfile | yq r - -j >  tmp.json

change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "OwnNamespace").supported=true)') && echo "$change" >  tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "SingleNamespace").supported=true)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "MultiNamespace").supported=false)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "AllNamespaces").supported=false)') && echo "$change" > tmp.json

cat tmp.json  | yq r - -P > $csvfile
rm tmp.json

make bundle-build BUNDLE_IMG=${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}

# Push ie-operator bundle
echo -----------------------------
echo [2/4] Pushing bundle
#docker push ${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
export COMPONENT_NAME=${IE_BUNDLE}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi


# Prepare ie-operator bundle index
echo -----------------------------
echo [3/4] Adding bundle to index

docker pull ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION}${COMPONENT_TAG_EXTENSION} | grep "Image is up to date" && pull_status="pulled" || pull_status="failed"

if [ "$pull_status" = "failed" ]; then
        sudo /usr/local/bin/opm index add -c docker --generate --bundles ${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} \
                      --tag ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} --out-dockerfile tmp.Dockerfile
else
	echo "Succesfulling pulled previous index"
	sudo /usr/local/bin/opm index add -c docker --generate --bundles ${IE_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} \
                      --from-index ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION}${COMPONENT_TAG_EXTENSION} \
                      --tag ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} --out-dockerfile tmp.Dockerfile
fi

rm -f tmp.Dockerfile

# Build ie-operator bundle index
echo -----------------------------
echo [3/4]  Building bundle index
docker build -f index.Dockerfile -t ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

# Push ie-operator bundle index
echo -----------------------------
echo [3/4]  Pushing bundle index

#docker push ${IE_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
export COMPONENT_NAME=${IE_INDEX}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
if [ `go env GOOS` == "linux" ]; then
    make component/push
fi

echo "Completed building bundle and index"
