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


if [ -z "$SHIELD_OP_DIR" ]; then
    echo "SHIELD_OP_DIR is empty. Please set env."
    exit 1
fi


cd $SHIELD_OP_DIR

echo "Current directory: $(pwd)"

export COMPONENT_VERSION=${VERSION}
export COMPONENT_DOCKER_REPO=${REGISTRY}

# Build ishield-operator bundle
echo -----------------------------
echo [1/4] Building bundle
make bundle IMG=${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} VERSION=${VERSION}

tmpcrd="${SHIELD_OP_DIR}/config/crd/bases/apis.integrityshield.io_integrityshieldren.yaml"
if [ -f $tmpcrd ]; then
  rm $tmpcrd
fi

csvfile="bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml"
cat $csvfile | yq r - -j >  tmp.json

change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "OwnNamespace").supported=true)') && echo "$change" >  tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "SingleNamespace").supported=true)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "MultiNamespace").supported=false)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "AllNamespaces").supported=false)') && echo "$change" > tmp.json

cat tmp.json  | yq r - -P > $csvfile
rm tmp.json

docker pull ${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} | grep "Image is up to date" && pull_status="pulled" || pull_status="failed"
if [ "$pull_status" = "failed" ]; then
  sed -i '/ replaces: /d' ${SHIELD_OP_DIR}/bundle/manifests/*.clusterserviceversion.yaml
fi

make bundle-build BUNDLE_IMG=${ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}

# Push ishield-operator bundle
echo -----------------------------
echo [2/4] Pushing bundle
#docker push ${ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
export COMPONENT_NAME=${ISHIELD_BUNDLE}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
#if [ `go env GOOS` == "linux" ]; then
#    make component/push
#fi

#echo DOCKER_REGISTRY: ${DOCKER_REGISTRY}
echo DOCKER_USER: ${DOCKER_USER}
echo DOCKER_PASS: ${DOCKER_PASS}
docker login quay.io -u ${DOCKER_USER} -p ${DOCKER_PASS}
make docker-push IMG=$DOCKER_IMAGE_AND_TAG

# Prepare ishield-operator bundle index
echo -----------------------------
echo [3/4] Adding bundle to index

if [ "$pull_status" = "failed" ]; then
        sudo /usr/local/bin/opm index add -c docker --generate --bundles ${ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} \
                      --tag ${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} --out-dockerfile tmp.Dockerfile
else
	echo "Succesfulling pulled previous index"
	sudo /usr/local/bin/opm index add -c docker --generate --bundles ${ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} \
                      --from-index ${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION}${COMPONENT_TAG_EXTENSION} \
                      --tag ${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} --out-dockerfile tmp.Dockerfile
fi

rm -f tmp.Dockerfile

# Build ishield-operator bundle index
echo -----------------------------
echo [3/4]  Building bundle index
docker build -f index.Dockerfile -t ${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION} --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

# Push ishield-operator bundle index
echo -----------------------------
echo [3/4]  Pushing bundle index

#docker push ${ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}${COMPONENT_TAG_EXTENSION}
export COMPONENT_NAME=${ISHIELD_INDEX}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
#if [ `go env GOOS` == "linux" ]; then
#    make component/push
#fi

make docker-push IMG=$DOCKER_IMAGE_AND_TAG

echo "Completed building bundle and index"
