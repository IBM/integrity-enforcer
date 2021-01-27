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


if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

cd $ISHIELD_REPO_ROOT/integrity-shield-operator


# Build ishield-operator bundle
echo -----------------------------
echo [1/4] Building bundle
make bundle IMG=${TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} VERSION=${VERSION}

# Temporary workarround for dealing with CRD generation issue

tmpcrd="${SHIELD_OP_DIR}/config/crd/bases/apis.integrityshield.io_integrityshieldren.yaml"
targetcrd="${SHIELD_OP_DIR}/config/crd/bases/apis.integrityshield.io_integrityshields.yaml"

if [ -f $tmpcrd ]; then
  sed -i 's/integrityshieldren/integrityshields/g' $tmpcrd
  mv $tmpcrd $targetcrd
fi

csvfile="bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml"
cat $csvfile | yq r - -j >  tmp.json

change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "OwnNamespace").supported=true)') && echo "$change" >  tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "SingleNamespace").supported=true)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "MultiNamespace").supported=false)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "AllNamespaces").supported=false)') && echo "$change" > tmp.json

cat tmp.json  | yq r - -P > $csvfile
rm tmp.json

docker pull ${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} | grep "Image is up to date" && pull_status="pulled" || pull_status="failed"

if [ "$pull_status" = "failed" ]; then
   sed -i '/ replaces: /d' ${SHIELD_OP_DIR}/bundle/manifests/*.clusterserviceversion.yaml
fi

make bundle-build BUNDLE_IMG=${TEST_ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}

# Push ishield-operator bundle
echo -----------------------------
echo [2/4] Pushing bundle
docker push ${TEST_ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}

# Prepare ishield-operator bundle index
echo -----------------------------
echo [3/4] Adding bundle to index



if [ "$pull_status" = "failed" ]; then
        sudo /usr/local/bin/opm index add -c docker --generate --bundles ${TEST_ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION} \
                      --tag ${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --out-dockerfile tmp.Dockerfile
else
	echo "Succesfulling pulled previous index"
	sudo /usr/local/bin/opm index add -c docker --generate --bundles ${TEST_ISHIELD_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION} \
                      --from-index ${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} \
                      --tag ${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --out-dockerfile tmp.Dockerfile
fi

rm -f tmp.Dockerfile

# Build ishield-operator bundle index
echo -----------------------------
echo [3/4]  Building bundle index
docker build -f index.Dockerfile -t ${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

# Push ishield-operator bundle index
echo -----------------------------
echo [3/4]  Pushing bundle index
docker push ${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}

echo "Completed building bundle and index"
