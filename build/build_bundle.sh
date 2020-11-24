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


if [ -z "$IV_REPO_ROOT" ]; then
    echo "IV_REPO_ROOT is empty. Please set root directory for IV repository"
    exit 1
fi

#source $IV_REPO_ROOT/iv-build.conf

cd $IV_REPO_ROOT/integrity-enforcer-operator


# Build iv-operator bundle
echo -----------------------------
echo [1/4] Building bundle
make bundle IMG=${IV_OPERATOR_IMAGE_NAME_AND_VERSION} VERSION=${VERSION}


csvfile="bundle/manifests/integrity-enforcer-operator.clusterserviceversion.yaml"
cat $csvfile | yq r - -j >  tmp.json

change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "OwnNamespace").supported=true)') && echo "$change" >  tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "SingleNamespace").supported=true)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "MultiNamespace").supported=false)') && echo "$change" > tmp.json
change=$(cat tmp.json | jq '.spec.installModes |=map (select(.type == "AllNamespaces").supported=false)') && echo "$change" > tmp.json

cat tmp.json  | yq r - -P > $csvfile
rm tmp.json

make bundle-build BUNDLE_IMG=${IV_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}

# Push iv-operator bundle
echo -----------------------------
echo [2/4] Pushing bundle
docker push ${IV_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION}

# Prepare iv-operator bundle index
echo -----------------------------
echo [3/4] Adding bundle to index


docker pull ${IV_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} | grep "Image is up to date" && pull_status="pulled" || pull_status="failed"

if [ "$pull_status" = "failed" ]; then
        sudo /usr/local/bin/opm index add -c docker --generate --bundles ${IV_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION} \
                      --tag ${IV_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --out-dockerfile tmp.Dockerfile
else
	echo "Succesfulling pulled previous index"
	sudo /usr/local/bin/opm index add -c docker --generate --bundles ${IV_OPERATOR_BUNDLE_IMAGE_NAME_AND_VERSION} \
                      --from-index ${IV_OPERATOR_INDEX_IMAGE_NAME_AND_PREVIOUS_VERSION} \
                      --tag ${IV_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --out-dockerfile tmp.Dockerfile
fi

rm -f tmp.Dockerfile

# Build iv-operator bundle index
echo -----------------------------
echo [3/4]  Building bundle index
docker build -f index.Dockerfile -t ${IV_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION} --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

# Push iv-operator bundle index
echo -----------------------------
echo [3/4]  Pushing bundle index
docker push ${IV_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}

echo "Completed building bundle and index"
