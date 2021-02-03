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

set -e

if [[ ${#@} -ne 1 ]]; then
    echo "Usage: $0 version"
    echo "* version: the github release version of OLM"
    exit 1
fi

echo "E2E TEST BUNDLE GOES HERE!"

BUNDLE_INDX_IMAGE=${TEST_ISHIELD_OPERATOR_INDEX_IMAGE_NAME_AND_VERSION}
echo BUNDLE_INDX_IMAGE: ${BUNDLE_INDX_IMAGE}

release=$1
echo ""
echo "-------------------------------------------------"
echo "Install OLM"
curl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/${release}/install.sh | bash -s ${release}

cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${ISHIELD_OP_NS}
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: operatorgroup
  namespace: ${ISHIELD_OP_NS}
spec:
  targetNamespaces:
  - ${ISHIELD_OP_NS}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: integrity-shield-operator
  namespace: ${ISHIELD_OP_NS}
spec:
  channel: alpha
  name: integrity-shield-operator
  source: integrity-shield-operator-catalog
  sourceNamespace: olm
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: integrity-shield-operator-catalog
  namespace: olm
spec:
  displayName: Integrity Ishield Operator
  image: ${BUNDLE_INDX_IMAGE}
  publisher: IBM
  sourceType: grpc
  updateStrategy:
    registryPoll:
      interval: 45m
EOF


