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
# limitations under the License


CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME <signer> <tmp-dir>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set env."
    exit 1
fi

SIGNER=$1
TEMP_DIR=$2

define(){ IFS='\n' read -r -d '' ${1} || true; }

echo ""
define MULTI_YAML <<-EOF
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
  name: policy-cert-ocp4
  annotations:
    policy.open-cluster-management.io/standards: NIST SP 800-53
    policy.open-cluster-management.io/categories: SC System and Communications Protection
    policy.open-cluster-management.io/controls: SC-12 Cryptographic Key Establishment and Management
spec:
  remediationAction: inform
  disabled: false
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
  name: binding-policy-cert-ocp4
placementRef:
  name: placement-policy-cert-ocp4
  kind: PlacementRule
  apiGroup: apps.open-cluster-management.io
subjects:
- name: policy-cert-ocp4
  kind: Policy
  apiGroup: policy.open-cluster-management.io
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
  name: placement-policy-cert-ocp4
spec:
  clusterConditions:
  - status: "True"
    type: ManagedClusterConditionAvailable
  clusterSelector:
    matchExpressions:
      - {key: vendor, operator: In, values: ["OpenShift"]}
EOF

echo ""
define MULTI_YAML_RSP <<-EOF
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: multi-yaml-rsp
spec:
  protectRules:
    - match:
        - kind: Policy
        - kind: PlacementBinding
        - kind: PlacementRule
EOF

echo ""
define SINGLE_YAML <<-EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key1: val1
  key2: val2
  key4: val4
EOF

echo ""
define SINGLE_YAML_RSP <<-EOF
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: single-yaml-rsp
spec:
  protectRules:
    - match:
        - kind: ConfigMap
EOF


echo ----------------------------------------------------------------------------
echo "[1/6] Unit test gpg annotation multi yaml"

${ISHIELD_REPO_ROOT}/build/unit-test-gpg-annotation.sh "$SIGNER" "$TEMP_DIR" "$MULTI_YAML"

echo ""
echo ----------------------------------------------------------------------------
echo "[2/6] Unit test gpg resource signature multi yaml"

${ISHIELD_REPO_ROOT}/build/unit-test-gpg-rs-sign.sh "$SIGNER" "$TEMP_DIR" "$MULTI_YAML"

echo ""
echo ----------------------------------------------------------------------------
echo "[3/6] Unit test gpg annotation single yaml"

${ISHIELD_REPO_ROOT}/build/unit-test-gpg-annotation.sh "$SIGNER" "$TEMP_DIR" "$SINGLE_YAML"

echo ""
echo ----------------------------------------------------------------------------
echo "[4/6] Unit test gpg resource signature single yaml"

${ISHIELD_REPO_ROOT}/build/unit-test-gpg-rs-sign.sh "$SIGNER" "$TEMP_DIR" "$SINGLE_YAML"

echo ""
echo ----------------------------------------------------------------------------
echo "[5/6] Unit test gpg rsp generation single yaml"

${ISHIELD_REPO_ROOT}/build/unit-test-rsp-generation.sh "single-yaml-rsp" "$SINGLE_YAML" "$SINGLE_YAML_RSP" "$TEMP_DIR"

echo ""
echo ----------------------------------------------------------------------------
echo "[6/6] Unit test gpg rsp generation multi yaml"

${ISHIELD_REPO_ROOT}/build/unit-test-rsp-generation.sh "multi-yaml-rsp" "$MULTI_YAML" "$MULTI_YAML_RSP" "$TEMP_DIR"
echo ""
