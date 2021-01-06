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



if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

CMDNAME=`basename $0`
if [ $# -ne 1 ]; then
  echo "Usage: $CMDNAME <public-key-file-path> " 1>&2
  exit 1
fi

PUBLIC_KEY_FILE_PATH=$1


OUTPUT_FILE=${TMP_DIR}/all_in_one.yaml
CRD_FILE=${TMP_DIR}/ishield_crds.yaml
OPERATOR_FILE=${TMP_DIR}/ishield_operator.yaml
KEYRING_FILE=${TMP_DIR}/key-ring.yaml
TMP_CR_FILE=${TMP_DIR}/ishield_cr.yaml

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
fi

cat <<EOF > $OUTPUT_FILE
apiVersion: v1
kind: Namespace
metadata:
  name: ${ISHIELD_OP_NS}
EOF

ENCODED_PUBKEY=$(cat ${PUBLIC_KEY_FILE_PATH} | ${base})

cat <<EOF > ${KEYRING_FILE}
apiVersion: v1
kind: Secret
metadata:
  name: keyring-secret
  namespace: ${ISHIELD_OP_NS}
type: Opaque
data:
  pubring.gpg: ${ENCODED_PUBKEY}
EOF


# Generate ishield-crds
echo -----------------------------
echo [1/4] Generating ishield-crds
kustomize build ${SHIELD_OP_DIR}/config/crd > ${CRD_FILE}


# Prepare ishield-operator resources
echo -----------------------------
echo [2/4] Generating operator resources
cp ${SHIELD_OP_DIR}/config/manager/kustomization.yaml ${TMP_DIR}/kustomization.yaml  #copy original file to tmp dir.
cd ${SHIELD_OP_DIR}/config/manager && kustomize edit set image controller=${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION}
kustomize build ${SHIELD_OP_DIR}/config/default > ${OPERATOR_FILE}
cp ${TMP_DIR}/kustomization.yaml ${SHIELD_OP_DIR}/config/manager/kustomization.yaml

# Prepare ishield-operator cr
echo -----------------------------
echo [3/4] Generating operator cr
cp ${SHIELD_OP_DIR}/config/samples/apis_v1alpha1_integrityshield_local.yaml ${TMP_CR_FILE}
yq write -i ${TMP_CR_FILE} spec.logger.image ${ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION}
yq write -i ${TMP_CR_FILE} spec.logger.imagePullPolicy Always
yq write -i ${TMP_CR_FILE} spec.server.image ${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION}
yq write -i ${TMP_CR_FILE} spec.server.imagePullPolicy Always
yq write -i ${TMP_CR_FILE} metadata.namespace ${ISHIELD_OP_NS}

# Prepare all-in-one yaml
echo -----------------------------
echo [3/4] Generating all_in_one.yaml

echo  "---"  >>  ${OUTPUT_FILE}
cat ${CRD_FILE} >>  ${OUTPUT_FILE}
echo  "---"  >>  ${OUTPUT_FILE}
cat ${OPERATOR_FILE} >>  ${OUTPUT_FILE}
echo  "---"  >>  ${OUTPUT_FILE}
cat ${KEYRING_FILE} >> ${OUTPUT_FILE}
echo  "---"  >>  ${OUTPUT_FILE}
cat ${TMP_CR_FILE} >>  ${OUTPUT_FILE}
echo  "---"  >>  ${OUTPUT_FILE}

cat ${OUTPUT_FILE}

if [ -f ${CRD_FILE} ]; then
  rm ${CRD_FILE}
fi

if [ -f ${OPERATOR_FILE} ]; then
  rm ${OPERATOR_FILE}
fi

if [ -f ${KEYRING_FILE} ]; then
  rm ${KEYRING_FILE}
fi

if [ -f ${TMP_CR_FILE} ]; then
  rm ${TMP_CR_FILE}
fi

echo
echo
echo "all-in-one.yaml for deploying IShield is generated !!"
echo
echo
