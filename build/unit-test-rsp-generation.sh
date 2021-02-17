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
if [ $# -ne 4 ]; then
  echo "Usage: $CMDNAME <rsp-name> <input-yaml> <expected-rsp> <tmp-dir> " 1>&2
  exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

RSP_NAME=$1
INPUT_YAML=$2
EXPECTED_RSP=$3
TMP_DIR="$4"/IV_TMP

if [ ! -d ${TMP_DIR} ]; then
   echo "Creating tmpdir $TMP_DIR"
   mkdir ${TMP_DIR}
fi

INPUT_FILE=${TMP_DIR}/input.yaml
RSP_FILE=${TMP_DIR}/rsp.yaml
EXPECTED_RSP_FILE=${TMP_DIR}/expected_rsp.yaml

echo "$INPUT_YAML" > ${INPUT_FILE}
echo  "$EXPECTED_RSP" > ${EXPECTED_RSP_FILE}

if [ ! -f ${INPUT_FILE} ]; then
   echo "Input file is not found"
   exit 0
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
fi

YQ_VERSION=$(yq --version 2>&1 | awk '{print $3}' | cut -c 1 )

echo -----------------------------
echo [1/2] Generating resource signing profile
${ISHIELD_REPO_ROOT}/scripts/generate_rsp.sh  "$RSP_NAME" "$INPUT_FILE" "$RSP_FILE"

echo -----------------------------
echo [2/2] Verifying resource signing profile

if [ -f ${RSP_FILE} ]; then
   if [[ $YQ_VERSION == "3" ]]; then
      RSP_GENERATED=$(yq r ${RSP_FILE} --prettyPrint)
      RSP_EXPECTED=$(yq r ${EXPECTED_RSP_FILE} --prettyPrint)
   elif [[ $YQ_VERSION == "4" ]]; then
      RSP_GENERATED=$(yq eval ${RSP_FILE} --prettyPrint )
      RSP_EXPECTED=$(yq eval ${EXPECTED_RSP_FILE} --prettyPrint)
   fi

   if [ "${RSP_GENERATED}" != "${RSP_EXPECTED}" ]; then
      echo "Generated RSP is different from expected one"
      exit 0
   else
     echo "Successfully verified generated RSP"
   fi
else
   echo "Failed to generate RSP"
   exit 0
fi
