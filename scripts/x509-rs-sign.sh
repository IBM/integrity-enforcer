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
  echo "Usage: $CMDNAME <signingkey-file> <signingcert-file> <input> <output>" 1>&2
  exit 1
fi

if [ ! -e $1 ]; then
  echo "$1 does not exist"
  exit 1
fi
if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi
if [ ! -e $3 ]; then
  echo "$3 does not exist"
  exit 1
fi

KEY_FILE=$1
CERT_FILE=$2
INPUT_FILE=$3
OUTPUT_FILE=$4

if [ -z "$TMP_DIR" ]; then
    echo "TMP_DIR is empty. Setting /tmp as default"
    TMP_DIR="/tmp"
    if [ ! -d $TMP_DIR ]; then
       echo "$TMP_DIR directory does not exist, please create it."
    fi
fi

# compute signature (and encoded message and certificate)
cat <<EOF > $OUTPUT_FILE
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSignature
metadata:
   annotations:
      integrityshield.io/messageScope: spec
      integrityshield.io/signature: ""
   name: ""
spec:
   data:
   - message: ""
     signature: ""
     certificate: ""
     type: resource
EOF


if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
fi

# message
msg=`cat $INPUT_FILE | gzip -c | $base`

# signature
sig=`openssl dgst -sha256 -sign ${KEY_FILE} ${INPUT_FILE} | $base`
sigtime=`date +%s`

# certificate
crt=`cat ${CERT_FILE} | $base`

yq w -i $OUTPUT_FILE spec.data.[0].message $msg
yq w -i $OUTPUT_FILE spec.data.[0].signature $sig
yq w -i $OUTPUT_FILE spec.data.[0].certificate $crt

# resource signature spec content
rsigspec=`cat $OUTPUT_FILE | yq r - -j |jq -r '.spec' | yq r - --prettyPrint | $base`

# resource signature signature
rsigsig=`echo -e "$rsigspec" > ${TMP_DIR}/temp-rsig.yaml; openssl dgst -sha256 -sign ${KEY_FILE} ${TMP_DIR}/temp-rsig.yaml | $base`

# name of resource signature
resApiVer=`cat $INPUT_FILE | yq r - -j | jq -r '.apiVersion' `
resKind=`cat $INPUT_FILE | yq r - -j | jq -r '.kind' `
reslowerkind=`cat $INPUT_FILE | yq r - -j | jq -r '.kind' | tr '[:upper:]' '[:lower:]'`
resname=`cat $INPUT_FILE | yq r - -j | jq -r '.metadata.name'`
rsigname="rsig-${reskind}-${resname}"

# add new annotations
yq w -i $OUTPUT_FILE 'metadata.annotations."integrityshield.io/signature"' $rsigsig
yq w -i $OUTPUT_FILE 'metadata.annotations."integrityshield.io/certificate"' $crt
yq w -i $OUTPUT_FILE metadata.name $rsigname
yq w -i $OUTPUT_FILE 'metadata.labels."integrityshield.io/sigobject-apiversion"' $resApiVer
yq w -i $OUTPUT_FILE 'metadata.labels."integrityshield.io/sigobject-kind"' $resKind
yq w -i --tag !!str $OUTPUT_FILE 'metadata.labels."integrityshield.io/sigtime"' $sigtime

if [ -f ${TMP_DIR}/temp-rsig.yaml ]; then
   rm ${TMP_DIR}/temp-rsig.yaml
fi
