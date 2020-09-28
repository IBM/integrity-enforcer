#!/bin/bash

CMDNAME=`basename $0`
if [ $# -ne 3 ]; then
  echo "Usage: $CMDNAME <signer> <input> <output>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

SIGNER=$1
INPUT_FILE=$2
OUTPUT_FILE=$3

# compute signature (and encoded message and certificate)
cat <<EOF > $OUTPUT_FILE
apiVersion: research.ibm.com/v1alpha1
kind: ResourceSignature
metadata:
   annotations:
      messageScope: spec
      signature: ""
   name: ""
spec:
   data:
   - message: ""
     signature: ""
     type: resource
EOF


if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
fi

# message
msg=`cat $INPUT_FILE | $base`

# signature
sig=`cat ${INPUT_FILE} > temp-aaa.yaml; gpg -u $SIGNER --detach-sign --armor --output - temp-aaa.yaml | $base`


yq w -i $OUTPUT_FILE spec.data.[0].message $msg
yq w -i $OUTPUT_FILE spec.data.[0].signature $sig

# resource signature spec content
rsigspec=`cat $OUTPUT_FILE | yq r - -j |jq -r '.spec' | yq r - --prettyPrint | $base`

# resource signature signature
rsigsig=`echo -e "$rsigspec" > temp-rsig.yaml; gpg -u $SIGNER --detach-sign --armor --output - temp-rsig.yaml | $base`

# name of resource signature
rsigname="rsig-$(cat $INPUT_FILE | yq r - -j | jq -r '.metadata.name')"

# add new annotations
yq w -i $OUTPUT_FILE metadata.annotations.signature $rsigsig
yq w -i $OUTPUT_FILE metadata.name $rsigname
