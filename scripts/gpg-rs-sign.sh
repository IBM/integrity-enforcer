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
apiVersion: apis.integrityenforcer.io/v1alpha1
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
msg=`cat $INPUT_FILE | gzip -c | $base`

# signature
sig=`cat ${INPUT_FILE} > temp-aaa.yaml; gpg -u $SIGNER --detach-sign --armor --output - temp-aaa.yaml | $base`
sigtime=`date +%s`

yq w -i $OUTPUT_FILE spec.data.[0].message $msg
yq w -i $OUTPUT_FILE spec.data.[0].signature $sig

# resource signature spec content
rsigspec=`cat $OUTPUT_FILE | yq r - -j |jq -r '.spec' | yq r - --prettyPrint | $base`

# resource signature signature
rsigsig=`echo -e "$rsigspec" > temp-rsig.yaml; gpg -u $SIGNER --detach-sign --armor --output - temp-rsig.yaml | $base`


# name of resource signature
resApiVer=`cat $INPUT_FILE | yq r - -j | jq -r '.apiVersion' | sed 's/\//_/g'`
resKind=`cat $INPUT_FILE | yq r - -j | jq -r '.kind'`
reslowerkind=`cat $INPUT_FILE | yq r - -j | jq -r '.kind' | tr '[:upper:]' '[:lower:]'`
resname=`cat $INPUT_FILE | yq r - -j | jq -r '.metadata.name'`
rsigname="rsig-${reslowerkind}-${resname}"

# add new annotations
yq w -i $OUTPUT_FILE metadata.annotations.signature $rsigsig
yq w -i $OUTPUT_FILE metadata.name $rsigname
yq w -i $OUTPUT_FILE 'metadata.labels."integrityenforcer.io/sigobject-apiversion"' $resApiVer
yq w -i $OUTPUT_FILE 'metadata.labels."integrityenforcer.io/sigobject-kind"' $resKind
yq w -i --tag !!str $OUTPUT_FILE 'metadata.labels."integrityenforcer.io/sigtime"' $sigtime
