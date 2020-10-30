#!/bin/bash

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
rsigsig=`echo -e "$rsigspec" > temp-rsig.yaml; openssl dgst -sha256 -sign ${KEY_FILE} temp-rsig.yaml | $base`

# name of resource signature
resApiVer=`cat $INPUT_FILE | yq r - -j | jq -r '.apiVersion' `
resKind=`cat $INPUT_FILE | yq r - -j | jq -r '.kind' `
reslowerkind=`cat $INPUT_FILE | yq r - -j | jq -r '.kind' | tr '[:upper:]' '[:lower:]'`
resname=`cat $INPUT_FILE | yq r - -j | jq -r '.metadata.name'`
rsigname="rsig-${reskind}-${resname}"

# add new annotations
yq w -i $OUTPUT_FILE metadata.annotations.signature $rsigsig
yq w -i $OUTPUT_FILE metadata.annotations.certificate $crt
yq w -i $OUTPUT_FILE metadata.name $rsigname
yq w -i $OUTPUT_FILE 'metadata.labels."integrityenforcer.io/sigsubject-apiversion"' $resApiVer
yq w -i $OUTPUT_FILE 'metadata.labels."integrityenforcer.io/sigsubject-kind"' $resKind
yq w -i --tag !!str $OUTPUT_FILE 'metadata.labels."integrityenforcer.io/sigtime"' $sigtime
