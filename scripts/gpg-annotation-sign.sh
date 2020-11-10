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
OUT_FILE=$3

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
fi

yq read $INPUT_FILE -d 0 > $OUT_FILE

yq d $OUT_FILE  metadata.annotations.message -i
yq d $OUT_FILE  metadata.annotations.signature -i

metaname=$(cat $INPUT_FILE | yq r - 'metadata.name')

# message
msg=`cat $INPUT_FILE | $base`

# signature
sig=`cat $INPUT_FILE > temp-aaa.yaml; gpg -u $SIGNER --detach-sign --armor --output - temp-aaa.yaml | $base`

yq d $OUT_FILE metadata.annotations.message -i
yq d $OUT_FILE metadata.annotations.signature -i

yq w -i $OUT_FILE metadata.annotations.message $msg
yq w -i $OUT_FILE metadata.annotations.signature $sig

rm temp-aaa.yaml
