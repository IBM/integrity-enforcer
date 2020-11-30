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
