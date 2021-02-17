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
  echo "Usage: $CMDNAME <rsp-name> <input-file> <output-file>" 1>&2
  exit 1
fi

RSP_NAME=$1
INPUT_FILE=$2
OUTPUT_FILE=$3

base_rpp='{"apiVersion":"apis.integrityshield.io/v1alpha1","kind":"ResourceSigningProfile","metadata":{"name":""},"spec": {} }'

if [ ! -f $INPUT_FILE ]; then
   echo "Input file does not exist, please create it."
   exit 1
fi

if [ -f $OUTPUT_FILE ]; then
   rm $OUTPUT_FILE
fi

YQ_VERSION=$(yq --version 2>&1 | awk '{print $3}' | cut -c 1 )

if [[ $YQ_VERSION == "3" ]]; then
  echo -e $base_rpp | yq r - --prettyPrint >> $OUTPUT_FILE
elif [[ $YQ_VERSION == "4" ]]; then
  echo -e $base_rpp | yq eval --prettyPrint >> $OUTPUT_FILE
fi

# Prepare RSP

# 1. set rpp name

if [[ $YQ_VERSION == "3" ]]; then
  yq w -i $OUTPUT_FILE metadata.name $RSP_NAME
elif [[ $YQ_VERSION == "4" ]]; then
  yq eval ".metadata.name = \"$RSP_NAME\"" -i $OUTPUT_FILE
fi

# 2. set rules
cnt=0
if [[ $YQ_VERSION == "3" ]]; then
   yq r -d'*' $INPUT_FILE -j | while read doc;
   do
      kind=$(echo $doc | yq r - -j | jq -r '.kind')
      if [ $kind = 'Namespace' ]; then
        continue
      fi

      #name=$(echo $doc | yq r - -j | jq -r '.metadata.name')

      yq w -i $OUTPUT_FILE spec.protectRules.[0].match.[$cnt].kind $kind

     cnt=$[$cnt+1]
   done

elif [[ $YQ_VERSION == "4" ]]; then
  indx=0
  while true
  do
    kind=$(yq eval ".kind | select(di == $cnt)" ${INPUT_FILE}  | sed 's/\//_/g')
    if [ -z "$kind" ]; then
       break
    fi
    if  [ $kind != 'Namespace' ]; then
       yq eval ".spec.protectRules.[0].match.[$indx].kind = \"$kind\"" -i $OUTPUT_FILE --prettyPrint
       indx=$[$indx+1]
    fi
    cnt=$[$cnt+1]
  done
fi
