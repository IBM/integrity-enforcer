#!/bin/bash

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
if [ $# -ne 1 ]; then
  echo "Usage: $CMDNAME <kind>" 1>&2
  exit 1
fi

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v jq)" ]; then
    echo 'Error: jq is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v column)" ]; then
    echo 'Error: column is not installed.' >&2
    exit 1
fi

search_kind=$1

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    date='date -u -d @'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    date='date -u -r '
fi

kindlist=""
if [[ $search_kind == "all" ]]; then
    kindlist=`kubectl api-resources | awk '{print $1}' | grep -v NAME`
else
    kindlist=$search_kind
fi



IFS=$'\n'
for line in $kindlist
do
    kind_input=$line
    items=`kubectl get ${kind_input} --all-namespaces --selector 'integrityshield.io/resourceIntegrity=verified' -o json 2> /dev/null`
    items_num=`echo -e "$items" | jq .items | jq length`
    kind=$kind_input
    if [[ $items_num != "0" ]]; then
        valid_item_found=0
        result=`echo NAMESPACE NAME SIGNER LAST_VERIFIED RSIG_UID`
        for item in `echo -e "$items" | jq .items[] | jq -c . `
        do
            # echo -e "$item"
            kind=`echo -e "$item" | jq -r .kind`
            ns=`echo -e "$item" | jq -r .metadata.namespace`
            if [[ $ns == "null" ]]; then
                ns="-"
            fi
            name=`echo -e "$item" | jq -r .metadata.name`
            signer=`echo -e "$item" | jq -r '.metadata.annotations."integrityshield.io/signedBy"'`
            lastVerified=`echo -e "$item" | jq -r '.metadata.annotations."integrityshield.io/lastVerifiedTimestamp"'`
            resSigUID=`echo -e "$item" | jq -r '.metadata.annotations."integrityshield.io/resourceSignatureUID"'`
            if [[ $lastVerified != "null" ]]; then
                valid_item_found=1
                result=`echo -e "${result}\n$ns $name $signer $lastVerified $resSigUID"`
            fi
        done
        if [[ $valid_item_found -eq 1 ]]; then
            echo --- $kind ---
            echo -e "$result" | column -t
            echo ""
        fi  
    fi
done

