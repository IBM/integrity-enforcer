#!/bin/bash

CMDNAME=`basename $0`
if [ $# -ne 3 ]; then
  echo "Usage: $CMDNAME <signer> <input-file> <pubring-key>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

SIGNER=$1
INPUT_FILE=$2
PUBRING_KEY=$3

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
    base_decode='base64 -d'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
    base_decode='base64 -D'
fi


msg=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations.message')
sign=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations.signature')

if [ -z ${msg} ] || [ -z ${sign} ] ; then
   echo "Input file is not yet signed."
else
   echo $msg | ${base_decode} >  /tmp/msg
   echo $sign | ${base_decode} > /tmp/sign.sig

   status=$(gpg --no-default-keyring --keyring ${PUBRING_KEY} --verify /tmp/sign.sig /tmp/msg 2>&1)
   result=$(echo $status | grep "Good" | wc -c)
   echo ----------------------------------------------
   if [ ${result} -gt 0 ]; then
      echo $status
      echo "Signature is successfully verified."
      exit 0
   else
      echo $status
      echo "Signature not verified."
      exit 1
   fi
   echo --------------------------------------------------
   if [ -f /tmp/msg ]; then
     rm /tmp/msg
   fi

   if [ -f /tmp/sign.sig ]; then
     rm /tmp/sign.sig
   fi
fi


