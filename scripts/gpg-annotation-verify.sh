#!/bin/bash

CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME  <input-file> <pubring-key>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

INPUT_FILE=$1
PUBRING_KEY=$2

if ! [ -x "$(command -v yq)" ]; then
   echo 'Error: yq is not installed.' >&2
   exit 1
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
    base_decode='base64 -d'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
    base_decode='base64 -D'
fi

msg=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations.message')
sign=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations.signature')


IV_TMP_DIR="/tmp/iv_tmp_dir"

if [ ! -d ${IV_TMP_DIR} ]; then
   mkdir -p  ${IV_TMP_DIR}
fi


IV_INPUT_FILE="${IV_TMP_DIR}/input.yaml"
IV_SIGN_FILE="${IV_TMP_DIR}/input.sig"
IV_MSG_FILE="${IV_TMP_DIR}/input.msg"


cat ${INPUT_FILE} > ${IV_INPUT_FILE}

yq d ${IV_INPUT_FILE} metadata.annotations.message -i
yq d ${IV_INPUT_FILE} metadata.annotations.signature -i


msg_body=`cat ${IV_INPUT_FILE} | $base`

if [ "${msg}" != "${msg_body}" ]; then
   echo Input file content has been changed.
   if [ -d ${IV_TMP_DIR} ]; then
     rm -rf ${IV_TMP_DIR}
   fi
   exit 0
fi

if [ -z ${msg} ] || [ -z ${sign} ] ; then
   echo "Input file is not yet signed."
else
   echo $msg | ${base_decode} >  ${IV_MSG_FILE}
   echo $sign | ${base_decode} > ${IV_SIGN_FILE}

   status=$(gpg --no-default-keyring --keyring ${PUBRING_KEY} --dry-run --verify ${IV_SIGN_FILE}  ${IV_MSG_FILE} 2>&1)

   if [ -d ${IV_TMP_DIR} ]; then
     rm -rf ${IV_TMP_DIR}
   fi

   result=$(echo $status | grep "Good" | wc -c)
   echo ----------------------------------------------
   if [ ${result} -gt 0 ]; then
      echo $status
      echo "Signature is successfully verified."
      exit 1
   else
      echo $status
      echo "Signature is invalid"
      exit 0
   fi
   echo --------------------------------------------------

fi


