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

if [ -z "$TMP_DIR" ]; then
    echo "TMP_DIR is empty. Setting /tmp as default"
    TMP_DIR="/tmp"
fi

if [ ! -d $TMP_DIR ]; then
    echo "$TMP_DIR directory does not exist, please create it."
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
    base_decode='base64 -d'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
    base_decode='base64 -D'
fi

msg=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/message"')
sign=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/signature"')


ISHIELD_TMP_DIR="${TMP_DIR}/ishield_tmp_dir"

if [ ! -d ${ISHIELD_TMP_DIR} ]; then
   mkdir -p  ${ISHIELD_TMP_DIR}
fi


ISHIELD_INPUT_FILE="${ISHIELD_TMP_DIR}/input.yaml"
ISHIELD_SIGN_FILE="${ISHIELD_TMP_DIR}/input.sig"
ISHIELD_MSG_FILE="${ISHIELD_TMP_DIR}/input.msg"


cat ${INPUT_FILE} > ${ISHIELD_INPUT_FILE}

yq d ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/message"' -i
yq d ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/signature"' -i


msg_body=`cat ${ISHIELD_INPUT_FILE} | $base`

if [ "${msg}" != "${msg_body}" ]; then
   echo Input file content has been changed.
   if [ -d ${ISHIELD_TMP_DIR} ]; then
     rm -rf ${ISHIELD_TMP_DIR}
   fi
   exit 0
fi

if [ -z ${msg} ] || [ -z ${sign} ] ; then
   echo "Input file is not yet signed."
else
   echo $msg | ${base_decode} >  ${ISHIELD_MSG_FILE}
   echo $sign | ${base_decode} > ${ISHIELD_SIGN_FILE}

   status=$(gpg --no-default-keyring --keyring ${PUBRING_KEY} --dry-run --verify ${ISHIELD_SIGN_FILE}  ${ISHIELD_MSG_FILE} 2>&1)

   if [ -d ${ISHIELD_TMP_DIR} ]; then
     rm -rf ${ISHIELD_TMP_DIR}
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


