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

if [ ! -f $INPUT_FILE ]; then
    echo "Input file could not be found."
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
    base_decode='base64 -d'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
    base_decode='base64 -D'
fi

YQ_VERSION=$(yq --version 2>&1 | awk '{print $3}' | cut -c 1 )

if [[ $YQ_VERSION == "3" ]]; then
    msg=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/message"')
    sign=$(yq r -d0 ${INPUT_FILE} 'metadata.annotations."integrityshield.io/signature"')
elif [[ $YQ_VERSION == "4" ]]; then
    msg=$(yq eval '.metadata.annotations."integrityshield.io/message" | select(di == 0)' ${INPUT_FILE})
    sign=$(yq eval '.metadata.annotations."integrityshield.io/signature" | select(di == 0)' ${INPUT_FILE})
fi


ISHIELD_TMP_DIR="${TMP_DIR}/ishield_tmp_dir"

if [ ! -d ${ISHIELD_TMP_DIR} ]; then
   mkdir -p  ${ISHIELD_TMP_DIR}
fi


ISHIELD_INPUT_FILE="${ISHIELD_TMP_DIR}/input.yaml"
ISHIELD_SIGN_FILE="${ISHIELD_TMP_DIR}/input.sig"
ISHIELD_MSG_FILE="${ISHIELD_TMP_DIR}/input.msg"


cat ${INPUT_FILE} > ${ISHIELD_INPUT_FILE}

if [[ $YQ_VERSION == "3" ]]; then
   yq d -d* ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/message"' -i
   yq d -d* ${ISHIELD_INPUT_FILE} 'metadata.annotations."integrityshield.io/signature"' -i
   cnt=0
   yq r -d* ${ISHIELD_INPUT_FILE} -j | while read doc;
   do
      annotation_exist=$(echo $doc | yq r - 'metadata.annotations')
      if  [ "${annotation_exist}" == "{}" ]; then
          yq d -d${cnt} ${ISHIELD_INPUT_FILE} 'metadata.annotations' -i
      fi
      cnt=$[$cnt+1]
   done
elif [[ $YQ_VERSION == "4" ]]; then
   yq eval 'del(.metadata.annotations."integrityshield.io/message")' -i ${ISHIELD_INPUT_FILE}
   yq eval 'del(.metadata.annotations."integrityshield.io/signature")' -i ${ISHIELD_INPUT_FILE}
   cnt=0
   while true
   do
      kind=$(yq eval ".kind | select(di == $cnt)" ${ISHIELD_INPUT_FILE}  | sed 's/\//_/g')
      if [ -z "$kind" ]; then
          break
      fi
      annotation_exist=$(yq eval ".metadata.annotations | select(di == $cnt)" ${ISHIELD_INPUT_FILE})
      if  [ "${annotation_exist}" == "{}" ]; then
          yq eval "del(.metadata.annotations | select(di == $cnt))" -i ${ISHIELD_INPUT_FILE}
      fi
      cnt=$[$cnt+1]
   done
fi


msg_body=`cat ${ISHIELD_INPUT_FILE} | $base`

if [ "${msg}" != "${msg_body}" ]; then
   echo "Input file content has been changed."
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


