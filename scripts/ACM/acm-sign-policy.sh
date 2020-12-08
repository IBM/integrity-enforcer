#!/bin/bash

CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME <signer> <YAML files directory>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi


SIGNER=$1
TARGET_DIR=$2

find ${TARGET_DIR} -type f -name "*.yaml" | while read file;
do
  echo Signing  $file with signer: ${SIGNER}

  ../gpg-annotation-sign.sh ${SIGNER} "$file"
done

