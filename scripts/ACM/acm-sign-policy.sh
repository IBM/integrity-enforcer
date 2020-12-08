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
SCRIPT_DIR=$(cd $(dirname $0); pwd)
SIGNER=$1
TARGET_DIR=$2
find ${TARGET_DIR} -type f -name "*.yaml" | while read file;
do
  cp ${file} ${file}.backup
  echo Original file backed up as ${file}.backup

  $SCRIPT_DIR/../gpg-annotation-sign.sh ${SIGNER} "$file"
  echo Signature annotation is attached in $file.
done
