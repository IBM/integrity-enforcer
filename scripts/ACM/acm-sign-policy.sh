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
  cp ${file} ${file}.backup
  echo Original file backed up as ${file}.backup

  curl -s https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/gpg-annotation-sign.sh | bash -s ${SIGNER} "$file"

  echo Signature annotation is attached in $file.
done
