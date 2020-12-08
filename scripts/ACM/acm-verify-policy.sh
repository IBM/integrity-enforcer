#!/bin/bash
CMDNAME=`basename $0`
if [ $# -ne 3 ]; then
  echo "Usage: $CMDNAME <signer> <YAML files directory> <pubring-key>" 1>&2
  exit 1
fi
if [ ! -e $3 ]; then
  echo "$3 does not exist"
  exit 1
fi

SCRIPT_DIR=$(cd $(dirname $0); pwd)
SIGNER=$1
TARGET_DIR=$2
PUBRING_KEY=$3

find ${TARGET_DIR} -type f -name "*.yaml" | while read file;
do
  echo "Verifying signature annotation in ${file}"
  $SCRIPT_DIR/../gpg-annotation-verify.sh ${SIGNER} "$file" ${PUBRING_KEY}
done
