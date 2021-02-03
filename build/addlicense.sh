#!/bin/bash

targetFile=$1
licenseFile=$2

LICENSELEN=$(wc -l ${licenseFile} | cut -f1 -d ' ')

echo $LICENSELEN

head -$LICENSELEN ${targetFile} | diff ${licenseFile} - || ( ( cat ${licenseFile}; echo; cat ${targetFile}) > ${SHIELD_OP_DIR}/file; mv ${SHIELD_OP_DIR}/file ${targetFile})
