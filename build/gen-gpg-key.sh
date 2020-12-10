#!/bin/bash
#
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
if [ $# -ne 4 ]; then
  echo "Usage: $CMDNAME <signer> <pub-key-out-file> <tmp-dir> <generate-key>" 1>&2
  exit 1
fi

if [ ! -e $3 ]; then
  echo "$3 does not exist"
  exit 1
fi

SIGNER=$1
PUB_RING_KEY=$2
TMP_DIR=$3
GEN_KEY=$4

if  [ "${GEN_KEY}" = true ]; then

cat >${TMP_DIR}/generate_key <<EOF
     %echo Generating a basic OpenPGP key
     %no-protection
     %no-ask-passphrase
     #%pubring pubring.kbx
     %secring trustdb.gpg
     Key-Type: RSA
     Key-Length: 3072
     Subkey-Type: RSA
     Subkey-Length:  3072
     Name-Real:${SIGNER}
     #Name-Comment: with a passphrase
     Name-Email: ${SIGNER}
     Expire-Date: 0
     #Passphrase: abc
     # Do a commit here, so that we can later print "done" :-)
     %commit
     %echo done
EOF

   echo "Going to generate new gpg key for ${SIGNER}"
   gpg --batch --generate-key ${TMP_DIR}/generate_key
fi

gpg --list-secret-keys

echo Exporting pubring key to ${PUB_RING_KEY}.
gpg --export ${SIGNER} > ${PUB_RING_KEY}
