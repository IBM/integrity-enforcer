#! /bin/bash
#
# Copyright 2021 IBM Corporation.
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

CRC=0

RED='\033[0;31m'
NC='\033[0m' # No Color

function fail()
{
    echo -en $RED
    tput bold
    echo -e "$1"
    tput sgr0
    echo -en $NC
}


# Enforce check for copyright statements in Go code
GOSRCFILES=($(find ./ -type f -name \*.go -or -name \*.sh -or -name Dockerfile))
for GOFILE in "${GOSRCFILES[@]}"; do
  if ! grep -q "Licensed under the Apache License, Version 2.0" $GOFILE; then
    fail "Missing copyright/licence statement in ${GOFILE}"
    CRC=$(($CRC + 1))
  fi
done 

if [ $CRC -gt 0 ]; then fail "Please add copyright statements and check in the updated file(s).\n"; fi

exit $CRC