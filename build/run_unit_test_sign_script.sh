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
# limitations under the License


CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME <signer> <tmp-dir>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set env."
    exit 1
fi

SIGNER=$1
TEMP_DIR=$2

echo -----------------------------
echo "Install yq 4"
sudo wget https://github.com/mikefarah/yq/releases/download/v4.5.1/yq_linux_amd64 -O /usr/bin/yq 2>/dev/null && sudo chmod +x /usr/bin/yq
echo ""
echo done
echo ""

echo -----------------------------
echo "[1/2] Unit test sign scripts with yq 4"

${ISHIELD_REPO_ROOT}/build/unit_test_sign_script.sh $SIGNER $TEMP_DIR

echo ""
echo "Done with unit test sign scripts (yq 4)"
echo ""


echo -----------------------------
echo "Install yq 3"
sudo wget https://github.com/mikefarah/yq/releases/download/3.3.2/yq_linux_amd64 -O /usr/bin/yq 2>/dev/null && sudo chmod +x /usr/bin/yq
echo ""
echo done
echo ""

echo -----------------------------
echo "[2/2] Unit test sign scripts with yq 3"

${ISHIELD_REPO_ROOT}/build/unit_test_sign_script.sh $SIGNER $TEMP_DIR

echo ""
echo "Done with unit test sign scripts (yq 3)"
echo ""
