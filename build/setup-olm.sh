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

set -e

if [[ ${#@} -ne 1 ]]; then
    echo "Usage: $0 version"
    echo "* version: the github release version of OLM"
    exit 1
fi

echo "SETUP-OLM GOES HERE!"

release=$1
echo ""
echo "-------------------------------------------------"
echo "Install OLM"
curl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/${release}/install.sh | bash -s ${release}
