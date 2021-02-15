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

if [ -z "$OLM_VERSION" ]; then
    echo "OLM_VERSION is empty. Please set olm version."
    exit 1
fi

echo "SETUP-OLM GOES HERE!"

echo ""
echo "-------------------------------------------------"
echo "Install OLM locally"
curl -sL ${OLM_RELEASE_URL}/${OLM_VERSION}/install.sh | bash -s ${OLM_VERSION}



