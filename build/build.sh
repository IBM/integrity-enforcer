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

echo "BUILD GOES HERE!"

echo "<repo>/<component>:<tag> : $1"

# Run our build target

make build-images NO_CACHE=true

echo "Pushing images with Travis build tag"

${ISHIELD_REPO_ROOT}/build/push_images_ocm.sh

echo "Building integrity shield bundle starting : $(date)"

${ISHIELD_REPO_ROOT}/build/build_bundle_ocm.sh

echo "Building integrity shield bundle completed : $(date)"
