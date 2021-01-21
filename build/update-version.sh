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

sed -i "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/docs/ACM/README_DISABLE_ISHIELD_PROTECTION_ACM_ENV.md
sed -i "s|$PREV_VERSION|$VERSION|" ${ISHIELD_REPO_ROOT}/scripts/install_shield.sh
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}Makefile
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}resources/testdata/deploymentForIShield.yaml
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}resources/testdata/integrityShieldCRForTest.yaml
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}resources/testdata/integrityShieldCR.yaml
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_OP_DIR}resources/default-ishield-cr.yaml
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_DIR}version/version.go
sed -i "s|$PREV_VERSION|$VERSION|" ${SHIELD_DIR}pkg/util/mapnode/node_test.go
