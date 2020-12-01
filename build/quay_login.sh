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

if [ -z "${QUAY_REGISTRY}" ]; then
	echo "QUAY_REGISTRY is empty."
	exit 1;
fi
if [ -z "${QUAY_USER}" ]; then
	echo "QUAY_USER is empty."
	exit 1;
fi
if [ -z "${QUAY_PASS}" ]; then
	echo "QUAY_PASS is empty."
	exit 1;
fi
docker login ${QUAY_REGISTRY} -u ${QUAY_USER} -p ${QUAY_PASS}
