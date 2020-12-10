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

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v kustomize)" ]; then
    echo 'Error: kustomize is not installed.' >&2
    exit 1
fi

if [ -z "$ISHIELD_NS" ]; then
    echo "ISHIELD_NS is empty. Please set namespace name for integrity-shield."
    exit 1
fi

if [ -z "$ISHIELD_ENV" ]; then
    echo "ISHIELD_ENV is empty. Please set local or remote."
    exit 1
fi

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IV repository"
    exit 1
fi


if [ ${ISHIELD_ENV} = "local" ]; then
    ISHIELD_OPERATOR_YAML="develop/local-deploy/operator_local.yaml"
    ISHIELD_CR="develop/local-deploy/crds/apis.integrityshield.io_v1alpha1_integrityshield_cr_local.yaml"
fi

if [ ${ISHIELD_ENV} = "remote" ]; then
    ISHIELD_OPERATOR_YAML="operator/deploy/operator.yaml"
    ISHIELD_CR="operator/deploy/crds/apis.integrityshield.io_v1alpha1_integrityshield_cr.yaml"
fi

SHIELD_OP_DIR="${ISHIELD_REPO_ROOT}/integrity-shield-operator/"

echo ""
echo "------------- Delete integrity-shield -------------"
echo ""

kubectl delete mutatingwebhookconfiguration ishield-webhook-config
cd $SHIELD_OP_DIR

if [ $ISHIELD_ENV = "local" ]; then
   kubectl delete -n $ISHIELD_NS -f config/samples/apis_v1alpha1_integrityshield_local.yaml
else
   kubectl delete -n $ISHIELD_NS -f config/samples/apis_v1alpha1_integrityshield.yaml
fi


kustomize build config/default | kubectl delete -f -
cd ${ISHIELD_REPO_ROOT}
