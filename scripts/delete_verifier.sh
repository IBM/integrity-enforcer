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

if [ -z "$IV_NS" ]; then
    echo "IV_NS is empty. Please set namespace name for integrity-verifier."
    exit 1
fi

if [ -z "$IV_ENV" ]; then
    echo "IV_ENV is empty. Please set local or remote."
    exit 1
fi

if [ -z "$IV_REPO_ROOT" ]; then
    echo "IV_REPO_ROOT is empty. Please set root directory for IV repository"
    exit 1
fi


if [ ${IV_ENV} = "local" ]; then
    IV_OPERATOR_YAML="develop/local-deploy/operator_local.yaml"
    IV_CR="develop/local-deploy/crds/apis.integrityverifier.io_v1alpha1_integrityverifier_cr_local.yaml"
fi

if [ ${IV_ENV} = "remote" ]; then
    IV_OPERATOR_YAML="operator/deploy/operator.yaml"
    IV_CR="operator/deploy/crds/apis.integrityverifier.io_v1alpha1_integrityverifier_cr.yaml"
fi

VERIFIER_OP_DIR="${IV_REPO_ROOT}/integrity-verifier-operator/"

echo ""
echo "------------- Delete integrity-verifier -------------"
echo ""

kubectl delete mutatingwebhookconfiguration iv-webhook-config
cd $VERIFIER_OP_DIR

if [ $IV_ENV = "local" ]; then
   kubectl delete -n $IV_NS -f config/samples/apis_v1alpha1_integrityverifier_local.yaml
else
   kubectl delete -n $IV_NS -f config/samples/apis_v1alpha1_integrityverifier.yaml
fi


kustomize build config/default | kubectl delete -f -
cd ${IV_REPO_ROOT}
