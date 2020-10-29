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

if [ -z "$IE_NS" ]; then
    echo "IE_NS is empty. Please set namespace name for integrity-enforcer."
    exit 1
fi

if [ -z "$IE_OP_NS" ]; then
    echo "IE_OP_NS is empty. Please set namespace name for integrity-enforcer-operator."
    exit 1
fi

if [ -z "$IE_ENV" ]; then
    echo "IE_ENV is empty. Please set local or remote."
    exit 1
fi

if [ -z "$IE_REPO_ROOT" ]; then
    echo "IE_REPO_ROOT is empty. Please set root directory for IE repository"
    exit 1
fi


if [ ${IE_ENV} = "local" ]; then
    IE_OPERATOR_YAML="develop/local-deploy/operator_local.yaml"
    IE_CR="develop/local-deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr_local.yaml"
fi

if [ ${IE_ENV} = "remote" ]; then
    IE_OPERATOR_YAML="operator/deploy/operator.yaml"
    IE_CR="operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml"
fi

ENFORCER_DIR="${IE_REPO_ROOT}/operator/"
ENFORCER_DEPLOY_DIR="${IE_REPO_ROOT}/operator/deploy"

IE_OP_DEFAULT_NS=ie-operator-ns

echo ""
echo "------------- Delete integrity-enforcer -------------"
echo ""

sed -i "s/$IE_OP_DEFAULT_NS/$IE_OP_NS/g" ${ENFORCER_DIR}config/default/kustomization.yaml

kubectl delete mutatingwebhookconfiguration ie-webhook-config
cd $ENFORCER_DIR
kubectl delete -n $IE_NS -f config/samples/apis_v1alpha1_integrityenforcer.yaml
kustomize build config/default | kubectl delete -f -
cd ${IE_REPO_ROOT}

################################
# previous script commands here
################################

# if [ ! -d ${ENFORCER_DEPLOY_DIR} ];then
#   echo "directory not exists."
# else
#     kubectl delete mutatingwebhookconfiguration ie-webhook-config
#     kubectl delete -f ${IE_REPO_ROOT}/${IE_CR}  -n ${IE_NS}
#     kubectl delete -f ${IE_REPO_ROOT}/${IE_OPERATOR_YAML} -n ${IE_NS}
#     kubectl delete -f ${ENFORCER_DEPLOY_DIR}/role_binding.yaml -n ${IE_NS}
#     kubectl delete -f ${ENFORCER_DEPLOY_DIR}/role.yaml -n ${IE_NS}
#     kubectl delete -f ${ENFORCER_DEPLOY_DIR}/service_account.yaml -n ${IE_NS}
#     kubectl delete -f ${ENFORCER_DEPLOY_DIR}/crds/research.ibm.com_integrityenforcers_crd.yaml
# fi

