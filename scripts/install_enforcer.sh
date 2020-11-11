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

if [ -z "$IE_ENV" ]; then
    echo "IE_ENV is empty. Please set local or remote."
    exit 1
fi

if [ -z "$IE_REPO_ROOT" ]; then
    echo "IE_REPO_ROOT is empty. Please set root directory for IE repository"
    exit 1
fi

IMG=integrityenforcer/integrity-enforcer-operator:0.0.4dev2
ENFORCER_DIR=${IE_REPO_ROOT}"/integrity-enforcer-operator/"

echo ""
echo "------------- Set integrity-enforcer operator watch namespace -------------"
echo ""
export WATCH_NAMESPACE=$IE_NS

echo ""
echo "------------- Install integrity-enforcer -------------"
echo ""

echo ""
echo "------------- Create crd -------------"
echo ""
cd ${ENFORCER_DIR}
kustomize build ${ENFORCER_DIR}config/crd | kubectl apply -f -

echo ""
echo "------------- Install operator -------------"
echo ""

cd ${ENFORCER_DIR}config/manager
kustomize edit set image controller=${IMG}
kustomize build ${ENFORCER_DIR}config/default | kubectl apply -f -

echo ""
echo "------------- Create CR -------------"
echo ""
cd $IE_REPO_ROOT

if [ $IE_ENV = "local" ]; then
   kubectl apply -f ${ENFORCER_DIR}config/samples/apis_v1alpha1_integrityenforcer_local.yaml -n $IE_NS
else
   kubectl apply -f ${ENFORCER_DIR}config/samples/apis_v1alpha1_integrityenforcer.yaml -n $IE_NS
fi

################################
# previous script commands here
################################

# if [ $IE_ENV = "local" ]; then
#     IE_OPERATOR_YAMl=${ENFORCER_LOCAL_DIR}"operator_local.yaml"
#     IE_CR=${ENFORCER_LOCAL_DIR}"crds/apis.integrityenforcer.io_v1alpha1_integrityenforcer_cr_local.yaml"
# fi

# if [ $IE_ENV = "remote" ]; then
#     IE_OPERATOR_YAMl=${ENFORCER_DIR}"deploy/operator.yaml"
#     IE_CR=${ENFORCER_DIR}"deploy/crds/apis.integrityenforcer.io_v1alpha1_integrityenforcer_cr.yaml"
# fi

# if [ ! -d $ENFORCER_DIR ];then
#   echo "directory not exists."
# else
#     echo ""
#     echo "------------- Create crd -------------"
#     echo ""
#     kubectl create -f ${ENFORCER_DIR}deploy/crds/apis.integrityenforcer.io_integrityenforcers_crd.yaml

#     echo ""
#     echo "------------- Install operator -------------"
#     echo ""
#     kubectl create -f ${ENFORCER_DIR}deploy/service_account.yaml -n ${IE_NS}
#     kubectl create -f ${ENFORCER_DIR}deploy/role.yaml -n ${IE_NS}
#     kubectl create -f ${ENFORCER_DIR}deploy/role_binding.yaml -n ${IE_NS}
#     kubectl create -f ${IE_OPERATOR_YAMl} -n ${IE_NS}

#     echo ""
#     echo "------------- Create CR -------------"
#     echo ""
#     kubectl create -f ${IE_CR} -n ${IE_NS}
# fi

