#!/bin/bash

curl -o demo-magic.sh https://raw.githubusercontent.com/paxtonhare/demo-magic/master/demo-magic.sh

if [ ! -f demo-magic ]; then
   . ./demo-magic.sh
else
   echo "Failed to download demo-magic"
   exit 1
fi

clear

if [ -z "$IV_REPO_ROOT" ]; then
    echo "IV_REPO_ROOT is empty. Please set root directory for IE repository"
    exit 1
fi

source $IV_REPO_ROOT/iv-build.conf
TEST_IV_SERVER_IMAGE_NAME_AND_VERSION=${REGISTRY}/${IV_IMAGE}:${VERSION}
TEST_IV_LOGGING_IMAGE_NAME_AND_VERSION=${REGISTRY}/${IV_LOGGING}:${VERSION}
TEST_IV_OPERATOR_IMAGE_NAME_AND_VERSION=${REGISTRY}/${IV_OPERATOR}:${VERSION}

cd ${IV_REPO_ROOT};

echo "===== ENTER Deployment admin ====="
echo
NO_WAIT=true
p "Checking if KUBECONFIG is set."
read
pe "make check-kubeconfig"
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Installing IntegrityVerifier CRDs."
read
pe "make install-crds"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Setting IntegrityVerifier envirionment such namespaces and secrets."
read
pe "make setup-iv-env"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Installing IntegrityVerifier operator."
read
pe "make install-operator"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Setting up IntegrityVerifier CR."
read
pe "make setup-cr"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Creating IntegrityVerifier CR."
read
pe "make create-cr"
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Please wait until IntegrityVerifier (two pods) is successfully deployed."
read
pe "kubectl get pod -n ${IV_OP_NS} "
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Setting up sample namespaces to see how IntegrityVerifier protect resources."
read
pe "make setup-test-resources; make setup-test-env"
echo
NO_WAIT=false

NO_WAIT=true
p "Define which reource(s) should be protected in ResourceSigningProfile."
read
pe "cat ${VERIFIER_OP_DIR}test/deploy/test-rsp.yaml"
echo
NO_WAIT=false

NO_WAIT=true
p "Create ResourceSigningProfile to protect specified resources in ${TEST_NS}"
read
pe "kubectl apply -f ${VERIFIER_OP_DIR}test/deploy/test-rsp.yaml -n ${TEST_NS}"
echo
NO_WAIT=false

NO_WAIT=true
p "Create a resource with signature."
read
pe "cat ${VERIFIER_OP_DIR}test/deploy/test-configmap.yaml"
echo
NO_WAIT=false

NO_WAIT=true
p "Try creating the configmap in $NS namespace without signature."
read
pe "kubectl apply -f ${VERIFIER_OP_DIR}test/deploy/test-configmap.yaml -n ${TEST_NS}"
echo
p "Resource creation request was blocked because no signature for this resource is stored in the cluster."
read
NO_WAIT=false

NO_WAIT=true
echo
p " A custom resource ResourceSignature which includes a signature for the resource."
read
pe "cat ${VERIFIER_OP_DIR}test/deploy/test-configmap-rs.yaml"
echo
NO_WAIT=false

NO_WAIT=true
p "Create the signature in the cluster for the resource."
read
pe "kubectl apply -f ${VERIFIER_OP_DIR}test/deploy/test-configmap-rs.yaml -n ${TEST_NS}"
echo
NO_WAIT=false

NO_WAIT=true
p "Create the ConfigMap resource after the signature is created."
read
pe "kubectl  apply -f ${VERIFIER_OP_DIR}test/deploy/test-configmap.yaml -n ${TEST_NS}"
echo
p "It should be successful this time because a corresponding ResourceSignature is available in the cluster."
read
NO_WAIT=false.

p "THE END"

make delete-cr
make test-e2e-clean-common --ignore-errors

if [ -f demo-magic.sh ]; then
   rm demo-magic.sh
fi
