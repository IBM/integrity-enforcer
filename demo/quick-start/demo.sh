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

curl -o demo-magic.sh https://raw.githubusercontent.com/paxtonhare/demo-magic/master/demo-magic.sh

if [ -f demo-magic.sh ]; then
   . ./demo-magic.sh
   rm ./demo-magic.sh
else
   echo "Failed to download demo-magic"
   exit 1
fi

#clear

if [ -z "$ISHIELD_REPO_ROOT" ]; then
    echo "ISHIELD_REPO_ROOT is empty. Please set root directory for IShield repository"
    exit 1
fi

source $ISHIELD_REPO_ROOT/ishield-build.conf

cd ${ISHIELD_REPO_ROOT};

echo "===== ENTER Deployment Admin ====="

echo
NO_WAIT=true
p "First, we create Integrity Shield (IShield) Custome Resource Definitions (CRDs). Please enter."
read
pe "make install-crds"
echo
p "===== Integrity Shield CRDs are created."
echo
NO_WAIT=false

echo
NO_WAIT=true
p "First, Let's create a namespace in cluster to deploy Integrity Shield. Please enter."
read
pe "make create-ns"
echo
p "===== A namespace ${ISHIELD_OP_NS} is created in cluster. ====="
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Then, Let's create a verification key as a secret in cluster. Integrity Shield would use this key to verify integrity of resources. Please enter."
read
pe "make create-key-ring"
echo
p "===== key-ring secret is created in cluster. ====="
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Now, we are ready to install IntegrityShield. Please enter."
read
pe "make setup-demo DEMO_ISHIELD_OP_IMAGE_NAME=${ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION} DEMO_ISHIELD_SERVER_IMAGE_NAME=${ISHIELD_SERVER_IMAGE_NAME_AND_VERSION} DEMO_ISHIELD_LOGGING_IMAGE_NAME=${ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION}"
echo
echo "===== Integrtity Shield operator is being deployed and IntegrityShield custome resource (CR) is created in cluster. ====="
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Please wait until Integrity Shield (two pods) is successfully deployed in the namespace ${ISHIELD_OP_NS}."
p "Let's wait (this script would resume shortly) "
while true; do
   ISHIELD_STATUS=$(kubectl get pod -n ${ISHIELD_OP_NS} | grep integrity-shield-server | awk '{print $3}')
   if [[ "$ISHIELD_STATUS" == "Running" ]]; then
      echo
      echo -n "===== Integrity Shield server has started, let's continue with verifying integrity of resources. ====="
      echo
      break
   else
      printf "."
      sleep 2
   fi
done

echo
NO_WAIT=true
p "Now, we would set up a sample namespace (e.g. ${TEST_NS}) to show how IntegrityShield verifies integrity of resources in that namespace. Please enter to create namespace."
read
pe "make setup-test-env"
echo
p "===== A namespace ${TEST_NS} is created in cluster ====="
echo
NO_WAIT=false

echo
cp ${SHIELD_OP_DIR}test/deploy/test-rsp.yaml test-rsp.yaml
NO_WAIT=true
p "First, we define which reource(s) should be protected in ResourceSigningProfile(RSP). Please enter to see a sample RSP."
read
pe "cat test-rsp.yaml"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "We create a RSP in cluster to protect specified resources in namespace: ${TEST_NS}. Please enter."
read
pe "kubectl apply -f test-rsp.yaml -n ${TEST_NS}"
echo
p "===== A RSP is created in cluster. ====="
echo
NO_WAIT=false

echo
cp ${SHIELD_OP_DIR}test/deploy/test-configmap.yaml test-configmap.yaml
NO_WAIT=true
p "Now, Please enter to see a sample ConfigMap resource that we would create in cluster."
read
pe "cat test-configmap.yaml"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Try creating the configmap in $NS namespace without signature. Please enter."
read
pe "kubectl apply -f test-configmap.yaml -n ${TEST_NS}"
echo
p "===== Resource creation request was blocked by Integrity Shield because no signature for this resource is stored in the cluster. ====="
read
NO_WAIT=false

echo
cp ${SHIELD_OP_DIR}test/deploy/test-configmap-annotation.yaml test-configmap-annotation.yaml
NO_WAIT=true
p "Now, we create a resource with signature annotation. Please enter to see a sample ConfigMap resource with signature."
read
pe "cat test-configmap-annotation.yaml"
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Create the ConfigMap resource with signature annotation. Please enter."
read
pe "kubectl  apply -f test-configmap-annotation.yaml -n ${TEST_NS}"
echo
p "===== It should be successful this time because Integrity Shield successfully verified corresponding signature, available as annotation in the resource. ====="
read
NO_WAIT=false.

p "THE END"

if [ -f test-rsp.yaml ]; then
   rm test-rsp.yaml
fi

if [ -f test-configmap.yaml ]; then
   rm test-configmap.yaml
fi

if [ -f test-configmap-annotation.yaml ]; then
   rm test-configmap-annotation.yaml
fi

echo
echo "Deleting deployed resources and temp files..."
make test-e2e-clean-common --ignore-errors
