#!/bin/bash

curl -o demo-magic.sh https://raw.githubusercontent.com/paxtonhare/demo-magic/master/demo-magic.sh

if [ -f demo-magic.sh ]; then
   echo found
   . ./demo-magic.sh
   rm ./demo-magic.sh
else
   echo "Failed to download demo-magic"
   exit 1
fi

#clear

if [ -z "$IV_REPO_ROOT" ]; then
    echo "IV_REPO_ROOT is empty. Please set root directory for IE repository"
    exit 1
fi

source $IV_REPO_ROOT/iv-build.conf

cd ${IV_REPO_ROOT};

echo "===== ENTER Deployment Admin ====="

echo
NO_WAIT=true
p "First, we create Integrity Verifier (IV) Custome Resource Definitions (CRDs). Please enter."
read
pe "make install-crds"
echo
p "===== Integrity Verifier CRDs are created."
echo
NO_WAIT=false

echo
NO_WAIT=true
p "First, Let's create a namespace in cluster to deploy Integrity Verifier. Please enter."
read
pe "make create-ns"
echo
p "===== A namespace ${IV_OP_NS} is created in cluster. ====="
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Then, Let's create a verification key as a secret in cluster. Integrity Verifier would use this key to verify integrity of resources. Please enter."
read
pe "make create-key-ring"
echo
p "===== key-ring secret is created in cluster. ====="
echo
NO_WAIT=false


echo
NO_WAIT=true
p "Now, we are ready to install IntegrityVerifier. Please enter."
read
pe "make install-operator"
echo
echo "===== Integrtity Verifier operator is being deployed in cluster. ====="
echo
echo "Then, we set up IntegrityVerifier custome resource (CR)."
make setup-cr
echo
echo "===== Integrity Verifier CR is set up. ====="
echo
echo "After setting up Integrity Verifier CR,  Let's now deploy Integrity Verfier CR in the cluster."
make create-cr
echo
echo "===== Integrity Verifier CR is created in cluster. ====="
echo
NO_WAIT=false

echo
NO_WAIT=true
p "Please wait until Integrity Verifier (two pods) is successfully deployed in the namespace ${IV_OP_NS}."
p "Let's wait (this script would resume shortly) "
while true; do
   IV_STATUS=$(kubectl get pod -n ${IV_OP_NS} | grep integrity-verifier-server | awk '{print $3}')
   if [[ "$IV_STATUS" == "Running" ]]; then
      echo
      echo -n "===== Integrity Verifier server has started, let's continue with verifying integrity of resources. ====="
      echo
      break
   else
      printf "."
      sleep 2
   fi
done

echo
NO_WAIT=true
p "Now, we would set up a sample namespace (e.g. ${TEST_NS}) to show how IntegrityVerifier verifies integrity of resources in that namespace. Please enter to create namespace."
read
pe "make setup-test-env"
echo
p "===== A namespace ${TEST_NS} is created in cluster ====="
echo
NO_WAIT=false

echo
cp ${VERIFIER_OP_DIR}test/deploy/test-rsp.yaml test-rsp.yaml
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
cp ${VERIFIER_OP_DIR}test/deploy/test-configmap.yaml test-configmap.yaml
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
p "===== Resource creation request was blocked by Integrity Verifier because no signature for this resource is stored in the cluster. ====="
read
NO_WAIT=false

echo
cp ${VERIFIER_OP_DIR}test/deploy/test-configmap-annotation.yaml test-configmap-annotation.yaml
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
p "===== It should be successful this time because Integrity Verifier successfully verified corresponding signature, available as annotation in the resource. ====="
read
NO_WAIT=false.

p "THE END"

if [ -f demo-magic.sh ]; then
   rm demo-magic.sh
fi

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
