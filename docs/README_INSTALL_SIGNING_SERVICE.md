# Signing Service
We build a signing service for demo purpose. This is a handy tool to create signatures for resources to be deployed on a cluster while integrity enforcement is enabled. 

This document describe the steps for deploying signing service an OCP cluster.

---

## Deploy a signing serivce via Signing Service Operator

First, clone this repository and moved to integrity-enforcer directory

```
git clone git@github.com:IBM/integrity-enforcer.git
cd integrity-enforcer
```

Create a namespace (if not exist).
Note: if `integrity-enforcer` is already deployed on a cluster in namespace `integrity-enforcer-ns`,   deploy `signing service` in the same namespace

```
oc create ns integrity-enforcer-ns
```

Change label (if not exist).

```
oc label namespace integrity-enforcer-ns integrity-enforced=true
```

1. Switch to enforcer namespace

    ```
    oc project integrity-enforcer-ns
    ```
2. Do the following commands to deploy signing service operator   

    ```
    cd develop/signservice/signservice-operator/
    
    # Create CRDs
    
    oc create -f deploy/crds/research.ibm.com_signservices_crd.yaml  
    
    # Deploy `sign-service-enforcer operator`    

    oc create -f deploy/service_account.yaml 
    oc create -f deploy/role.yaml 
    oc create -f deploy/role_binding.yaml 
    oc create -f deploy/operator.yaml
    
    ```
3. Confirm if signing service operator is running properly. 

    ```
    $ oc get pod | grep signservice-operator
    signservice-operator-6b4dd5cd47-4vmvt         1/1     Running   0          35
    ```
4. Add a `certSigner` to signservice cr (e.g. `'Service Team Admin A'`) as shown below.

   Edit `deploy/crds/research.ibm.com_v1alpha1_signservice_cr.yaml`
   
   ```
    certSigners:
    - name: "Root CA"
      isCA: true
    - name: "Intermediate CA"
      issuerName: "Root CA"
      isCA: true
    - name: "Cluster Admin"
      issuerName: "Intermediate CA"
      isCA: false
    - name: "Service Team Admin A"
      issuerName: "Intermediate CA"
      isCA: false
   ```
5. Add a `signer` to signservice cr as shown below

   Edit `deploy/crds/research.ibm.com_v1alpha1_signservice_cr.yaml`
   
   ```
    signers:
    - cluster_signer@signer.com
    - secure_ns_signer@signer.com
    - app_signer@signer.com
   ```
   
5. After successfully installing the operator, create a signing service.

    deploy signing service `signservice` by creating custom resource for singingservice by
   ```
    oc create -f deploy/crds/research.ibm.com_v1alpha1_signservice_cr.yaml
   ```
    
    Check if the pods are running properly. 
   ```
    $ oc get pod | grep 'signservice'
    signservice-775695d84d-s8qbp            1/1       Running   0          5s
    signservice-operator-6b4dd5cd47-z4lg4   1/1       Running   0          3m8s
   ```
---

## Delete a signing serivce via Signing Service Operator
  
   run the following commands to delete signing serivce from cluster
   ```
   # Delete CR `signingservice` 
    cd ../develop/signservice/signservice-operator
    oc delete -f /develop/deploy/crds/research.ibm.com_v1alpha1_signservice_cr.yaml 

    # Delete SignService Operator    
    oc delete -f deploy/service_account.yaml
    oc delete -f deploy/role.yaml
    oc delete -f deploy/role_binding.yaml
    oc delete -f deploy/operator.yaml

    # Delete CRD
    oc delete -f deploy/crds/research.ibm.com_signservices_crd.yaml
   ``` 
   
   
   
   
