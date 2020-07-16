# Integrity Enforcer (IE)

## Configurations
This document describes a set of confiuration required for IE to enable integrity enforcement on cluster.

- Configure namespaces

  Make sure the following namespaces and their labels exist

  1. a namespace `integrity-enforcer-ns` for deploying integrity-enforcer and set it as a protected namespace
    ```
    oc create ns integrity-enforcer-ns
    oc label ns integrity-enforcer-ns integrity-enforced=true    
    ```

  2. a namespace `ie-sign` for creating signatures and set it as a protected namespace
    ```
    oc create ns ie-sign
    oc label ns ie-sign integrity-enforced=true    
    ```
  2.  a namespace `ie-policy` for creating custom policies and set it as a protected namespace
    ```
    oc create ns ie-policy
    oc label ns ie-policy integrity-enforced=true    
    ``` 

- Configure signer policy
    IE enforces integrity per namespace. This requires a signer policy for each namespace. Configure signer policy as follows.
  
  1. Get the signer policy after deployging IE on cluster
    
   ```
    oc get enforcepolicies.research.ibm.com signer-policy -o yaml > /tmp/signer-policy.yaml
   ```
   
  2. Edit the signer policy by adding the following snipet to `/tmp/signer-policy.yaml`
   
   The following shows adding signer `secure_ns_signer@signer.com` to a namespace `secure-ns`. This enables `secure_ns_signer@signer.com` to sign any resources to be created or updated on `secure-ns`.
   
   ```
    -------
    spec:
      policy:
        allowedSigner:
        - request:
            namespace: secure-ns
          subject:
            commonName: Service Team Admin A
    -------
   ```
   
   E.g. Final signer policy
   ```
    apiVersion: research.ibm.com/v1alpha1
    kind: EnforcePolicy
    metadata:
      creationTimestamp: "2020-06-10T07:10:46Z"
      generation: 1
      name: signer-policy
      namespace: integrity-enforcer-ns
      ownerReferences:
      - apiVersion: research.ibm.com/v1alpha1
        blockOwnerDeletion: true
        controller: true
        kind: IntegrityEnforcer
        name: integrity-enforcer-server
        uid: 1944e488-e1c4-47f6-a660-1405bb2d8050
      resourceVersion: "4863231"
      selfLink: /apis/research.ibm.com/v1alpha1/namespaces/integrity-enforcer-ns/enforcepolicies/signer-policy
      uid: c280009c-9701-4184-aacf-3ade33a509ce
    spec:
      policy:
        allowedSigner:
        - request:
            namespace: secure-ns
          subject:
            commonName: Service Team Admin A
    status: {}
     
   ```
   
  3. Apply signature for signer policy

   Note that `cluster_signer@signer.com` is used for signing a signer policy.  `cluster_signer@signer.com` is a cluster wide signer.
  
   ```
   # generate signature by using sign service API. To access the service, need port-forward.  
   
   oc port-forward deployment.apps/signservice 8180:8180 --namespace integrity-enforcer-ns

   curl -sk -X POST -F 'yaml=@/tmp/signer-policy.yaml' \
                    'https://localhost:8180/sign/apply?signer=Cluster Admin&namespace=integrity-enforcer-ns&scope=' > /tmp/signer-policy-rsig.yaml
                    
 

   # confirm signature is generated correctly 
   $ head /tmp/signer-policy-rsig.yaml
   apiVersion: research.ibm.com/v1alpha1
   kind: ResourceSignature
   metadata:
     annotations:
       certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t ....
       messageScope: spec
       signature: LS0tLS1 ... 0tLQ==
     name: rsig-integrity-enforcer-ns-enforcepolicy-signer-policy
   spec:
     data:
     - apiVersion: research.ibm.com/v1alpha1

   # create signature in the cluster
   oc create -f /tmp/signer-policy-rsig.yaml -n ie-sign
   
   # Apply signer policy changes
   oc apply -f /tmp/signer-policy.yaml -n integrity-enforcer-ns
   ```

   
- Configure enforce policy 
  
  see documentation [here](README_FOR_ENFORCE_POLICY.md)
  

  
