# Deploy integrity-enforcer on ROKS

This document is described for supporting evaluation of Integrity Enforcer (IE) on your RedHat OpenShift cluster including ROKS. The steps in this document include 
- Step 1. Deploy admission webhook via Integrity Enforcer operator
- Step 2. Deploy signing serivce via Signing Service Operator
- Step 3. Create signer policy
- Step 4. Try to deploy resources with signature
- Step 5. Change the resource after deploy
- Step 6. Define Whitelist
- Step 7. Customize policy
- How to check why IE allowed/denied the requests in detail
- How to Delete Integrity Enforcer from cluster

## Prerequisites
- ROKS or RedHat OpenShift 4.3 cluster
- admin access to the cluster to use `oc` command
- create three namespaces for IE. all resources for IE are deployed there. 
  - All IE resources are deployed in `integrity-enforcer-ns` namespace.
  - Sigatures are stored in `ie-sign` namespace. 
  - Policied are stored in `ie-policy` namespace. 
- All requests to namespaces with label `integrity-enforced=true` are processed by IE. 

---
## Step.1 Deploy admission webhook via Integrity Enforcer operator
  
  Install `integrity-enforcer-operator` on ROKS as follows.

  First, clone this repository and moved to integrity-enforcer directory

  ```
  git clone git@github.com:IBM/integrity-enforcer.git
  cd integrity-enforcer
  ```

  Create a namespace

  ```
  oc create ns integrity-enforcer-ns
  ```

  Change label

  ```
  oc label namespace integrity-enforcer-ns integrity-enforced=true
  ```

1. Switch to enforcer namespace
    ```
    oc project integrity-enforcer-ns
    ```

2. Do the following commands to deploy operator
    
    ```
    cd ../../../operator

    # Create CRDs

    oc create -f deploy/crds/research.ibm.com_integrityenforcers_crd.yaml
     
    
    # Deploy `integrity-enforcer operator`    

    oc create -f deploy/service_account.yaml 
    oc create -f deploy/role.yaml 
    oc create -f deploy/role_binding.yaml 
    oc create -f deploy/operator.yaml
    ```

3. Confirm if IE operator is running properly. 
    ```
    $ oc get pod | grep integrity-enforcer-operator
    integrity-enforcer-operator-c4699c95c-4p8wp   1/1     Running   0          5m
    ```

4. After successfully installing the operator, create a integrity-enforcer server.
    
    deploy webhook server `integrity-enforcer-server` by creating custom resource for IE by
    ```     
    $ oc create -f deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml
    ```
    
    Check if the pods are running properly. It takes about a minute to get runnning state.
    ```
    $ oc get pod | grep 'integrity-enforcer-server'
    integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
    ```

4. Create a namespace `ie-sign` for creating signatures and set it as a protected namespace
    ```
    oc create ns ie-sign
    oc label ns ie-sign integrity-enforced=true    
    ```
5.  Create a namespace `ie-policy` for creating custom policies and set it as a protected namespace
    ```
    oc create ns ie-policy
    oc label ns ie-policy integrity-enforced=true    
    ```   
---
## Step 2. Deploy a signing serivce via Signing Service Operator

   This documentation assume a signing service is deployed to create signatures.
   See documentation [here](docs/README_INSTALL_SIGNING_SERVICE.md)

---

## Step.3 Create signer policy
    
1. Get the signer policy
    
   ```
    oc get enforcepolicies.research.ibm.com signer-policy -o yaml > /tmp/signer-policy.yaml
   ```
   
2. Edit the signer policy by adding the following snipet to `/tmp/signer-policy.yaml`
   
   ```
    -------
    spec:
      policy:
        allowedSigner:
        - request:
            namespace: secure-ns
          subject:
            email: secure_ns_signer@signer.com
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
            email: secure_ns_signer@signer.com
    status: {}
     
   ```
3. Apply signature for signer policy

  ```
  # generate signature by using sign service API. To access the service, need port-forward.  
   
  oc port-forward deployment.apps/signservice 8180:8180 --namespace integrity-enforcer-ns

  curl -sk -X POST -F 'yaml=@/tmp/signer-policy.yaml' 'https://localhost:8180/sign?signer=cluster_signer@signer.com&namespace=integrity-enforcer-ns' > /tmp/signer-policy-rsig.yaml
   

  # confirm signature is generated correctly

  $ head /tmp/signer-policy-rsig.yaml
  apiVersion: research.ibm.com/v1alpha1
  kind: ResourceSignature
  metadata:
    annotations:
      messageScope: spec
      signature: LS0tLS1 ... 0tLQ==
    name: rsig-integrity-enforcer-ns-enforcepolicy-signer-policy
  spec:
    data:
    - apiVersion: research.ibm.com/v1alpha1

  # apply signature in the cluster
  oc apply -f /tmp/signer-policy-rsig.yaml -n ie-sign
   
  # Apply signer policy changes
  oc apply -f /tmp/signer-policy.yaml -n integrity-enforcer-ns
  ```
   
---
## Step.4 Try to deploy resources with signature

Define a protected namespace (e.g. `secure-ns` here)

```
oc create ns secure-ns
oc label ns secure-ns integrity-enforced=true    
```

Let's try to create sample config map. Create a file /tmp/test-cm.yaml with a content as below

```
apiVersion: v1
kind: ConfigMap
metadata:
    name: test-cm
data:
    audit_enabled: 'true'
    comment1: This is a property that can be edited if whitelisted
```
        
Run the command below to Create this config map, but it fails because no signature for this resource is not set in the cluster. 
    
```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
Error from server: admission webhook "ac-server.ie-operator.svc" denied the request: No signature found
```

Use the signer setup in Step 3. 
- `secure_ns_signer@signer.com` (authorized) 

```
$ curl -sk -X GET 'https://localhost:8180/list/users'  | jq . 
[
    {
    "signer": {
        "email": "cluster_signer@signer.com",
        "name": "cluster_signer@signer.com",
        "comment": "cluster_signer@signer.com"
    },
    "valid": true
    },
    {
    "signer": {
        "email": "secure_ns_signer@signer.com",
        "name": "secure_ns_signer@signer.com",
        "comment": "secure_ns_signer@signer.com"
    },
    "valid": true
    },
    {
    "signer": {
        "email": "invalid_signer@invalid.enterprise.com",
        "name": "invalid_signer@invalid.enterprise.com",
        "comment": "invalid_signer@invalid.enterprise.com"
    },
    "valid": false
    }
]
```

The following generates a signature for a given resource file (e.g. `test-cm.yaml`) to be deployed on a target namespace (e.g. `secure-ns`) using key of a given signer (e.g. `secure_ns_signer@signer.com`)
```
curl -sk -X POST -F 'yaml=@/tmp/test-cm.yaml' \
        'https://localhost:8180/sign?signer=secure_ns_signer@signer.com&namespace=secure-ns' > /tmp/rsign_cm.yaml

```
        
The signature is included. 
```
$ head /tmp/rsign_cm.yaml
apiVersion: research.ibm.com/v1alpha1
kind: ResourceSignature
metadata:
annotations:
    messageScope: spec
    signature: LS0tLS1CRUdJTiBQ...
name: rsig-secure-ns-configmap-test-cm
spec:
data:
- apiVersion: v1
...
```


Register this signature in `ie-sign` namespace. 
```
$ oc create -f /tmp/rsign_cm.yaml -n ie-sign
resourcesignature.research.ibm.com/rsig-ac-go-configmap-test-cm created
```

Then, create the config map again. It should be successful this time because sigature is already in cluster. 
```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm created
```

---

## Step.5 Change the resource after deploy

Let's make a change in the deployed config map. Change audit_enabled flag from true to false

```    
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: test-cm
    data:
        audit_enabled: 'false'
        comment1: This is a property that can be edited 
```

Then, apply this change, but failed because signature is unmatch with new content. 

```
$ oc apply -f /tmp/test-cm.yaml -n secure-ns
for: "test-cm.yaml": admission webhook "ac-server.integrity-enforcer-ns.svc" denied the request: Failed to verify signature; Message in ResourceSignature is not identical with the requested object
```

Regenerate and register signature again. Now change can be applied. 
```
$ curl -sk -X POST -F 'yaml=@/tmp/test-cm.yaml' \
        'https://localhost:8180/sign?signer=secure_ns_signer@signer.com&namespace=secure-ns' > /tmp/rsign_cm.yaml

$ oc apply -f /tmp/rsign_cm.yaml -n ie-sign
resourcesignature.research.ibm.com/rsig-ac-go-configmap-test-cm configured

$ oc apply -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm configured
```

---
## Step.6 Define Whitelist

1. Create a custom policy

e.g. Create a file /tmp/custom-policy.yaml with the folllowing content:

```
apiVersion: research.ibm.com/v1alpha1
kind: EnforcePolicy
metadata:
  name: custom-policy
spec:
  policy:
    namespace: secure-ns
    allowedChange:
      - key:
        - data.comment1
        - data.comment2
        owner: {}
        request:
          name: test-cm
          namespace: secure-ns
          kind: ConfigMap
    allowedForInternalRequest: []
    allowedSigner: []
    enforce: []
    ignoreRequest: []
    permitIfVerifiedOwner: []
    policyType: CustomPolicy
```

With this sample custom-policy, it is allowed to changes fields `data.comment1` and `data.comment2` of `test-cm` ConfigMap in `secure-ns` namespace.


create the custome policy in the cluster
```
# try to create policy
$ oc create -f /tmp/custom-policy.yaml -n ie-policy
Error from server: error when creating "/tmp/custom-policy.yaml": admission webhook "ac-server.integrity-enforcer-ns.svc" denied the request: No signature found

# generate signature 
$ curl -sk -X POST -F 'yaml=@/tmp/custom-policy.yaml' 'https://localhost:8180/sign?signer=secure_ns_signer@signer.com&namespace=ie-policy' > rsig_custom-policy.yaml

# create signature
$ oc create -f rsig_custom-policy.yaml -n ie-sign
resourcesignature.research.ibm.com/rsig-ie-policy-enforcepolicy-custom-policy created

# create custome policy
$ oc create -f /tmp/custom-policy.yaml -n ie-policy
enforcepolicy.research.ibm.com/custom-policy created
```


Make a change in a file test-cm.yaml with a content as below: value of `comment1` is changed
```
apiVersion: v1
kind: ConfigMap
metadata:
    name: test-cm
data:
    audit_enabled: 'false'
    comment1: Changed !!
```

Now apply the above changes to ConfigMap. 
Integrity enforcer allows updating a ConfigMap because a mutation whitelist policy is applied.

```
$ oc apply -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm configured
```

---

## Step.7 Customize policy

Policy for IE is defined in EnforcePolicy custom resource in `integrity-enforcer-ns` namespace, and it can be customized to change control behavior by IE. EnforcePolicy includes the following fields: 
- allowedSigner: allow only if signer and request satisfy the condition (default false)
- allowedForInternalRequest: allow when request is classfieid as internal request (default false)
- allowedByRule:  allow when request satisfies conditions in rule (default false)
- allowedChange: allow when changes are whitelisted (default false)
- permitIfVerifiedOwner: allow when owner resource is verified with signature (default false)
- permitIfCreator: allow when username is same as when the resource was created (default false)
- ignoreRequest: skip processing request in this condition (default false)
- enforce: block if not allowed. (default true)
- allowUnverified: allow request in this condition (default false)

---

## How to check why IE allowed/denied the requests in detail
Executing `watch_events.sh` in `scripts` dir, it would show detail events logs like the following.

```
$ ./watch_events.sh
secure-ns false ConfigMap           test-cm                                      UPDATE  (username)                                   Failed to verify signature; Message in ResourceSignature is not identical with the requested object
ie-sign   true  ResourceSignature   rsig-ie-policy-enforcepolicy-custom-policy   CREATE  (username)   secure_ns_signer@signer.com     allowed by valid signer's signature
ie-policy true  EnforcePolicy       custom-policy                                CREATE  (username)   secure_ns_signer@signer.com     allowed by valid signer's signature
secure-ns true  ConfigMap           test-cm                                      UPDATE  (username)                                   allowed because no mutation found
```



---

## How to Delete Integrity Enforcer from cluster

To delete IE from cluster, run the following commands.

```
# Delete CR `integrity-enforcer`  
oc delete -f deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml 

# Delete Operator    
oc delete -f deploy/service_account.yaml
oc delete -f deploy/role.yaml
oc delete -f deploy/role_binding.yaml
oc delete -f deploy/operator.yaml

# Delete CRD
oc delete -f deploy/crds/research.ibm.com_integrityenforcers_crd.yaml

```
