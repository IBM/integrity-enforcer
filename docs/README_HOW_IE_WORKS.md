# Integrity Enforcer
​
Integrity Enforcer (IE) is a tool for built-in preventive integrity control for regulated cloud workloads. 
​
## Goal
​
The goal of Integrity Enforcer is to provide assurance of the integrity of Kubernetes resources.  
​
Resources on kubernetes cluster are defined in various form of artifacts such as YAML files, Helm charts, Operator, etc., but those artifacts may be altered maliciously or unintentionally before deploying them to cluster. 
This could be an integrity issue. For example, some artifact are modified to inject malicous scripts and configurations inside in stealthy manner, then admin deploys it without knowing the falsification.
​
IE provides signature-based assurance of integrity for Kubernetes resources at cluster side. IE works as an admission controller which handles all incoming Kubernetes admission requests, verifies if the requests attached signature, and blocks any unauthorized requests according to the enforce policy before actually pursisting in EtcD. 
​
## Supported Platforms
​
Integrity Enforcer works as Kubernetes Admission Controller using mutating admission webhook, and it can run on any Kubernetes cluster by design. 
IE can be deployed with operator. We have verified the feasibility on the following platforms:
​
- RedHat OpenShift 4.5
- RedHat OpenShift 4.3 on IBM Cloud (ROKS)
- Minikube v1.18.2
​
## How Integrity Enforcer works
- Resources to be protected in each namespace can be defined in the custom resource. For example, The following snippet shows an example of definition of protected resources in a namespace. ConfigMap, Depoloyment, and Service in a namespace `secure-ns` which is protected by IE, so any request to create/update resources is verified with signature.  (see rpp/crpp)
​
    ```
        apiVersion: research.ibm.com/v1alpha1
        kind: ResourceProtectionProfile
        metadata:
          name: sample-rpp
        spec:
        rules:
        - match:
            - namespace: secure-ns
              kind: ConfigMap
            - namespace: secure-ns
              kind: Deployment
            - namespace: secure-ns
              kind: Service
    ```
​
- Adminssion request to the protected resources is blocked at mutating admission webhook, and the request is allowed only when the valid signature on the resource in the request is provided.
- Signer can be defined for each namespace independently. Signer for cluster-scope resources can be also defined. (see sign policy.)
- Signature is provided in the form of separate signature resource or annotation attached to the resource. (see resource signature)
- Integrity Enforcer admission controller is installed in a dedicated namespace (e.g. `integrity-enforcer-ns` in this document). It can be installed by operator. (see installation)
​
---

## Installation Instructions
​
### Prerequisites
​
The following prerequisites must be satisfied to deploy IE on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use oc or kubectl command
- Prepare a namespace to deploy IE. Use `integrity-enforcer-ns` as default.
- All requests to namespaces with label integrity-enforced=true are passed to IE.
- A secret resource (ie-certpool-secret / kubring-secret) which contains public key and certificates should be setup for enabling signature verification by IE.

### Install Integrity Enforcer
​
This section describe the steps for deploying Integrity Enforcer (IE) on your RedHat OpenShift cluster including ROKS via `oc` or `kubectl` CLI commands. 

1. git clone this repository and moved to `integrity-enforcer` directory

    ```
    git clone https://github.com/IBM/integrity-enforcer.git
    cd integrity-enforcer
    ```
    

2. Create a namespace (if not exist) and switch to ie namespace

    ```
    oc create ns integrity-enforcer-ns
    oc project integrity-enforcer-ns
    ```

3. Setup environment
    
    - `IE_ENV=remote` refers to a RedHat OpenShift cluster
    - `IE_NS=integrity-enforcer-ns` refers to a namespace where IE to be deployed
    - `IE_REPO_ROOT` refers to root directory of the cloned `integrity-enforcer` source repository

    ```
    $ export IE_ENV=remote 
    $ export IE_NS=integrity-enforcer-ns
    $ export IE_REPO_ROOT= <root directory of `integrity-enforcer`>
    ```  

4. Setup IE secret called `sig-verify-secret` (pubkey ring)

    IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.

    1. export key

        E.g. The following shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported as a key stored in `~/.gnupg/pubring.gpg`.
        ```
        $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
        $ cat ~/.gnupg/pubring.gpg | base64
        ```
    2.  embed encoded content of `~/.gnupg/pubring.gpg` to `sig-verify-secret` as follows:   

        E.g.:  /tmp/sig-verify-secret.yaml 
        ```
        apiVersion: v1
        kind: Secret
        metadata:
          name: sig-verify-secret
        type: Opaque
        data:
            pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
        ```

     3. create `sig-verify-secret` in namespace `IE_NS` in the cluster.
        ```
        $ oc create -f  /tmp/sig-verify-secret.yaml -n integrity-enforcer-ns
        ```      

5. Configure SignPolicy in `integrity-enforcer` Custom Resource file
   
   Edit [`deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml`](../operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml) to specify a signer for a namespace `secure-ns`

   Example below shows a signer `service-a` identified by email `signer@enterprise.com` is configured to sign rosources to be created in a namespace `secure-ns`.
   
   ```
       signPolicy:
        policies:
        - namespaces:
            - "*"
            signers:
            - "ClusterSigner"
            - "HelmClusterSigner"
        - namespaces:
            - secure-ns
            signers:
            - service-a    
        signers:
        - name: "ClusterSigner"
          subjects:
          - commonName: "ClusterAdmin"
        - name: "HelmClusterSigner"
          subjects:
          - email: cluster_signer@signer.com
        - name: service-a 
          subjects:
          - email: signer@enterprise.com  

   ```

6. Execute the following script to deploy `integrity-enforcer`

    ```
    ./scripts/install_enforcer.sh
    ```

7. Confirm if `integrity-enforcer` is running properly.
    
   Check if there are two pods running in the namespace `integrity-enforcer-ns`: 
        
      ```
      $ oc get pod -n integrity-enforcer-ns
      integrity-enforcer-operator-c4699c95c-4p8wp   1/1     Running   0          5m
      integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
      ```


8. Clean up `integrity-enforcer` from a cluster
  
    Execute the following script to remove all resources related to IE deployment from cluster.
    ```
    $ cd integrity-enforcer
    $ ./scripts/delete_enforcer.sh
    ```
​
### Protect Resources with Integrity Enforcer
​
This section describes the steps required to use Integrity Enforcer (IE) on your RedHat OpenShift (including ROKS) to protect resources.

The steps for protecting resources include:
- Step 1. Setup a ResourceProtectionProfile.
- Step 2. Specify a resource to be protected.
- Step 3. Create and store a ResourceSignature.
- Step 4. Create a resource.
- Step 5. Check status on ResourceProtectionProfile (with cap).
- Step 6. Check logs (server, forwarder).

---
#### Step.1 Setup a ResourceProtectionProfile
Define which reources should be protected as a ResourceProtectionProfile 

   1. Specify a ResourceProtectionProfile
    To protect resources such as ConfigMap, Deployment, and Service in namespace `secure-ns`, create a ResourceProtectionProfile as below (/tmp/sample-rpp.yaml):

        ```
        apiVersion: research.ibm.com/v1alpha1
        kind: ResourceProtectionProfile
        metadata:
          name: sample-rpp
        spec:
        rules:
        - match:
            - namespace: secure-ns
              kind: ConfigMap
            - namespace: secure-ns
              kind: Deployment
            - namespace: secure-ns
              kind: Service
        ```
   2. Store ResourceProtectionProfile in namespace `secure-ns` in the cluster.

        ```
        $ oc create -f /tmp/sample-rpp.yaml -n secure-ns
        resourceprotectionprofile.research.ibm.com/sample-rpp created
        ```

#### Step 2. Specify a resource to be protected

1. Specify a ConfigMap resource in a namespace `secure-ns` 
    
    E.g. The following snippet (/tmp/test-cm.yaml) shows a spec of a ConfigMap `test-cm`

    ```
    apiVersion: v1
    kind: ConfigMap
    metadata:
        name: test-cm
    data:
        key1: val1
        key2: val2
        key4: val4
    ```
2. Try to create ConfigMap resource `test-cm` shown above (test-cm.yaml) in the namespace `secure-ns`

    Run the command below to create ConfigMap `test-cm`, but it fails because no signature for this resource is stored in the cluster.

    ```
    $ oc create -f /tmp/test-cm.yaml -n secure-ns
    Error from server: error when creating "test-cm.yaml": admission webhook "ac-server.integrity-enforcer-ns.svc" denied the request: No signature found
    ```

#### Step 3. Create and store a ResourceSignature

1. Generate a ResourceSignature with the script: https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-rs-sign.sh

    Setup a signer in https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-sign-config.sh

    ```
    #!/bin/bash
    SIGNER=signer@enterprise.com
    ```

    Run the following script to generate a ResourceSignature
    ```
    $ ./scripts/gpg-rs-sign.sh gpg-sign-config.sh /tmp/test-cm.yaml /tmp/test-cm-rs.yaml
    ```

    Content of the generated ResourceSinature `/tmp/test-cm-rs.yaml`:
    
    ```
      apiVersion: research.ibm.com/v1alpha1
      kind: ResourceSignature
      metadata:
        annotations:
          messageScope: spec
          signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t ...
        name: rsig-test-cm
      spec:
        data:
          - message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29u ...
            signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t ...
            type: resource
    ```
    
2. Store the ResourceSignature in a cluster

    ```
    $ oc create -f /tmp/test-cm-rs.yaml -n integrity-enforcer-ns
    resourcesignature.research.ibm.com/rsig-test-cm created
    ```


#### Step 4. Create a resource

1. After successfull creation of ResourceSignature, now create the resource that need to be protected (shown in Step 2)

    Run the command below to create this ConfigMap, it should be successful this time because a corresponding ResourceSignature is available in the cluster.
    ```
    $ oc create -f /tmp/test-cm.yaml -n secure-ns
    configmap/test-cm created
    ```

#### Step 5. Check status on ResourceProtectionProfile (with cap)



#### Step 6. Check logs (server, forwarder)
1. Check why IE allowed/denied the requests.

   Run the script below to check why IE allowed/denied the requests
   ```
   $ ./scripts/watch_events.sh
   secure-ns    false   false   ConfigMap   test-cm CREATE  IAM#gajan@jp.ibm.com    No signature found   no-signature

   ```

2. Check detail logs generated by IE

   Run the script below to check the log generated by IE when processing individual request to create/update resources. 

    ```
    $ ./scripts/log_server.sh 
    {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRole",
    "level": "trace",
    "msg": "New Admission Request Received",
    "name": "olm-operators-view",
    "namespace": "",
    "operation": "CREATE",
    "time": "2020-09-23T02:43:24.337685569Z"
    }

    ```
3. Check detail logs forwarded by IE to a data store

    Run the script below to check the log forwarded by IE when processing individual request to create/update resources. 
    
    ```
    $ ./scripts/log_logging.sh 
    2020-09-23 02:45:19.729197700 +0000 fw.events: {
    "abortReason":"",
    "aborted":false,
    "allowed":false,
    "apiGroup":"",
    "apiVersion":"v1",
    "breakglass":false,
    "claim.ownerApiVersion":"",
    "claim.ownerKind":"",
    "claim.ownerName":"",
    "claim.ownerNamespace":"secure-ns",
    "creator":"",
    "detectOnly":false,
    "ieresource":false,
    "ignoreSA":false,
    "kind":"ConfigMap",
    "ma.checked":"false",
    "ma.diff":"",
    "ma.errOccured":false,
    "ma.filtered":"",
    "ma.mutated":"false",
    "maIntegrity.serviceAccount":"",
    "maIntegrity.signature":"",
    "msg":"Failed to verify signature; Signature is invalid",
    "name":"test-cm",
    "namespace":"secure-ns",
    "objLabels":"",
    "objMetaName":"test-cm",
    "operation":"CREATE",
    "org.ownerApiVersion":"",
    "org.ownerKind":"",
    "org.ownerName":"",
    "org.ownerNamespace":"secure-ns",
    "own.errOccured":false,
    "own.owners":"null",
    "own.verified":false,
    "protected":true,
    "reasonCode":"invalid-signature",
    "request.dump":"",
    "request.objectHash":"",
    "request.objectHashType":"",
    "request.uid":"bdb62f22-22f8-4a4d-9ead-cc034e4ce07b",
    "requestScope":"Namespaced",
    "sessionTrace":"time=2020-09-23T02:45:19Z level=trace msg=New Admission Request Sent aborted=false allowed=true apiVersion=research.ibm.com/v1alpha1 kind=ResourceProtectionProfile name=sample-rpp namespace=secure-ns operation=UPDATE\n",
    "sig.allow":false,
    "sig.errMsg":"",
    "sig.errOccured":true,
    "sig.errReason":"Failed to verify signature; Signature is invalid",
    "timestamp":"2020-09-23T02:45:19.728Z",
    "type":"",
    "userInfo":"{
      "username": "IAM#gajan@jp.ibm.com",
      "groups": [
        "admin",
        "ie-group",
        "system:authenticated"
      ]
    }",
    "userName":"IAM#gajan@jp.ibm.com",
    "verified":false
    }
    ```