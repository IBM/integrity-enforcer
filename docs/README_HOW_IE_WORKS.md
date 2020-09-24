# Integrity Enforcer
​
Integrity Enforcer (IE) is a tool for built-in preventive integrity control for regulated cloud workloads. 
​
## Goal
​
The goal of Integrity Enforcer is to provide assurance of the integrity of Kubernetes resources.  
​
Resources on a Kubernetes cluster are defined in various form of artifacts such as YAML files, Helm charts, Operator, etc., but those artifacts may be altered maliciously or unintentionally before deploying them to cluster. 
This could be an integrity issue. For example, some artifact may be modified to inject malicous scripts and configurations inside in stealthy manner, then admin deploys it without knowing the falsification.
​
IE provides signature-based assurance of integrity for Kubernetes resources at cluster side. IE works as an Admission Controller which handles all incoming Kubernetes admission requests, verifies if the requests attached a signature, and blocks any unauthorized requests according to the enforce policy before actually pursisting in EtcD. 
​
## Supported Platforms
​
Integrity Enforcer works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design. 
IE can be deployed with operator. We have verified the feasibility on the following platforms:
​
- RedHat OpenShift 4.5
- RedHat OpenShift 4.3 on IBM Cloud (ROKS)
- Minikube v1.18.2
​

## How Integrity Enforcer works
- Resources to be protected in each namespace can be defined in the custom resource called `ResourceProtectionProfile`. For example, The following snippet shows an example definition of protected resources in a namespace. ConfigMap, Depoloyment, and Service in a namespace `secure-ns` which is protected by IE, so any request to create/update resources is verified with signature.  (see [Define Protected Resources](README_FOR_RESOURCE_PROTECTION_PROFILE.md))
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
- Adminssion request to the protected resources is blocked at Mutating Admission Webhook, and the request is allowed only when the valid signature on the resource in the request is provided.
- Signer can be defined for each namespace independently. Signer for cluster-scope resources can be also defined. (see [Sign Policy](README_CONFIG_SIGNER_POLICY.md).)
- Signature is provided in the form of separate signature resource or annotation attached to the resource. (see [How to Sign Resources](README_RESOURCE_SIGNATURE.md))
- Integrity Enforcer admission controller is installed in a dedicated namespace (e.g. `integrity-enforcer-ns` in this document). It can be installed by operator. (see installation instructions)
​
---

## Installation Instructions

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

1. Retrive the source from `integrity-enforcer` Git repository.

    git clone this repository and moved to `integrity-enforcer` directory

    ```
    $ git clone https://github.com/IBM/integrity-enforcer.git
    $ cd integrity-enforcer
    $ pwd
    /home/gajan/go/src/github.com/IBM/integrity-enforcer
    ```

    Note the absolute path of root directory of the cloned `integrity-enforcer` git repository.
    
2. Prepare a namespace to deploy IE. 

    The following example show that we use `integrity-enforcer-ns` as default namespace for deploying IE. 
    ```
    oc create ns integrity-enforcer-ns
    ```
    We swtich to  `integrity-enforcer-ns` namespace.

    ```
    oc project integrity-enforcer-ns
    ```

3. Define a public key secret for verifying signature by IE.
    
    IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  IE supports X509 or PGP key for signing resources. We describe signing resources using PGP key as follows.

    1. If you do not have a PGP key, generate PGP key as shown below.
   
        Use your `name` and `email` to generate PGP key using the following command
        ```
        $ gpg --full-generate-key
        ```

        Confirm if key is avaialble in keyring. The following example shows a PGP key is successfully generated using email `signer@enterprise.com`
        ```
        $ gpg -k signer@enterprise.com
        gpg: checking the trustdb
        gpg: marginals needed: 3  completes needed: 1  trust model: pgp
        gpg: depth: 0  valid:   2  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 2u
        pub   rsa3072 2020-09-24 [SC]
              FE866F3F88FCDAF42BB1B1ED23EC90D3DAD9A6C0
        uid           [ultimate] signer@enterprise.com <signer@enterprise.com>
        sub   rsa3072 2020-09-24 [E]
        ```

    2. Once you have a PGP key, export it as a file.

        The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `~/.gnupg/pubring.gpg`.

        ```
        $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
        ```
        
    3.  Define a secret that includes a pubkey ring for verifying signatures of resources  
        
        The encoded content of `~/.gnupg/pubring.gpg` can be retrived by using the following command:
        ```
        $ cat ~/.gnupg/pubring.gpg | base64
        ```

        Once you have the encoded content of `~/.gnupg/pubring.gpg`, embed it to `/tmp/sig-verify-secret.yaml` as follows.

        ```
        apiVersion: v1
        kind: Secret
        metadata:
          name: sig-verify-secret
        type: Opaque
        data:
            pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
        ```

    4. Create `sig-verify-secret` in a namespace `integrity-enforcer-ns` in the cluster.

        ```
        $ oc create -f  /tmp/sig-verify-secret.yaml -n integrity-enforcer-ns
        ```

4. Define which signers (identified by email) should sign the resources in a specific namespace.

   Configure signPolicy in the following `integrity-enforcer` Custom Resource file:
   
   Edit [`deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml`](../operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml) to specify a signer for a namespace `secure-ns`.

   Example below shows a signer `signer-a` identified by email `signer@enterprise.com` is configured to sign rosources to be protected in a namespace `secure-ns`.
   
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
            - signer-a    
        signers:
        - name: "ClusterSigner"
          subjects:
          - commonName: "ClusterAdmin"
        - name: "HelmClusterSigner"
          subjects:
          - email: cluster_signer@signer.com
        - name: signer-a 
          subjects:
          - email: signer@enterprise.com  

   ```

5. Install IE to a cluster

   IE can be installed to a cluster using a series of steps which are bundled in a script called [`install_enforcer.sh`](../script/install_enforcer.sh).
    
   Before executing the script `install_enforcer.sh`, setup local environment as follows:
      - `IE_ENV=remote`  (for deploying IE on OpenShift or ROKS clusters, use this [guide](README_DEPLOY_IE_LOCAL.md) for deploying IE in minikube)
      - `IE_NS=integrity-enforcer-ns` (a namespace where IE to be deployed)
      - `IE_REPO_ROOT=<set absolute path of the root directory of cloned integrity-enforcer source repository>`


   The following example shows how to set up a local envionement.
   Note the absolute path of root directory of the cloned `integrity-enforcer` git repository.
    
      ```
      $ export IE_ENV=remote 
      $ export IE_NS=integrity-enforcer-ns
      $ export IE_REPO_ROOT=/home/gajan/go/src/github.com/IBM/integrity-enforcer
      ``` 


   Execute the following script to deploy IE in a cluster.
   
      ```
      $ cd integrity-enforcer
      $ ./scripts/install_enforcer.sh
      ```

6. Confirm if `integrity-enforcer` is running successfully in a cluster.
    
   Check if there are two pods running in the namespace `integrity-enforcer-ns`: 
        
      ```
      $ oc get pod -n integrity-enforcer-ns
      integrity-enforcer-operator-c4699c95c-4p8wp   1/1     Running   0          5m
      integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
      ```


7. Clean up `integrity-enforcer` from a cluster
    
    IE can be removed  from a cluster using a series of steps which are bundled in a script called [`delete_enforcer.sh`](../script/delete_enforcer.sh).

    Execute the following script to remove IE from cluster.
    ```
    $ cd integrity-enforcer
    $ ./scripts/delete_enforcer.sh
    ```
​

### Protect Resources with Integrity Enforcer
​

This section describes the execution flow for protecting a specific resource (e.g. ConfigMap) in a specific namespace (e.g. secure-ns) on your RedHat OpenShift (including ROKS).

The steps for protecting resources include:
- Step 1. Define which reource(s) should be protected.
- Step 2. Create a resource with signature .
- Step 3. Check status on ResourceProtectionProfile (with cap).
- Step 4. Check logs (server, forwarder).

---
#### Step.1 Define which reource(s) should be protected
 
   1. Create Resource Protection Profile

      You can define which resources should be protected with signature in IE. For resources (e.g. ConfigMap, Deployment, Service etc. ) in namespace, custom resource `ResourceProtectionProfile` (RPP) is created in the same namespace.
      Example below illustrates a custom resource `ResourceProtectionProfile` to protect resources such as ConfigMap, Deployment, and Service in a namespace `secure-ns`.

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
   2. Store ResourceProtectionProfile in a namespace `secure-ns` in the cluster.

        ```
        $ oc create -f /tmp/sample-rpp.yaml -n secure-ns
        resourceprotectionprofile.research.ibm.com/sample-rpp created
        ```


#### Step 2. Create a resource with signature 

1. Specify a ConfigMap resource.

    The following snippet (/tmp/test-cm.yaml) shows a spec of a ConfigMap `test-cm`.

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

2. Try to create ConfigMap resource `test-cm` shown above (/tmp/test-cm.yaml) in the namespace `secure-ns`, before creating a signature.

    Run the command below to create ConfigMap `test-cm`, but it fails because no signature for this resource is stored in the cluster.

    ```
    $ oc create -f /tmp/test-cm.yaml -n secure-ns
    Error from server: error when creating "test-cm.yaml": admission webhook "ac-server.integrity-enforcer-ns.svc" denied the request: No signature found
    ```

3. Generate a signature for a resource 

    To generate a signature for a resource,  we use a utility [script](https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-rs-sign.sh)

    We setup a signer in the [config file](https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-sign-config.sh)

    The following shows the content of config file: `gpg-sign-config.sh`  which configures `signer@enterprise.com` as `SIGNER`.

    ```
    #!/bin/bash
    SIGNER=signer@enterprise.com
    ```

    Run the following script to generate a signature
 
    ```
    $ ./scripts/gpg-rs-sign.sh gpg-sign-config.sh /tmp/test-cm.yaml /tmp/test-cm-rs.yaml
    ```
      - `gpg-sign-config.sh`:  Config file to specify a signer
      - `/tmp/test-cm.yaml`:  A resource file to be signed
      - `/tmp/test-cm-rs.yaml`: A custom resource file `ResourceSignature` generated

    Generated signature for a resource is included in a custom resource `ResourceSignature`.

    Structure of generated `ResourceSinature` in `/tmp/test-cm-rs.yaml`:
    
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
    
4. Store the generated signature in a cluster.
    
    After creating the ResourceSignature in a cluster, the corresponding resource can be created successfully after successfull signature verification by IE.
    
    ```
    $ oc create -f /tmp/test-cm-rs.yaml -n integrity-enforcer-ns
    resourcesignature.research.ibm.com/rsig-test-cm created
    ```

5. Create a resource in a specific namespace after creating the signature in the cluster.

    Run the command below to create a ConfigMap resource (/tmp/test-cm.yaml), it should be successful this time because a corresponding ResourceSignature is available in the cluster.
    ```
    $ oc create -f /tmp/test-cm.yaml -n secure-ns
    configmap/test-cm created
    ```

#### Step 3. Check status on ResourceProtectionProfile (with cap)

  We can check the status ResourceProtectionProfile resource created in the cluster.

  The following example shows which requests are denied by IE for this ResourceProtectionProfile. see [documentation](README_FOR_RESOURCE_PROTECTION_PROFILE.md)

    ```
    $ oc get ResourceProtectionProfile.research.ibm.com  sample-rpp -n secure-ns -o json | jq -r .status

      {
        "deniedRequests": [
          {
            "matchedRule": "{\"match\":[{\"namespace\":\"secure-ns\",\"kind\":\"ConfigMap\"},{\"namespace\":\"secure-ns\",\"kind\":\"HelmReleaseMetadata\"},{\"namespace\":\"secure-ns\",\"kind\":\"Service\"},{\"namespace\":\"secure-ns\",\"kind\":\"Secret\",\"name\":\"sh.helm.release.*\"}]}",
            "reason": "No signature found",
            "request": "{\"operation\":\"CREATE\",\"namespace\":\"secure-ns\",\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"name\":\"test-cm\",\"userName\":\"kube:admin\"}"
          },
          {
            "matchedRule": "{\"match\":[{\"namespace\":\"secure-ns\",\"kind\":\"ConfigMap\"},{\"namespace\":\"secure-ns\",\"kind\":\"HelmReleaseMetadata\"},{\"namespace\":\"secure-ns\",\"kind\":\"Service\"},{\"namespace\":\"secure-ns\",\"kind\":\"Secret\",\"name\":\"sh.helm.release.*\"}]}",
            "reason": "No signer policies met this resource. this resource is signed by signer@sampleenterprse.com",
            "request": "{\"operation\":\"CREATE\",\"namespace\":\"secure-ns\",\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"name\":\"test-cm\",\"userName\":\"kube:admin\"}"
          }
        ]
      }
    ```

#### Step 4. Check logs (server, forwarder)


1. Check logs generated by IE

   IE server component generates logs while processing admission requests in a cluster.  Logs of IE server could be retrived using a script called [`log_server.sh `](../script/log_server.sh).

   Run the script below to check the log generated by IE server when processing individual request to create/update resources. 

    ```
    $ cd integrity-enforcer
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
2. Check detail logs forwarded by IE to a data store

    IE server component generates detail logs while processing admission requests in a cluster. Detail logs of IE server could be retrived using a script called [`log_logging.sh  `](../script/log_logging.sh).

    Run the script below to check the log forwarded by IE when processing individual request to create/update resources. 
    
    ```
    $ cd integrity-enforcer
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