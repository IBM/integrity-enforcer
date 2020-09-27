# Quick Start

## Prerequisites
​
The following prerequisites must be satisfied to deploy IE on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use `oc` or `kubectl` command
- Prepare a namespace to deploy IE. (We will use `integrity-enforcer-ns` namespace in this document.)
- All requests to namespaces with label integrity-enforced=true are passed to IE. You can set label to a namespace `secure-ns` by 
  ```
  kubectl label namespace secure-ns integrity-enforced=true
  ```
  or unset it by
  ```
  kubectl label namespace secure-ns integrity-enforced-
  ```
- A secret resource (ie-certpool-secret / keyring-secret) which contains public key and certificates should be setup for enabling signature verification by IE.

---

## Install Integrity Enforcer
​
This section describe the steps for deploying Integrity Enforcer (IE) on your cluster. We will use RedHat OpenShift cluster and so use `oc` commands for installation. (You can use `kubectl` for Minikube or IBM Kubernetes Service.)

### Retrive the source from `integrity-enforcer` Git repository.

git clone this repository and moved to `integrity-enforcer` directory

```
$ git clone https://github.com/IBM/integrity-enforcer.git
$ cd integrity-enforcer
$ pwd /home/repo/integrity-enforcer
```
In this document, we clone the code in `/home/repo/integrity-enforcer`.

### Prepape namespace for installing IE

You can deploy IE to any namespace. In this document, we will use `integrity-enforcer-ns` to deploy IE. 
```
oc create ns integrity-enforcer-ns
oc project integrity-enforcer-ns
```
All the commands are executed on the `integrity-enforcer-ns` namespace unless mentioned explicitly.

### Define public key secret in IE

IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  IE supports X509 or PGP key for signing resources. The following steps show how you can import your signature verification key to IE.

First, you need to export public key to a file. The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key). 

Then, create a secret that includes a pubkey ring for verifying signatures of resources  

```
oc create secret generic --save-config keyring-secret  -n integrity-enforcer-ns --from-file=/tmp/pubring.gpg
```

### Define signers for each namespace


You can define signer who can provide signature for resources on each namespace. It can be configured when deploying the Integrity Enforcer. For that, configure signPolicy in the following Integrity Enforcer Custom Resource [file](../operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml). Example below shows a signer `signer-a` identified by email `signer@enterprise.com` is configured to sign rosources to be protected in a namespace `secure-ns`.
   
```yaml
# Edit operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml

apiVersion: research.ibm.com/v1alpha1
kind: IntegrityEnforcer
metadata:
  name: integrity-enforcer-server
spec:
  ...
  enforcerConfig:
    verifyType: pgp # x509
    ...
    signPolicy:
      policies:
      - namespaces:
        - "*"
        signers:
        - "ClusterSigner"
        - "HelmClusterSigner"
      # bind signer with a namespace
      - namespaces:
        - "secure-ns"
        signers:
        - "signer-a"
      signers:
      - name: "ClusterSigner"
        subjects:
        - commonName: "ClusterAdmin"
      - name: "HelmClusterSigner"
        subjects:
        # define cluster-wide signer here
        - email: signer@enterprise.com
      ### define per-namespace signer ###
      - name: "signer-a"
        subjects:
        - email: signer@enterprise.com
```

### Install IE to a cluster

IE can be installed to a cluster using a series of steps which are bundled in a script called [`install_enforcer.sh`](../scripts/install_enforcer.sh). Before executing the script `install_enforcer.sh`, setup local environment as follows:
- `IE_ENV=remote`  (for deploying IE on OpenShift or ROKS clusters, use this [guide](README_DEPLOY_IE_LOCAL.md) for deploying IE in minikube)
- `IE_NS=integrity-enforcer-ns` (a namespace where IE to be deployed)
- `IE_REPO_ROOT=<set absolute path of the root directory of cloned integrity-enforcer source repository`

Example: 
```
$ export IE_ENV=remote 
$ export IE_NS=integrity-enforcer-ns
$ export IE_REPO_ROOT=/home/repo/integrity-enforcer
``` 

Then, execute the following script to deploy IE in a cluster.

```
$ cd integrity-enforcer
$ ./scripts/install_enforcer.sh
```

After successful installation, you should see two pods are running in the namespace `integrity-enforcer-ns`.

```
$ oc get pod -n integrity-enforcer-ns
integrity-enforcer-operator-c4699c95c-4p8wp   1/1     Running   0          5m
integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
```

---

## Protect Resources with Integrity Enforcer
​
Once IE is deployed to a cluster, you are ready to put resources on the cluster into signature-based protection. To start actual protection, you need to define which resources should be protected specifically. This section describes the execution flow for protecting a specific resource (e.g. ConfigMap) in a specific namespace (e.g. `secure-ns`) on your cluster.

The steps for protecting resources include:
- Define which reource(s) should be protected.
- Create a resource with signature.

### Define which reource(s) should be protected

You can define which resources should be protected with signature in a cluster by IE. A custom resource `ResourceProtectionProfile` (RPP) includes the definition and it is created in the same namespace as resources. Example below illustrates how to define RPP to protect three resources ConfigMap, Deployment, and Service in a namespace `secure-ns`. After this, any resources specified here cannot be created/updated without valid signature. 

```
$ cat <<EOF | oc apply -n secure-ns -f -
apiVersion: research.ibm.com/v1alpha1
kind: ResourceProtectionProfile
metadata:
  name: sample-rpp
spec:
  rules:
  - match:
    - kind: ConfigMap
    - kind: Deployment
    - kind: Service
EOF

resourceprotectionprofile.research.ibm.com/sample-rpp created
```

See [Define Protected Resources](README_FOR_RESOURCE_PROTECTION_PROFILE.md) for detail specs.

### Create a resource with signature 

Any configmap cannot be created without signature in `secure-ns` namespace. Run the following command to create a sample configmap. 

```
cat << EOF > /tmp/test-cm.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key1: val1
  key2: val2
  key4: val4
EOF
```


run the command below for trying to create the configmap in `secure-ns` namespace without signature. You will see it is blocked because no signature for this resource is stored in the cluster.

```
$ oc apply -f /tmp/test-cm.yaml -n secure-ns
Error from server: error when creating "test-cm.yaml": admission webhook "ac-server.integrity-enforcer-ns.svc" denied the request: No signature found
```


To generate a signature for a resource, you can use a [utility script](../scripts/gpg-rs-sign.sh) (Use [yq](https://github.com/mikefarah/yq) in the script)

Run the following script to generate a signature

```
$ ./scripts/gpg-rs-sign.sh signer@enterprise.com /tmp/test-cm.yaml /tmp/test-cm-rs.yaml
```


Then, output file `/tmp/test-cm-rs.yaml` is A custom resource `ResourceSignature` which includes signature of the input yaml. 


```yaml
apiVersion: research.ibm.com/v1alpha1
kind: ResourceSignature
metadata:
  annotations:
    messageScope: spec
    signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t
  name: rsig-test-cm
spec:
  data:
    - message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29u
      signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t
      type: resource
```


Create this resource. 
```
$ oc create -f /tmp/test-cm-rs.yaml -n secure-ns
resourcesignature.research.ibm.com/rsig-test-cm created
```


Then, run the same command again to create ConfigMap. It should be successful this time because a corresponding ResourceSignature is available in the cluster.

```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm created
```


IE generates logs while processing admission requests in a cluster. Two types of logs are available. You can see IE server processing logs by a script called [`log_server.sh `](../script/log_server.sh). This includes when requests come and go, as well as errors which occured during processing. 

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
...
```

If you want to see the result of admission check, you can see the detail by using a script called [`log_logging.sh  `](../script/log_logging.sh).    
```json
{
  "abortReason": "",
  "aborted": false,
  "allowed": false,
  "apiGroup": "",
  "apiVersion": "v1",
  "breakglass": false,
  "claim.ownerApiVersion": "",
  "claim.ownerKind": "",
  "claim.ownerName": "",
  "claim.ownerNamespace": "secure-ns",
  "creator": "",
  "detectOnly": false,
  "ieresource": false,
  "ignoreSA": false,
  "kind": "ConfigMap",
  "ma.checked": "false",
  "ma.diff": "",
  "ma.errOccured": false,
  "ma.filtered": "",
  "ma.mutated": "false",
  "maIntegrity.serviceAccount": "",
  "maIntegrity.signature": "",
  "msg": "Failed to verify signature; Signature is invalid",
  "name": "test-cm",
  "namespace": "secure-ns",
  "objLabels": "",
  "objMetaName": "test-cm",
  "operation": "CREATE",
  "org.ownerApiVersion": "",
  "org.ownerKind": "",
  "org.ownerName": "",
  "org.ownerNamespace": "secure-ns",
  "own.errOccured": false,
  "own.owners": "null",
  "own.verified": false,
  "protected": true,
  "reasonCode": "invalid-signature",
  "request.dump": "",
  "request.objectHash": "",
  "request.objectHashType": "",
  "request.uid": "bdb62f22-22f8-4a4d-9ead-cc034e4ce07b",
  "requestScope": "Namespaced",
  "sessionTrace": "time=2020-09-23T02:45:19Z level=trace msg=New Admission Request Sent aborted=false allowed=true apiVersion=research.ibm.com/v1alpha1 kind=ResourceProtectionProfile name=sample-rpp namespace=secure-ns operation=UPDATE\n",
  "sig.allow": false,
  "sig.errMsg": "",
  "sig.errOccured": true,
  "sig.errReason": "Failed to verify signature; Signature is invalid",
  "timestamp": "2020-09-23T02:45:19.728Z",
  "type": "",
  "userInfo": "{\"username\":\"IAM#gajan@jp.ibm.com\",\"groups\":[\"admin\",\"ie-group\",\"system:authenticated\"]}",
  "userName": "IAM#gajan@jp.ibm.com",
  "verified": false
}
```

### Clean up IE from the cluster

When you want to remove IE from a cluster, run the uninstaller script [`delete_enforcer.sh`](../scripts/delete_enforcer.sh).
```
$ cd integrity-enforcer
$ ./scripts/delete_enforcer.sh
```


